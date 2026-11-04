//! Process lifecycle management for the openconnect child process.
//!
//! This module owns the [`ProcessManager`] struct, which spawns and supervises
//! the `openconnect.exe` child process. It streams stdout and stderr line-by-line
//! through the parser, emits structured Tauri events, and tracks connection state.
//!
//! # Sync architecture
//!
//! Both stdout and stderr are read concurrently, but every parsed line is pushed
//! into a **single** bounded `mpsc` channel. A dedicated emitter task drains that
//! channel in FIFO order and emits events to the frontend. This guarantees that:
//!
//! * events arrive at the GUI strictly in the order openconnect produced them
//!   (no interleaving races between the stdout and stderr reader tasks);
//! * a state-change event is always emitted *after* the log line that triggered
//!   it, so the GUI state and log never disagree;
//! * a final `Disconnected`/`Failed` state event is always flushed after the
//!   last log line, fully sealing the wrapper↔openconnect state gap.

use crate::parser::{analyze_line, current_timestamp, parse_line_owned_with_level};
use crate::types::{AppError, ConnectionState, ParsedEvent};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, Notify};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

/// Capacity of the line/event channel. A bounded channel back-pressures the
/// reader tasks instead of growing memory without bound during a log storm.
const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Maximum number of log lines coalesced into one `openconnect://events` batch
/// before it is force-flushed, bounding the emitter's transient memory even
/// during an unbounded log storm.
const EVENT_BATCH_MAX: usize = 256;

/// Internal message exchanged between the reader tasks and the emitter task.
/// Using a single enum on one channel preserves emission ordering.
enum StreamMessage {
    /// A parsed log line (already assigned a level + timestamp).
    Event(ParsedEvent),
    /// A server-cert pin detected in a line.
    ServerCert(String),
    /// A connection-state transition derived from a line.
    State(ConnectionState),
    /// The tunnel came up; carries the assigned local IP.
    TunnelInfo(crate::types::TunnelInfo),
}

/// Total time to wait for a killed process to actually exit before escalating
/// / giving up. Split into two native waits (see `kill_process_tree`).
const KILL_VERIFY_TIMEOUT_MS: u32 = 500;

/// Return `true` if a process with `pid` currently exists (Windows).
///
/// Uses the native `OpenProcess` + `GetExitCodeProcess` path instead of
/// shelling out to `tasklist`: opening a handle with only
/// `PROCESS_QUERY_LIMITED_INFORMATION` succeeds while the process is alive, and
/// `GetExitCodeProcess` returns `STILL_ACTIVE` (259) for a running process. This
/// avoids spawning a child process on every poll.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn process_exists(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return false;
    }
    // SAFETY: FFI call; a null/invalid return is handled below and we always
    // close any non-null handle we obtain.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        // Could not open — the process is gone (or access denied). Treat as gone;
        // for a child we spawned, access is never denied while it is alive.
        return false;
    }
    let mut exit_code: u32 = 0;
    // SAFETY: `handle` is a valid open process handle.
    let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
    // SAFETY: closing the handle we opened above.
    unsafe {
        CloseHandle(handle);
    }
    // If the query failed, err on the side of "still alive" so the caller retries.
    if ok == 0 {
        return true;
    }
    exit_code == STILL_ACTIVE as u32
}

/// Block until `pid` exits or `timeout_ms` elapses; returns `true` if it exited.
///
/// Waits natively on the process handle via `WaitForSingleObject` — a single
/// blocking OS wait that returns the instant the process dies, instead of a
/// sleep/poll loop. Falls back to `process_exists` if a handle cannot be opened.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn wait_for_pid_exit(pid: u32, timeout_ms: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};

    // Standard access right to wait on an object. Defined inline because the
    // windows-sys export lives behind the `Win32_Storage_FileSystem` feature
    // which this crate does not enable; the value is stable in the Win32 ABI.
    const SYNCHRONIZE: u32 = 0x0010_0000;

    if pid == 0 {
        return true;
    }
    // SAFETY: FFI; null return handled below.
    let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        // Cannot open for wait — assume already gone.
        return !process_exists(pid);
    }
    // SAFETY: `handle` is valid; WaitForSingleObject blocks up to timeout_ms.
    let rc = unsafe { WaitForSingleObject(handle, timeout_ms) };
    // SAFETY: closing our handle.
    unsafe {
        CloseHandle(handle);
    }
    rc == WAIT_OBJECT_0
}

/// Kill an entire process tree on Windows using `taskkill /F /T /PID`, then
/// **verify** the process actually exited, escalating if it did not.
///
/// This terminates openconnect.exe and every child it spawned (e.g. the Wintun
/// adapter-setup scripts). Returns `true` if the process is confirmed gone.
#[cfg(target_os = "windows")]
fn kill_process_tree(pid: u32) -> bool {
    use std::process::Command as StdCommand;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    if pid == 0 {
        return true;
    }

    // Attempt 1: taskkill with /T (terminate the whole tree).
    let _ = StdCommand::new(crate::types::system32_exe("taskkill.exe"))
        .args(["/F", "/T", "/PID", &pid.to_string()])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    // Wait natively for the process to exit (no poll loop). Give it half the
    // budget first; if it is still alive, escalate and wait for the rest.
    if wait_for_pid_exit(pid, KILL_VERIFY_TIMEOUT_MS / 2) {
        return true;
    }
    // Still alive: re-issue the kill without /T in case a stubborn child in the
    // tree blocked the group termination, then wait out the remaining budget.
    let _ = StdCommand::new(crate::types::system32_exe("taskkill.exe"))
        .args(["/F", "/PID", &pid.to_string()])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    wait_for_pid_exit(pid, KILL_VERIFY_TIMEOUT_MS / 2)
}

/// Kill an entire process tree on non-Windows platforms.
#[cfg(not(target_os = "windows"))]
fn kill_process_tree(pid: u32) -> bool {
    use std::process::Command as StdCommand;
    if pid == 0 {
        return true;
    }
    // On Unix, kill the process group.
    let _ = StdCommand::new("kill")
        .args(["-9", &pid.to_string()])
        .output();
    true
}

/// Kill a freshly-spawned child (and any process tree it may have started) and
/// reap it on a detached task so it never lingers as an unwaited (zombie) or
/// orphaned process. Used on the early-abort paths in `connect` where the child
/// was spawned but the session could not be set up.
fn kill_and_reap(mut child: Child) {
    let pid = child.id().unwrap_or(0);
    // Tree-kill first so any helper the child already spawned dies too, then
    // reap our handle on a background task.
    if pid != 0 {
        tokio::task::spawn_blocking(move || {
            let _ = kill_process_tree(pid);
        });
    }
    let _ = child.start_kill();
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
}

/// Spawn a reader task that streams one pipe (stdout or stderr) line-by-line.
///
/// The task performs a single combined [`analyze_line`] scan per line — one
/// level classification plus a cheap keyword gate before any state/cert
/// detection — and moves the owned line straight into the [`ParsedEvent`] with
/// [`parse_line_owned`], avoiding the extra `String` clone the previous
/// per-line path incurred.
///
/// # Cancellation
///
/// The read is raced against `shutdown.notified()`. If a helper process the
/// openconnect child spawned outlives the tree-kill while holding the write end
/// of this pipe, `next_line()` would never resolve; the shutdown signal breaks
/// that wait so the task returns, drops its channel sender, and never leaks.
fn spawn_reader<R>(
    stream: R,
    tx: mpsc::Sender<StreamMessage>,
    shutdown: Arc<Notify>,
    emit_cert: bool,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = BufReader::with_capacity(8192, stream).lines();
        // Wait for the shutdown signal to be armed *before* we start reading so
        // a notify fired between spawn and the first read is not missed.
        let notified = shutdown.notified();
        tokio::pin!(notified);

        loop {
            let line = tokio::select! {
                // Bias toward draining the pipe so a burst is not starved, but
                // the shutdown branch still wins once no line is immediately
                // ready and the signal has fired.
                biased;
                read = reader.next_line() => match read {
                    Ok(Some(line)) => line,
                    // EOF or read error: pipe closed, normal end of stream.
                    _ => break,
                },
                _ = &mut notified => break,
            };

            // One scan for level + (gated) state/cert.
            let analysis = analyze_line(&line);
            let level = analysis.level;
            let state = analysis.state;
            let cert = if emit_cert { analysis.server_cert } else { None };
            let tunnel_info = analysis.tunnel_info;

            // Move the owned line into the event (no clone); timestamp is
            // computed once per line here rather than inside the parser.
            let event: ParsedEvent =
                parse_line_owned_with_level(line, current_timestamp(), level);
            // Log lines are shed (dropped) rather than awaited when the channel
            // is full. Blocking here would stop draining the child's stdout/
            // stderr pipe; once that OS pipe buffer fills, openconnect BLOCKS on
            // its own write() and the *data tunnel itself* can stall. Losing a
            // few log lines under a burst is acceptable; stalling the VPN is not.
            match tx.try_send(StreamMessage::Event(event)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => break,
            }
            // Control messages (cert prompt, state transitions, tunnel-up) are
            // rare and semantically critical, so they are delivered on the
            // awaited path and must never be dropped.
            if let Some(cert) = cert {
                let _ = tx.send(StreamMessage::ServerCert(cert)).await;
            }
            if let Some(new_state) = state {
                let _ = tx.send(StreamMessage::State(new_state)).await;
            }
            if let Some(info) = tunnel_info {
                let _ = tx.send(StreamMessage::TunnelInfo(info)).await;
            }
        }
    });
}

/// A connection attempt waiting for a password or MFA code.
///
/// Stored when `read_credential` fails (credential not found) so that
/// `submit_mfa` can spawn the process once the user provides the password.
pub(crate) struct PendingConnection {
    /// Tauri app handle for emitting events.
    pub app_handle: AppHandle,
    /// Absolute path to `openconnect.exe`.
    pub exe_path: PathBuf,
    /// Command-line arguments (without the password/MFA).
    pub args: Vec<String>,
    /// Profile ID for credential storage after successful connection.
    pub profile_id: String,
    /// Username for credential storage.
    pub username: String,
    /// VPN server URL (used to scope the kill-switch).
    pub server: String,
    /// Whether the kill-switch should be engaged for this connection.
    pub kill_switch: bool,
}

/// Manages the lifecycle of the `openconnect` child process.
///
/// A single `ProcessManager` instance is stored in Tauri's managed state.
/// It is safe to share across threads because all mutable fields are wrapped
/// in `Arc<Mutex<_>>`.
///
/// The mutexes are [`parking_lot::Mutex`], which are **poison-free**: if a task
/// panics while holding a lock, the next locker still gets the guard instead of
/// a `PoisonError`. This matters for teardown — a panic in a reader/watcher task
/// must never wedge `disconnect`/`kill_if_running` out of the cleanup path and
/// leave a ghost process or an engaged kill-switch behind.
pub struct ProcessManager {
    /// Current connection lifecycle state.
    state: Arc<Mutex<ConnectionState>>,
    /// The running child process, if any.
    child: Arc<Mutex<Option<Child>>>,
    /// The child's stdin handle for sending MFA codes.
    stdin: Arc<Mutex<Option<ChildStdin>>>,
    /// A pending connection waiting for password/MFA input.
    pending: Arc<Mutex<Option<PendingConnection>>>,
    /// Monotonic session generation. Incremented on every `connect` and every
    /// `disconnect`. A watcher task captures the generation at spawn time and
    /// only publishes its terminal state if the generation is still current —
    /// this drops stale exit states from a session the user already tore down
    /// or superseded with a new connection.
    generation: Arc<AtomicU64>,
    /// PID of the current child, tracked separately from the `Child` handle so
    /// `disconnect` can still kill the process tree after the watcher task has
    /// taken ownership of the `Child`. `0` means "no PID".
    current_pid: Arc<AtomicU32>,
    /// The tunnel adapter's assigned local IP (set when the tunnel comes up),
    /// used to revert NetShield DNS on teardown. Empty when disconnected.
    tunnel_ip: Arc<Mutex<String>>,
    /// Broadcast-style shutdown signal for the current session's reader tasks.
    ///
    /// A reader task can otherwise block forever inside `next_line()` if a
    /// helper the openconnect child spawned (e.g. a Wintun `wscript`/`cscript`
    /// setup helper) survives the process-tree kill while still holding the
    /// write end of the stdout/stderr pipe. Every teardown path fires this
    /// `Notify`; the readers `select!` on it and return promptly, which drops
    /// their channel senders and lets the emitter task finish — no leaked task,
    /// no dangling pipe. Each `connect` installs a fresh `Notify` so a stale
    /// session's signal can never cancel a newer session's readers.
    shutdown: Arc<Mutex<Arc<Notify>>>,
}

impl ProcessManager {
    /// Create a new `ProcessManager` with an initial `Disconnected` state.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            child: Arc::new(Mutex::new(None)),
            stdin: Arc::new(Mutex::new(None)),
            pending: Arc::new(Mutex::new(None)),
            generation: Arc::new(AtomicU64::new(0)),
            current_pid: Arc::new(AtomicU32::new(0)),
            tunnel_ip: Arc::new(Mutex::new(String::new())),
            shutdown: Arc::new(Mutex::new(Arc::new(Notify::new()))),
        }
    }

    /// Install a fresh shutdown `Notify` for a new session and return a clone
    /// the reader tasks can wait on. The previous session's `Notify` is dropped
    /// (its readers have already been signalled during teardown).
    fn new_shutdown(&self) -> Arc<Notify> {
        let fresh = Arc::new(Notify::new());
        *self.shutdown.lock() = Arc::clone(&fresh);
        fresh
    }

    /// Signal the current session's reader tasks to stop.
    ///
    /// Uses `notify_one()` (not `notify_waiters()`): `notify_one` stores a permit
    /// for tasks that register their `notified()` future *after* this call, so a
    /// reader spawned in the tiny window between `new_shutdown()` and the signal
    /// still wakes. `notify_waiters()` would silently drop that signal and leave
    /// the reader (and its `mpsc::Sender`) blocked forever, which would also
    /// prevent the emitter task from ever observing channel close.
    ///
    /// Up to two readers (stdout + stderr) may be awaiting the same `Notify`, so
    /// we issue several notifications to ensure both are released; any surplus
    /// permits are harmless and discarded when the session's `Notify` is dropped.
    fn signal_shutdown(&self) {
        let notify = self.shutdown.lock();
        for _ in 0..4 {
            notify.notify_one();
        }
    }

    /// Store a pending connection waiting for password/MFA input.
    ///
    /// Returns `Result` for call-site ergonomics; with a poison-free
    /// `parking_lot::Mutex` the lock never fails, so this is always `Ok`.
    pub(crate) fn set_pending(&self, pending: PendingConnection) -> Result<(), AppError> {
        *self.pending.lock() = Some(pending);
        Ok(())
    }

    /// Take the pending connection, returning `None` if there isn't one.
    pub(crate) fn take_pending(&self) -> Result<Option<PendingConnection>, AppError> {
        Ok(self.pending.lock().take())
    }

    /// Spawn the openconnect process and begin managing it.
    ///
    /// # Parameters
    ///
    /// - `app_handle` — Tauri app handle used to emit events to the frontend.
    /// - `exe_path`   — Absolute path to `openconnect.exe`.
    /// - `args`       — Command-line arguments forwarded to `openconnect`.
    /// - `mfa_code`   — Optional MFA/TOTP code written to stdin immediately after spawn.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::ProcessError`] if:
    /// - A child process is already running.
    /// - The OS fails to spawn the process.
    pub async fn connect(
        &self,
        app_handle: AppHandle,
        exe_path: &Path,
        args: &[&str],
        mfa_code: Option<String>,
    ) -> Result<(), AppError> {
        // ── Guard: reject if a connection is active or in progress ────────
        //
        // We guard on STATE, not just the `child` handle: the watcher task
        // takes the `Child` out of the shared slot shortly after spawn, so a
        // child-only check would let a rapid second Connect (or a Connect while
        // still Connecting) spawn a duplicate openconnect. Holding the state
        // lock across the check + transition makes this atomic.
        {
            let mut state_guard = self.state.lock();
            match *state_guard {
                ConnectionState::Connecting
                | ConnectionState::Connected
                | ConnectionState::Disconnecting => {
                    return Err(AppError::ProcessError(
                        "a connection is already active — disconnect first".to_string(),
                    ));
                }
                _ => {}
            }
            // Reserve the session by moving to Connecting under the lock so no
            // concurrent Connect can slip through.
            *state_guard = ConnectionState::Connecting;
        }

        // New session generation; the watcher captures this to detect staleness.
        let session_gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;

        // ── Build and spawn the child process ─────────────────────────────
        let mut cmd = Command::new(exe_path);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Safety net: if a `Child` handle is ever dropped without being
            // explicitly killed+reaped (e.g. an unforeseen early return), tokio
            // will kill the process and reap it on drop. This guarantees we can
            // never leak the openconnect child as an orphan/zombie.
            .kill_on_drop(true);

        // On Windows, prevent console window flicker
        #[cfg(target_os = "windows")]
        {
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                // Spawn failed after we reserved the session: reset the state
                // so the UI does not get stuck on "Connecting".
                self.reset_to_failed(&app_handle, "failed to spawn openconnect");
                return Err(AppError::ProcessError(format!(
                    "failed to spawn openconnect: {e}"
                )));
            }
        };
        crate::log_info!("process", "spawned openconnect (pid {:?})", child.id());

        // Track the PID separately so disconnect can kill it even after the
        // watcher takes ownership of the Child handle.
        self.current_pid
            .store(child.id().unwrap_or(0), Ordering::SeqCst);

        // Take ownership of the I/O handles before storing the child.
        let child_stdin = match child.stdin.take() {
            Some(s) => s,
            None => {
                kill_and_reap(child);
                self.reset_to_failed(&app_handle, "failed to capture stdin");
                return Err(AppError::ProcessError("failed to capture stdin".to_string()));
            }
        };

        let child_stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                kill_and_reap(child);
                self.reset_to_failed(&app_handle, "failed to capture stdout");
                return Err(AppError::ProcessError("failed to capture stdout".to_string()));
            }
        };

        let child_stderr = match child.stderr.take() {
            Some(s) => s,
            None => {
                kill_and_reap(child);
                self.reset_to_failed(&app_handle, "failed to capture stderr");
                return Err(AppError::ProcessError("failed to capture stderr".to_string()));
            }
        };

        // Install a fresh shutdown signal for this session's reader tasks so a
        // helper that survives tree-kill holding the pipe can never wedge a
        // reader inside next_line() forever.
        let shutdown = self.new_shutdown();

        // ── Single ordered event channel + dedicated emitter ──────────────
        let (tx, mut rx) = mpsc::channel::<StreamMessage>(EVENT_CHANNEL_CAPACITY);
        let emitter_app = app_handle.clone();
        let emitter_state = Arc::clone(&self.state);
        let emitter_tunnel_ip = Arc::clone(&self.tunnel_ip);

        tokio::spawn(async move {
            // Coalesce consecutive identical state transitions so we never
            // spam the frontend with duplicate events.
            let mut last_emitted_state: Option<ConnectionState> = None;

            // Batch consecutive log lines into a single IPC event. During a log
            // storm openconnect can emit hundreds of lines per second; sending
            // one Tauri event per line floods the IPC bridge and forces one DOM
            // task per line on the frontend. We accumulate `Event`s and flush
            // the whole `Vec` as one `openconnect://events` message, draining
            // whatever is already queued before yielding.
            let mut batch: Vec<ParsedEvent> = Vec::new();

            // Flush the pending log batch (if any) as a single IPC event.
            macro_rules! flush_batch {
                () => {
                    if !batch.is_empty() {
                        let _ = emitter_app.emit("openconnect://events", &batch);
                        batch.clear();
                    }
                };
            }

            while let Some(first) = rx.recv().await {
                // Process the message we just received, then greedily drain any
                // others already sitting in the channel so a burst becomes one
                // batch and one flush rather than one event per line.
                let mut msg = first;
                loop {
                    match msg {
                        StreamMessage::Event(event) => {
                            batch.push(event);
                            // Cap batch size so a truly unbounded storm still
                            // flushes periodically instead of ballooning memory.
                            if batch.len() >= EVENT_BATCH_MAX {
                                flush_batch!();
                            }
                        }
                        StreamMessage::ServerCert(cert) => {
                            // Preserve ordering: emit buffered lines first.
                            flush_batch!();
                            let _ = emitter_app.emit("openconnect://server-cert", &cert);
                        }
                        StreamMessage::TunnelInfo(info) => {
                            // Preserve ordering: emit buffered lines first.
                            flush_batch!();
                            let _ = emitter_app.emit("openconnect://tunnel-info", &info);
                            // Remember the tunnel IP so we can revert NetShield
                            // DNS on teardown.
                            *emitter_tunnel_ip.lock() = info.ip.clone();
                            // Apply NetShield DNS now that the adapter (and its
                            // IP) exist. Loaded from the
                            // global settings file; failures are logged and do
                            // not tear down the (working) tunnel.
                            apply_tunnel_hardening(&emitter_app, &info);
                        }
                        StreamMessage::State(new_state) => {
                            // A state event must arrive after the log line that
                            // triggered it, so flush the batch first.
                            flush_batch!();
                            *emitter_state.lock() = new_state.clone();
                            let emit = match &last_emitted_state {
                                Some(prev) => prev != &new_state,
                                None => true,
                            };
                            if emit {
                                let _ = emitter_app.emit("openconnect://state", &new_state);
                                last_emitted_state = Some(new_state);
                            }
                        }
                    }
                    match rx.try_recv() {
                        Ok(next) => msg = next,
                        Err(_) => break,
                    }
                }
                // Channel momentarily drained: flush whatever lines remain.
                flush_batch!();
            }
        });

        // State was already set to Connecting under the reservation guard; now
        // notify the frontend.
        app_handle
            .emit("openconnect://state", ConnectionState::Connecting)
            .map_err(|e| AppError::ProcessError(format!("failed to emit state event: {e}")))?;

        // ── Write MFA code to stdin if provided ───────────────────────────
        let mut child_stdin = child_stdin;
        if let Some(mut code) = mfa_code {
            let mut line = format!("{code}\n");
            let write_result = child_stdin.write_all(line.as_bytes()).await;
            // Scrub the plaintext secret from our heap copies immediately after
            // the write, regardless of outcome, so it cannot be recovered from a
            // later memory dump.
            use zeroize::Zeroize;
            line.zeroize();
            code.zeroize();
            if let Err(e) = write_result {
                kill_and_reap(child);
                self.reset_to_failed(&app_handle, "failed to write MFA code");
                return Err(AppError::ProcessError(format!(
                    "failed to write MFA code: {e}"
                )));
            }
        }

        // Store child and stdin in the shared state.
        *self.stdin.lock() = Some(child_stdin);
        *self.child.lock() = Some(child);

        // ── Spawn stdout reader task ───────────────────────────────────────
        //
        // `emit_cert = true`: watch stdout for the `--servercert` pin prompt.
        spawn_reader(child_stdout, tx.clone(), Arc::clone(&shutdown), true);

        // ── Spawn stderr reader task ───────────────────────────────────────
        //
        // `emit_cert = true`: openconnect prints the certificate-mismatch hint
        // (`--servercert pin-sha256:...`) on stderr, so the cert branch must run
        // for stderr lines too.
        spawn_reader(child_stderr, tx.clone(), Arc::clone(&shutdown), true);

        // ── Spawn watcher task: waits for exit, updates state ─────────────
        {
            let state_arc = Arc::clone(&self.state);
            let child_arc = Arc::clone(&self.child);
            let stdin_arc = Arc::clone(&self.stdin);
            let gen_arc = Arc::clone(&self.generation);
            let pid_arc = Arc::clone(&self.current_pid);
            let tx_watcher = tx.clone();
            let shutdown_watcher = Arc::clone(&shutdown);

            tokio::spawn(async move {
                // Take the child out of the shared slot so we can await it
                // without holding the MutexGuard across an await point.
                let mut owned_child = {
                    let mut child_guard = child_arc.lock();
                    match child_guard.take() {
                        Some(c) => c,
                        None => return,
                    }
                    // child_guard is dropped here, before any await
                };

                let exit_status = owned_child.wait().await.ok();

                // Staleness check: if the generation changed while we were
                // waiting, this session was superseded by a `disconnect` or a
                // new `connect`. Publishing our terminal state now would clobber
                // the newer session's UI, so we drop it silently.
                if gen_arc.load(Ordering::SeqCst) != session_gen {
                    crate::log_info!(
                        "process",
                        "watcher gen {} superseded; dropping stale exit state",
                        session_gen
                    );
                    return;
                }

                // Determine new state from exit status.
                let new_state = match exit_status {
                    Some(status) if status.success() => ConnectionState::Disconnected,
                    Some(status) => {
                        let code = status
                            .code()
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        ConnectionState::Failed(format!("exit code {code}"))
                    }
                    None => ConnectionState::Failed("process terminated unexpectedly".to_string()),
                };

                // Update shared state.
                *state_arc.lock() = new_state.clone();

                // This session is over; clear the tracked PID.
                pid_arc.store(0, Ordering::SeqCst);

                // Wake the reader tasks in case a helper is still holding a pipe
                // open after openconnect itself exited, so they cannot leak.
                // `notify_one` (not `notify_waiters`) so the signal is not lost
                // for a reader that registers after this point.
                shutdown_watcher.notify_one();

                crate::log_info!("process", "openconnect exited -> {:?}", new_state);

                // NOTE: the kill-switch is deliberately LEFT ENGAGED here. If
                // the tunnel dropped unexpectedly, tearing down the firewall now
                // would be the very IP/DNS leak we are protecting against. The
                // kill-switch is only released on a user-initiated `disconnect`
                // or on app exit (`kill_if_running`).

                // Route the final state through the SAME ordered channel so it is
                // always emitted after the last log line — fully sealing the
                // wrapper↔openconnect state gap. The channel closes only once the
                // reader tasks have finished and dropped their senders, so this
                // message is guaranteed to be last.
                let _ = tx_watcher.send(StreamMessage::State(new_state)).await;

                // Clear the child and stdin handles.
                *child_arc.lock() = None;
                *stdin_arc.lock() = None;
            });
        }

        Ok(())
    }

    /// Reset the connection to a terminal `Failed` state and notify the UI.
    ///
    /// Used on early-return error paths in `connect` (after the session was
    /// reserved as `Connecting`) so the frontend never gets stuck showing a
    /// perpetual "Connecting" state. Also bumps the generation so any watcher
    /// that may have been spawned for this aborted session is treated as stale.
    fn reset_to_failed(&self, app_handle: &AppHandle, reason: &str) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.signal_shutdown();
        self.current_pid.store(0, Ordering::SeqCst);
        *self.state.lock() = ConnectionState::Failed(reason.to_string());
        let _ = app_handle.emit(
            "openconnect://state",
            ConnectionState::Failed(reason.to_string()),
        );
    }

    /// Terminate the running child process and its entire process tree.
    ///
    /// Uses `taskkill /F /T` on Windows to kill the child process and any
    /// processes it spawned (e.g. Wintun adapter scripts). Transitions the
    /// connection state to [`ConnectionState::Disconnecting`] and emits an
    /// `openconnect://state` event so the frontend can update its UI.
    ///
    /// # Parameters
    ///
    /// - `app_handle` — Tauri app handle used to emit the state-change event.
    ///
    /// # Errors
    ///
    /// Returns `Result` for call-site ergonomics. With poison-free
    /// `parking_lot` mutexes the lock never fails, so this currently always
    /// returns `Ok`.
    pub fn disconnect(&self, app_handle: &AppHandle) -> Result<(), AppError> {
        use tauri::Emitter;
        crate::log_info!("process", "disconnect requested");

        // 0. Bump the generation so any in-flight watcher treats its eventual
        //    exit state as stale and does NOT emit a late Failed/Connected that
        //    would flip the UI back after we report Disconnected.
        self.generation.fetch_add(1, Ordering::SeqCst);

        // Wake the reader tasks so they cannot block forever on next_line() if
        // a helper process kept the pipe open past the tree-kill below.
        self.signal_shutdown();

        // 1. Take ownership of the tracked PID and the Child handle (if the
        //    watcher has not already taken it). We kill by the whole process
        //    TREE using the PID, which reaches openconnect and every helper it
        //    spawned (Wintun setup scripts), then drop the owned Child so tokio
        //    reaps its internal handle — no zombie, no orphan.
        let owned_child = self.child.lock().take();
        let pid = owned_child
            .as_ref()
            .and_then(|c| c.id())
            .filter(|p| *p != 0)
            .unwrap_or_else(|| self.current_pid.load(Ordering::SeqCst));
        self.current_pid.store(0, Ordering::SeqCst);

        let killed = kill_process_tree(pid);
        if !killed {
            crate::log_warn!(
                "process",
                "kill_process_tree could not confirm pid {} exited",
                pid
            );
        }

        // Reap the tokio Child handle so its OS handle and any tokio bookkeeping
        // are released. The tree-kill above already terminated the process; this
        // drops our handle (kill_on_drop makes this a no-op if already dead).
        drop(owned_child);

        // User asked to disconnect: release the kill-switch so normal internet
        // access is restored. Idempotent if it was never engaged.
        crate::killswitch::disable();

        // Revert any NetShield DNS we applied to the tunnel adapter.
        let tip = self.tunnel_ip.lock().clone();
        if !tip.is_empty() {
            crate::netshield::disable(&tip);
            *self.tunnel_ip.lock() = String::new();
        }

        // 3. Clear the stdin handle (child handle already taken above).
        *self.stdin.lock() = None;

        // 4. Transition to the terminal `Disconnected` state and emit it
        //    directly.
        //
        //    Rationale: killing the process out from under the watcher task can
        //    prevent the watcher from ever observing the exit (it may have
        //    already taken the Child handle, or we just took it above), so we
        //    cannot rely on the watcher to publish the terminal state. Emitting
        //    `Disconnected` here guarantees the frontend leaves the transient
        //    `Disconnecting` UI within one event loop tick. A late duplicate
        //    `Disconnected` from the watcher is harmless (the emitter coalesces
        //    consecutive identical states, and the frontend is idempotent).
        *self.state.lock() = ConnectionState::Disconnected;
        let _ = app_handle.emit("openconnect://state", ConnectionState::Disconnected);
        Ok(())
    }

    /// Kill the entire process tree of the child process.
    ///
    /// This is intended for use in [`Drop`], Tauri exit hooks, and disconnect
    /// where no async runtime or error handling is available. Uses `taskkill /F /T`
    /// on Windows to ensure all child processes (e.g. Wintun adapter scripts) are
    /// terminated. Errors are silently ignored.
    ///
    /// Also clears the stored stdin handle to release the pipe.
    pub fn kill_if_running(&self) {
        // Bump the generation so any watcher's late exit state is dropped.
        self.generation.fetch_add(1, Ordering::SeqCst);

        // Wake the reader tasks so they exit promptly instead of blocking on a
        // pipe a surviving helper may still hold.
        self.signal_shutdown();

        // Take the Child out (if the watcher hasn't already) and capture the
        // best-known PID. Prefer the live Child's PID; fall back to the tracked
        // PID when the watcher already owns the handle.
        let owned_child = self.child.lock().take();
        let pid = owned_child
            .as_ref()
            .and_then(|c| c.id())
            .filter(|p| *p != 0)
            .unwrap_or_else(|| self.current_pid.swap(0, Ordering::SeqCst));

        // Kill the entire process tree and verify it exited.
        if pid != 0 {
            let _ = kill_process_tree(pid);
        }
        self.current_pid.store(0, Ordering::SeqCst);

        // Drop our Child handle so tokio reaps it (kill_on_drop guarantees the
        // process is dead even if the tree-kill somehow missed it). This runs on
        // synchronous teardown paths (Drop, exit hook) where no runtime await is
        // available; the drop itself does not block on a wait.
        drop(owned_child);

        *self.stdin.lock() = None;

        // App is exiting / cleaning up: never leave the machine firewalled off.
        crate::killswitch::disable();

        // Revert any NetShield DNS applied to the tunnel adapter.
        let tip = self.tunnel_ip.lock().clone();
        if !tip.is_empty() {
            crate::netshield::disable(&tip);
            *self.tunnel_ip.lock() = String::new();
        }
    }

    /// Return the current [`ConnectionState`].
    pub fn get_state(&self) -> ConnectionState {
        self.state.lock().clone()
    }

    /// Return the tunnel's assigned local IP, or an empty string if the tunnel
    /// is not up (or the IP has not been observed yet).
    pub fn get_tunnel_ip(&self) -> String {
        self.tunnel_ip.lock().clone()
    }

    /// Write a string to the openconnect process stdin.
    ///
    /// Used by `submit_mfa` to send a manual MFA code after the process is running.
    ///
    /// # Errors
    /// Returns [`AppError::ProcessError`] if no process is running or the write fails.
    pub async fn write_stdin(&self, data: &str) -> Result<(), AppError> {
        // We must NOT hold the MutexGuard across the .await point because the
        // guard is not Send. Take the stdin handle out of the lock, await the
        // write, then put it back.
        let bytes = data.as_bytes().to_vec();

        // Take the ChildStdin out so we can write without holding the lock
        // across the await point. Put it back regardless of outcome.
        let mut stdin_opt = self.stdin.lock().take();

        let result = if let Some(ref mut stdin) = stdin_opt {
            stdin
                .write_all(&bytes)
                .await
                .map_err(|e| AppError::ProcessError(format!("stdin write failed: {e}")))
        } else {
            Err(AppError::ProcessError("no active process stdin".to_string()))
        };

        // Restore the stdin handle.
        *self.stdin.lock() = stdin_opt;

        result
    }
}

impl Drop for ProcessManager {
    fn drop(&mut self) {
        self.kill_if_running();
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply NetShield DNS once the tunnel adapter has an assigned IP.
///
/// This runs on the dedicated emitter task (not the async command runtime), so
/// all filesystem / netsh work is done synchronously via `std::process`. Any
/// failure is logged; a hardening failure must never tear down a healthy tunnel.
fn apply_tunnel_hardening(app: &AppHandle, info: &crate::types::TunnelInfo) {
    use tauri::Manager;

    let dir = match app.path().app_data_dir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let settings = crate::settings::load_settings(&dir).unwrap_or_default();

    if settings.netshield_enabled {
        if let Err(e) = crate::netshield::enable(&info.ip) {
            crate::log_warn!("netshield", "{}", e);
        }
    }
}
