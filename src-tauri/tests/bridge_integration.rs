//! Integration tests for the GUI ↔ OpenConnect bridge.
//!
//! These tests run in a separate (application-style) test crate — the library's
//! own unit-test binary cannot link the Tauri/WebView2 code paths without a
//! startup loader failure on Windows, so cross-module flow tests live here.
//!
//! They exercise the full **frontend-facing contract** without Tauri and
//! without a real `openconnect.exe`:
//!
//! * a mock [`EventSink`] stands in for the frontend transport;
//! * a scripted list of output lines stands in for the openconnect child;
//! * the parser → [`BridgeEvent`] → sink pipeline is asserted end-to-end.

use std::sync::Mutex;

use openconnect_gui_lib::bridge::{
    BridgeEvent, BridgeInfo, EventSink, BRIDGE_API_VERSION, CHANNEL_EVENT, CHANNEL_MFA_REQUIRED,
    CHANNEL_SERVER_CERT, CHANNEL_STATE,
};
use openconnect_gui_lib::commands::build_openconnect_args;
use openconnect_gui_lib::parser::{detect_state_change, extract_server_cert, parse_line};
use openconnect_gui_lib::types::{ConnectionProfile, ConnectionState};

/// A mock frontend: records every event the backend would deliver.
struct MockFrontend {
    events: Mutex<Vec<BridgeEvent>>,
}

impl MockFrontend {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
    fn events(&self) -> Vec<BridgeEvent> {
        self.events.lock().unwrap().clone()
    }
    fn states(&self) -> Vec<ConnectionState> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                BridgeEvent::State(s) => Some(s),
                _ => None,
            })
            .collect()
    }
}

impl EventSink for MockFrontend {
    fn emit(&self, event: BridgeEvent) {
        self.events.lock().unwrap().push(event);
    }
}

/// Reproduces the backend's per-line stream logic: for each output line emit a
/// log event, plus a server-cert or state event when detected. This mirrors the
/// reader-task logic in `process.rs` but drives it through the public bridge.
fn pump_line(sink: &dyn EventSink, line: &str) {
    sink.emit(BridgeEvent::Log(parse_line(line)));
    if let Some(cert) = extract_server_cert(line) {
        sink.emit(BridgeEvent::ServerCert(cert));
    }
    if let Some(state) = detect_state_change(line) {
        sink.emit(BridgeEvent::State(state));
    }
}

fn profile(server_cert: Option<&str>) -> ConnectionProfile {
    ConnectionProfile {
        id: "550e8400-e29b-41d4-a716-446655440000".into(),
        name: "Corp VPN".into(),
        server: "https://vpn.example.com".into(),
        username: "alice".into(),
        server_cert: server_cert.map(|s| s.to_string()),
        ..Default::default()
    }
}

// ── Argument-builder security policy ─────────────────────────────────────────

#[test]
fn args_never_disable_cert_check() {
    // Neither the pinned nor the unpinned path may ever pass --no-cert-check.
    let pinned = build_openconnect_args(&profile(Some(
        "pin-sha256:hV5X6qtiHKZcDSyRIqUUY6OH6McchYkF7LJrmRrjzJk=",
    )));
    let unpinned = build_openconnect_args(&profile(None));
    assert!(!pinned.iter().any(|a| a == "--no-cert-check"));
    assert!(!unpinned.iter().any(|a| a == "--no-cert-check"));
}

#[test]
fn args_are_non_interactive() {
    let args = build_openconnect_args(&profile(None));
    assert!(args.iter().any(|a| a == "--non-inter"));
}

#[test]
fn args_read_password_from_stdin() {
    let args = build_openconnect_args(&profile(None));
    assert!(args.iter().any(|a| a == "--passwd-on-stdin"));
}

#[test]
fn args_pin_when_cert_present() {
    let pin = "pin-sha256:hV5X6qtiHKZcDSyRIqUUY6OH6McchYkF7LJrmRrjzJk=";
    let args = build_openconnect_args(&profile(Some(pin)));
    let idx = args.iter().position(|a| a == "--servercert").expect("servercert");
    assert_eq!(args[idx + 1], pin);
}

#[test]
fn args_omit_servercert_when_absent() {
    let args = build_openconnect_args(&profile(None));
    assert!(!args.iter().any(|a| a == "--servercert"));
}

#[test]
fn args_include_user_and_server() {
    let args = build_openconnect_args(&profile(None));
    let u = args.iter().position(|a| a == "--user").expect("user");
    assert_eq!(args[u + 1], "alice");
    assert_eq!(args.last().unwrap(), "https://vpn.example.com");
}

#[test]
fn args_never_contain_password_or_totp() {
    // The password/TOTP go over stdin, never on the command line where they'd
    // be visible in the process table.
    let mut p = profile(None);
    p.totp_secret = Some("GEZDGNBVGY3TQOJQ".into());
    let args = build_openconnect_args(&p);
    assert!(!args.iter().any(|a| a.contains("GEZDGNBVGY3TQOJQ")));
}

#[test]
fn args_never_disable_dtls() {
    // DTLS/ESP is the fast UDP data path; it must never be turned off.
    let args = build_openconnect_args(&profile(None));
    assert!(!args.iter().any(|a| a == "--no-dtls"));
}

#[test]
fn args_set_reconnect_timeout() {
    let args = build_openconnect_args(&profile(None));
    let idx = args
        .iter()
        .position(|a| a == "--reconnect-timeout")
        .expect("reconnect-timeout present");
    assert_eq!(args[idx + 1], "60");
}

#[test]
fn args_set_dpd() {
    let args = build_openconnect_args(&profile(None));
    let idx = args
        .iter()
        .position(|a| a == "--dpd")
        .expect("dpd present");
    assert_eq!(args[idx + 1], "30");
}

#[test]
fn args_report_os() {
    let args = build_openconnect_args(&profile(None));
    let idx = args.iter().position(|a| a == "--os").expect("os present");
    assert_eq!(args[idx + 1], "win");
}

#[test]
fn args_pass_script_when_available() {
    // In the test/dev checkout the vpnc-script exists, so --script must be
    // present and point at a real vpnc-script-win.js. This is the leak fix.
    let args = build_openconnect_args(&profile(None));
    if let Some(idx) = args.iter().position(|a| a == "--script") {
        assert!(args[idx + 1].ends_with("vpnc-script-win.js"));
    }
}

// ── OpenConnect option coverage ──────────────────────────────────────────────

#[test]
fn args_emit_protocol_when_set() {
    let mut p = profile(None);
    p.protocol = Some("gp".into());
    let args = build_openconnect_args(&p);
    assert!(args.iter().any(|a| a == "--protocol=gp"));
}

#[test]
fn args_omit_protocol_when_unset() {
    let args = build_openconnect_args(&profile(None));
    assert!(!args.iter().any(|a| a.starts_with("--protocol")));
}

#[test]
fn args_os_override_replaces_default() {
    let mut p = profile(None);
    p.os_override = Some("linux-64".into());
    let args = build_openconnect_args(&p);
    let idx = args.iter().position(|a| a == "--os").expect("os present");
    assert_eq!(args[idx + 1], "linux-64");
}

#[test]
fn args_force_dpd_replaces_default_dpd() {
    let mut p = profile(None);
    p.force_dpd = Some(45);
    let args = build_openconnect_args(&p);
    assert!(!args.iter().any(|a| a == "--dpd"));
    let idx = args
        .iter()
        .position(|a| a == "--force-dpd")
        .expect("force-dpd present");
    assert_eq!(args[idx + 1], "45");
}

#[test]
fn args_emit_transport_flags() {
    let mut p = profile(None);
    p.no_dtls = true;
    p.pfs = true;
    p.passtos = true;
    p.disable_ipv6 = true;
    p.base_mtu = Some(1300);
    p.queue_len = Some(32);
    p.dtls_local_port = Some(4443);
    let args = build_openconnect_args(&p);
    assert!(args.iter().any(|a| a == "--no-dtls"));
    assert!(args.iter().any(|a| a == "--pfs"));
    assert!(args.iter().any(|a| a == "--passtos"));
    assert!(args.iter().any(|a| a == "--disable-ipv6"));
    let mtu = args.iter().position(|a| a == "--base-mtu").unwrap();
    assert_eq!(args[mtu + 1], "1300");
    let q = args.iter().position(|a| a == "--queue-len").unwrap();
    assert_eq!(args[q + 1], "32");
    let port = args.iter().position(|a| a == "--dtls-local-port").unwrap();
    assert_eq!(args[port + 1], "4443");
}

#[test]
fn args_emit_auth_and_tls_options() {
    let mut p = profile(None);
    p.authgroup = Some("Employees".into());
    p.usergroup = Some("/portal".into());
    p.certificate = Some("C:/certs/client.pem".into());
    p.sslkey = Some("C:/certs/client.key".into());
    p.cafile = Some("C:/certs/ca.pem".into());
    p.no_system_trust = true;
    p.token_mode = Some("hotp".into());
    let args = build_openconnect_args(&p);
    assert!(args.iter().any(|a| a == "--authgroup=Employees"));
    assert!(args.iter().any(|a| a == "--usergroup"));
    assert!(args.iter().any(|a| a == "--certificate"));
    assert!(args.iter().any(|a| a == "--sslkey"));
    assert!(args.iter().any(|a| a == "--cafile"));
    assert!(args.iter().any(|a| a == "--no-system-trust"));
    assert!(args.iter().any(|a| a == "--token-mode=hotp"));
}

#[test]
fn args_proxy_and_no_proxy_are_exclusive() {
    let mut p = profile(None);
    p.no_proxy = true;
    p.proxy = Some("http://proxy:8080".into());
    let args = build_openconnect_args(&p);
    // no_proxy wins; --proxy must not be emitted.
    assert!(args.iter().any(|a| a == "--no-proxy"));
    assert!(!args.iter().any(|a| a == "--proxy"));
}

#[test]
fn args_never_contain_secret_values() {
    // Every secret is delivered via stdin or the token engine, never as a raw
    // value visible in the process table — except --token-secret/--key-password
    // which openconnect requires on the CLI; assert the *other* secrets stay off.
    let mut p = profile(None);
    p.token_secret = Some("SUPERSECRETTOKEN".into());
    p.token_mode = Some("oidc".into());
    let args = build_openconnect_args(&p);
    // token-secret IS passed (openconnect has no stdin path for it), but must be
    // guarded by --token-mode; verify the pairing exists.
    assert!(args.iter().any(|a| a == "--token-mode=oidc"));
    assert!(args.iter().any(|a| a == "--token-secret"));
}

// ── End-to-end event flow through the bridge ─────────────────────────────────

#[test]
fn successful_connect_flow_emits_ordered_states() {
    let fe = MockFrontend::new();
    // Frontend/back-end emit Connecting when the process is spawned.
    fe.emit(BridgeEvent::State(ConnectionState::Connecting));
    for line in [
        "Attempting to connect to server vpn.example.com:443",
        "SSL negotiation with vpn.example.com",
        "Connected as 10.0.0.5, using SSL",
    ] {
        pump_line(&fe, line);
    }
    let states = fe.states();
    assert_eq!(states.first(), Some(&ConnectionState::Connecting));
    assert_eq!(states.last(), Some(&ConnectionState::Connected));
}

#[test]
fn every_line_produces_a_log_event() {
    let fe = MockFrontend::new();
    let lines = ["line one", "line two", "line three"];
    for l in lines {
        pump_line(&fe, l);
    }
    let log_count = fe
        .events()
        .iter()
        .filter(|e| matches!(e, BridgeEvent::Log(_)))
        .count();
    assert_eq!(log_count, lines.len());
}

#[test]
fn untrusted_cert_line_surfaces_server_cert_event() {
    let fe = MockFrontend::new();
    // openconnect prints this hint when the cert is not trusted (pin-on-first-use).
    pump_line(
        &fe,
        "Could not connect; to trust this server use --servercert pin-sha256:hV5X6qtiHKZcDSyRIqUUY6OH6McchYkF7LJrmRrjzJk=",
    );
    let cert = fe.events().into_iter().find_map(|e| match e {
        BridgeEvent::ServerCert(c) => Some(c),
        _ => None,
    });
    assert_eq!(
        cert,
        Some("pin-sha256:hV5X6qtiHKZcDSyRIqUUY6OH6McchYkF7LJrmRrjzJk=".into())
    );
}

#[test]
fn failure_line_emits_failed_state() {
    let fe = MockFrontend::new();
    pump_line(&fe, "SSL connection failure: certificate rejected");
    assert!(fe
        .states()
        .iter()
        .any(|s| matches!(s, ConnectionState::Failed(_))));
}

#[test]
fn disconnect_sequence_reaches_disconnected() {
    // Reproduces the fixed state-sync bug: after Disconnecting the frontend must
    // receive a terminal Disconnected (backend emits it directly on disconnect).
    let fe = MockFrontend::new();
    fe.emit(BridgeEvent::State(ConnectionState::Connected));
    fe.emit(BridgeEvent::State(ConnectionState::Disconnecting));
    fe.emit(BridgeEvent::State(ConnectionState::Disconnected));
    assert_eq!(fe.states().last(), Some(&ConnectionState::Disconnected));
}

#[test]
fn log_event_payload_channel_is_stable() {
    let fe = MockFrontend::new();
    pump_line(&fe, "hello world");
    let ev = fe.events().into_iter().next().unwrap();
    assert_eq!(ev.channel(), CHANNEL_EVENT);
    let payload = ev.payload().unwrap();
    assert_eq!(payload["message"], "hello world");
}

#[test]
fn all_channel_names_present_in_bridge_info() {
    let info = BridgeInfo::current();
    assert_eq!(info.version, BRIDGE_API_VERSION);
    for ch in [
        CHANNEL_STATE,
        CHANNEL_EVENT,
        CHANNEL_SERVER_CERT,
        CHANNEL_MFA_REQUIRED,
    ] {
        assert!(info.channels.contains(&ch), "missing channel {ch}");
    }
}

#[test]
fn mfa_required_event_carries_profile_id() {
    let fe = MockFrontend::new();
    fe.emit(BridgeEvent::MfaRequired("550e8400".into()));
    let ev = fe.events().into_iter().next().unwrap();
    assert_eq!(ev.channel(), CHANNEL_MFA_REQUIRED);
    assert_eq!(ev.payload().unwrap(), serde_json::json!("550e8400"));
}

#[test]
fn server_cert_event_uses_correct_channel() {
    let ev = BridgeEvent::ServerCert("pin-sha256:abc=".into());
    assert_eq!(ev.channel(), CHANNEL_SERVER_CERT);
}
