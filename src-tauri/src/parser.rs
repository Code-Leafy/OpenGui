//! Stdout/stderr line parser for openconnect output.
//!
//! This module provides a pure string-matching parser that converts raw output lines
//! from the openconnect process into structured [`ParsedEvent`] values. It has no
//! dependency on any regex crate — all pattern matching is performed via standard
//! library string methods (`str::contains`, `str::find`, etc.).

use crate::types::{ConnectionState, ParsedEvent};
use std::time::{SystemTime, UNIX_EPOCH};

/// Parse one line of openconnect stdout/stderr into a structured event.
///
/// # Level detection (applied in priority order)
///
/// | Substring present in `line` | Assigned level |
/// |------------------------------|----------------|
/// | `"ERROR"`                    | `"ERROR"`      |
/// | `"WARNING"` or `"WARN"`      | `"WARN"`       |
/// | `"DEBUG"`                    | `"DEBUG"`      |
/// | anything else                | `"INFO"`       |
///
/// The full input `line` is preserved verbatim as `ParsedEvent::message`.
/// A UTC timestamp in `YYYY-MM-DDTHH:MM:SSZ` format is generated from the
/// system clock without any external crate dependency.
pub fn parse_line(line: &str) -> ParsedEvent {
    parse_line_owned(line.to_string(), current_timestamp())
}

/// Build a [`ParsedEvent`] from an **owned** line without cloning it.
///
/// This is the hot-path entry point used by the process reader tasks: the
/// `BufReader` already owns the `String` returned by `next_line()`, so we move
/// it straight into the event instead of allocating a second copy. The caller
/// supplies a precomputed `timestamp` so the calendar conversion is amortised
/// across a whole read batch rather than recomputed for every single line.
pub fn parse_line_owned(line: String, timestamp: String) -> ParsedEvent {
    let level = detect_level(&line);
    parse_line_owned_with_level(line, timestamp, level)
}

/// Build a [`ParsedEvent`] from an owned line whose level has already been
/// classified (e.g. by [`analyze_line`]), avoiding a redundant level scan.
pub fn parse_line_owned_with_level(
    line: String,
    timestamp: String,
    level: &'static str,
) -> ParsedEvent {
    ParsedEvent {
        timestamp,
        level: level.to_string(),
        message: redact_secrets(line),
    }
}

/// Redact secret-looking values from a log line before it is forwarded to the
/// frontend or persisted.
///
/// This is a defense-in-depth chokepoint: even though the app never itself logs
/// passwords, the underlying `openconnect` process may echo challenge/secret
/// text to stdout/stderr. Any `key<sep>value` pair whose key looks sensitive
/// (`password`, `passwd`, `secret`, `pin`, `token`, `otp`) has its value
/// replaced with `***`, keeping the surrounding line intact for diagnostics.
fn redact_secrets(line: String) -> String {
    let lower = line.to_ascii_lowercase();
    const KEYS: [&str; 6] = ["password", "passwd", "secret", "token", "otp", "pin"];
    let mut has_key = false;
    for k in KEYS {
        if lower.contains(k) {
            has_key = true;
            break;
        }
    }
    if !has_key {
        return line;
    }

    let bytes = line.as_bytes();
    let lower_bytes = lower.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        let mut matched_key: Option<usize> = None;
        for k in KEYS {
            let kb = k.as_bytes();
            if i + kb.len() <= lower_bytes.len() && &lower_bytes[i..i + kb.len()] == kb {
                matched_key = Some(kb.len());
                break;
            }
        }
        if let Some(klen) = matched_key {
            out.push_str(&line[i..i + klen]);
            i += klen;
            let mut j = i;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b':' || bytes[j] == b'=') {
                out.push_str(&line[i..=j]);
                i = j + 1;
                while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                    out.push(bytes[i] as char);
                    i += 1;
                }
                let start = i;
                while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\t' {
                    i += 1;
                }
                if i > start {
                    out.push_str("***");
                }
            }
        } else {
            let ch_len = line[i..].chars().next().map(char::len_utf8).unwrap_or(1);
            out.push_str(&line[i..i + ch_len]);
            i += ch_len;
        }
    }
    out
}

/// Result of a single combined scan of one output line.
///
/// Computing the level, any state transition, and any server-cert pin in one
/// place lets callers avoid re-scanning the same line three times. The heavy
/// state/cert checks are gated behind a cheap keyword pre-filter so ordinary
/// log lines (the overwhelming majority) pay for only the level scan plus one
/// `contains` guard.
pub struct LineAnalysis {
    /// Log level for the line (`"INFO"`, `"WARN"`, `"ERROR"`, `"DEBUG"`).
    pub level: &'static str,
    /// A detected connection-state transition, if any.
    pub state: Option<ConnectionState>,
    /// A detected `pin-sha256:` server certificate, if any.
    pub server_cert: Option<String>,
    /// The tunnel's assigned local IP, if this line announces tunnel-up.
    pub tunnel_info: Option<crate::types::TunnelInfo>,
}

/// Analyse a line once, returning its level plus any state/cert signal.
///
/// The state and cert detectors only run when a single cheap `contains` guard
/// indicates the line *might* be interesting, keeping the common case to one
/// level scan + one guard scan instead of ~10-13 substring passes.
pub fn analyze_line(line: &str) -> LineAnalysis {
    let level = detect_level(line);

    // Cheap gate: only the tiny fraction of lines that mention one of these
    // tokens can possibly be a cert pin or a state transition. Everything else
    // skips the heavier multi-keyword scans entirely.
    let maybe_interesting = line.contains("servercert")
        || line.contains("Connect")
        || line.contains("SSL")
        || line.contains("DTLS")
        || line.contains("Fail")
        || line.contains("Configured")
        || line.contains("Attempting");

    if !maybe_interesting {
        return LineAnalysis {
            level,
            state: None,
            server_cert: None,
            tunnel_info: None,
        };
    }

    LineAnalysis {
        level,
        state: detect_state_change(line),
        server_cert: extract_server_cert(line),
        tunnel_info: extract_tunnel_info(line),
    }
}

/// Extract a server certificate pin from an openconnect output line.
///
/// Looks for the pattern `--servercert pin-sha256:...` in the line and returns
/// the full pin string (e.g. `pin-sha256:hV5X6qtiHKZcDSyRIqUUY6OH6McchYkF7LJrmRrjzJk=`).
/// Returns `None` if the line doesn't contain a certificate pin.
pub fn extract_server_cert(line: &str) -> Option<String> {
    // Look for "--servercert pin-sha256:..." pattern
    if let Some(start) = line.find("--servercert pin-sha256:") {
        let pin_start = start + "--servercert ".len();
        // Find the end of the pin (whitespace or end of line)
        let pin_end = line[pin_start..]
            .find(|c: char| c.is_whitespace())
            .map(|i| pin_start + i)
            .unwrap_or(line.len());
        let pin = &line[pin_start..pin_end];
        // Require an actual hash payload after the "pin-sha256:" prefix; a bare
        // "pin-sha256:" is malformed and must not be accepted.
        if pin.len() > "pin-sha256:".len() {
            return Some(pin.to_string());
        }
    }
    None
}

/// Detect connection state changes from openconnect output lines.
///
/// Returns `Some(ConnectionState)` when a state-relevant line is detected:
/// - `"Configured as"` + `"SSL connected"` → `Connected`
/// - `"Connected as"` (openconnect's actual tunnel-up message) → `Connected`
/// - `"SSL connection failure"` / `"Failed to complete authentication"` /
///   `"Failed to open HTTPS connection"` → `Failed`
/// - `"Establishing DTLS"` / `"DTLS connection attempt"` / `"SSL negotiation"` → `Connecting`
///
/// Returns `None` for lines that don't indicate a state change.
pub fn detect_state_change(line: &str) -> Option<ConnectionState> {
    if (line.contains("Configured as") && line.contains("SSL connected"))
        || line.contains("Connected as")
        || line.contains("Connection established")
    {
        Some(ConnectionState::Connected)
    } else if line.contains("SSL connection failure")
        || line.contains("Failed to complete authentication")
        || line.contains("Failed to open HTTPS connection")
        || line.contains("Connection failed")
    {
        Some(ConnectionState::Failed("connection failed".to_string()))
    } else if line.contains("Establishing DTLS")
        || line.contains("DTLS connection attempt")
        || line.contains("SSL negotiation")
        || line.contains("Attempting to connect")
    {
        Some(ConnectionState::Connecting)
    } else {
        None
    }
}

/// Extract the tunnel's assigned local IP from openconnect's tunnel-up line.
///
/// openconnect prints `Connected as <ip>` (optionally `(with DTLS)` or
/// `, using SSL`). Returns a [`crate::types::TunnelInfo`] with that IP, or
/// `None` if the line is not a tunnel-up announcement.
pub fn extract_tunnel_info(line: &str) -> Option<crate::types::TunnelInfo> {
    let rest = line.trim().strip_prefix("Connected as")?;
    // The IP is the first whitespace-delimited token of the remainder.
    let ip = rest
        .split(|c: char| c.is_whitespace() || c == ',' || c == '(')
        .find(|tok| !tok.is_empty())?
        .trim()
        .to_string();
    // Reject anything that isn't an IP literal (defence-in-depth before it is
    // interpolated into a `netsh` interface lookup).
    if ip.parse::<std::net::IpAddr>().is_err() {
        return None;
    }
    Some(crate::types::TunnelInfo { ip, gateway: None })
}

/// Detect the log level for a single output line using substring matching.
///
/// Returns one of `"ERROR"`, `"WARN"`, `"DEBUG"`, or `"INFO"`.
fn detect_level(line: &str) -> &'static str {
    if line.contains("ERROR") {
        "ERROR"
    } else if line.contains("WARNING") || line.contains("WARN") {
        "WARN"
    } else if line.contains("DEBUG") {
        "DEBUG"
    } else {
        "INFO"
    }
}

/// Produce a UTC timestamp string in `YYYY-MM-DDTHH:MM:SSZ` format.
///
/// Uses only [`std::time::SystemTime`] and integer arithmetic — no `chrono`,
/// no `time` crate, no regex. If `SystemTime::now()` somehow precedes the
/// Unix epoch (unreachable on any modern OS) the duration defaults to zero,
/// yielding `1970-01-01T00:00:00Z`.
pub fn current_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (year, month, day, hour, min, sec) = secs_to_datetime(secs);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

/// Convert a Unix timestamp (seconds since 1970-01-01T00:00:00Z) to individual
/// UTC date/time components `(year, month, day, hour, minute, second)`.
///
/// Uses the proleptic Gregorian calendar via the Julian Day Number algorithm
/// (Civil Date from Julian Day — Fliegel & Van Flandern, 1968).
fn secs_to_datetime(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let sec = (secs % 60) as u32;
    let mins_total = secs / 60;
    let min = (mins_total % 60) as u32;
    let hours_total = mins_total / 60;
    let hour = (hours_total % 24) as u32;
    let days = hours_total / 24; // days since 1970-01-01

    // Julian Day Number for 1970-01-01 is 2440588.
    let jdn = days + 2_440_588;

    // Fliegel & Van Flandern algorithm (Communications of the ACM, 1968).
    let l = jdn + 68_569;
    let n = (4 * l) / 146_097;
    let l = l - (146_097 * n).div_ceil(4);
    let i = (4000 * (l + 1)) / 1_461_001;
    let l = l - (1461 * i) / 4 + 31;
    let j = (80 * l) / 2447;
    let day = l - (2447 * j) / 80;
    let l = j / 11;
    let month = j + 2 - 12 * l;
    let year = 100 * (n - 49) + i + l;

    (year as u32, month as u32, day as u32, hour, min, sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── detect_level unit tests ────────────────────────────────────────────

    #[test]
    fn error_keyword_yields_error_level() {
        assert_eq!(detect_level("ERROR: tunnel closed"), "ERROR");
    }

    #[test]
    fn warning_keyword_yields_warn_level() {
        assert_eq!(detect_level("WARNING: certificate expired"), "WARN");
    }

    #[test]
    fn warn_keyword_yields_warn_level() {
        assert_eq!(detect_level("WARN: retrying"), "WARN");
    }

    #[test]
    fn debug_keyword_yields_debug_level() {
        assert_eq!(detect_level("DEBUG: sending packet"), "DEBUG");
    }

    #[test]
    fn plain_line_yields_info_level() {
        assert_eq!(detect_level("Connected to vpn.example.com"), "INFO");
    }

    #[test]
    fn empty_line_yields_info_level() {
        assert_eq!(detect_level(""), "INFO");
    }

    #[test]
    fn error_takes_priority_over_warn() {
        // A line containing both ERROR and WARN should resolve to ERROR.
        assert_eq!(detect_level("ERROR WARNING mismatch"), "ERROR");
    }

    #[test]
    fn warning_takes_priority_over_debug() {
        assert_eq!(detect_level("WARNING DEBUG info"), "WARN");
    }

    // ── redaction tests ───────────────────────────────────────────────────

    #[test]
    fn redact_scrubs_password_value() {
        let e = parse_line("Password: hunter2");
        assert_eq!(e.message, "Password: ***");
    }

    #[test]
    fn redact_scrubs_equals_form() {
        let e = parse_line("secret=abc123 extra");
        assert_eq!(e.message, "secret=*** extra");
    }

    #[test]
    fn redact_leaves_ordinary_lines_untouched() {
        let input = "Connected to vpn.example.com port 443";
        let e = parse_line(input);
        assert_eq!(e.message, input);
    }

    #[test]
    fn redact_keeps_key_without_value() {
        let e = parse_line("Password:");
        assert_eq!(e.message, "Password:");
    }

    // ── parse_line integration tests ──────────────────────────────────────

    #[test]
    fn parse_line_preserves_message() {
        let input = "Connected to vpn.example.com port 443";
        let event = parse_line(input);
        assert_eq!(event.message, input);
    }

    #[test]
    fn parse_line_error_message() {
        let event = parse_line("ERROR: authentication failed");
        assert_eq!(event.level, "ERROR");
        assert_eq!(event.message, "ERROR: authentication failed");
    }

    #[test]
    fn parse_line_timestamp_format() {
        let event = parse_line("some line");
        // Must be exactly 20 characters: YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(event.timestamp.len(), 20, "timestamp length wrong: {}", event.timestamp);
        assert!(event.timestamp.ends_with('Z'), "timestamp must end with Z: {}", event.timestamp);
        assert_eq!(&event.timestamp[4..5], "-");
        assert_eq!(&event.timestamp[7..8], "-");
        assert_eq!(&event.timestamp[10..11], "T");
        assert_eq!(&event.timestamp[13..14], ":");
        assert_eq!(&event.timestamp[16..17], ":");
    }

    #[test]
    fn parse_line_non_empty_message_is_non_empty() {
        let event = parse_line("hello");
        assert!(!event.message.is_empty());
    }

    // ── secs_to_datetime unit tests ───────────────────────────────────────

    #[test]
    fn unix_epoch_converts_correctly() {
        let (year, month, day, hour, min, sec) = secs_to_datetime(0);
        assert_eq!((year, month, day, hour, min, sec), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn known_date_2025_01_15_converts_correctly() {
        // 2025-01-15T10:30:00Z  →  Unix timestamp 1736936200 + offset
        // Calculated: days from 1970-01-01 to 2025-01-15
        // = 55 * 365 + leap_years + 14 days in January
        // Precomputed: 2025-01-15 00:00:00 UTC = 1736899200
        let ts: u64 = 1_736_899_200 + 10 * 3600 + 30 * 60;
        let (year, month, day, hour, min, sec) = secs_to_datetime(ts);
        assert_eq!((year, month, day, hour, min, sec), (2025, 1, 15, 10, 30, 0));
    }

    #[test]
    fn leap_year_date_feb_29_converts_correctly() {
        // 2024-02-29T00:00:00Z = 1709164800
        let (year, month, day, hour, min, sec) = secs_to_datetime(1_709_164_800);
        assert_eq!((year, month, day, hour, min, sec), (2024, 2, 29, 0, 0, 0));
    }

    // ── extract_server_cert unit tests ─────────────────────────────────────

    #[test]
    fn extract_server_cert_from_openconnect_output() {
        // The function should extract the pin from a single line
        let single_line = "--servercert pin-sha256:hV5X6qtiHKZcDSyRIqUUY6OH6McchYkF7LJrmRrjzJk=";
        let cert = extract_server_cert(single_line);
        assert_eq!(cert, Some("pin-sha256:hV5X6qtiHKZcDSyRIqUUY6OH6McchYkF7LJrmRrjzJk=".to_string()));
    }

    #[test]
    fn extract_server_cert_returns_none_for_normal_line() {
        let line = "Connected to vpn.example.com port 443";
        let cert = extract_server_cert(line);
        assert_eq!(cert, None);
    }

    #[test]
    fn extract_server_cert_handles_line_with_trailing_whitespace() {
        let line = "--servercert pin-sha256:abc123  ";
        let cert = extract_server_cert(line);
        assert_eq!(cert, Some("pin-sha256:abc123".to_string()));
    }

    // ── detect_state_change unit tests ─────────────────────────────────────

    #[test]
    fn detect_connected_state() {
        let line = "Configured as 10.10.159.253, with SSL connected and DTLS connected";
        let state = detect_state_change(line);
        assert_eq!(state, Some(ConnectionState::Connected));
    }

    #[test]
    fn detect_connected_state_connected_as() {
        // openconnect's real tunnel-up message
        let line = "Connected as 10.10.159.253 (with DTLS)";
        let state = detect_state_change(line);
        assert_eq!(state, Some(ConnectionState::Connected));
    }

    #[test]
    fn detect_connecting_state() {
        let line = "Establishing DTLS connection";
        let state = detect_state_change(line);
        assert_eq!(state, Some(ConnectionState::Connecting));
    }

    #[test]
    fn detect_connecting_state_ssl_negotiation() {
        let line = "SSL negotiation with vpn.example.com";
        let state = detect_state_change(line);
        assert_eq!(state, Some(ConnectionState::Connecting));
    }

    #[test]
    fn detect_failed_state_connection_failed() {
        let line = "Connection failed: unexpected packet";
        let state = detect_state_change(line);
        assert!(matches!(state, Some(ConnectionState::Failed(_))));
    }

    #[test]
    fn detect_failed_state_ssl_failure() {
        let line = "SSL connection failure: Error in the certificate.";
        let state = detect_state_change(line);
        assert!(matches!(state, Some(ConnectionState::Failed(_))));
    }

    #[test]
    fn detect_failed_state_auth_failure() {
        let line = "Failed to complete authentication";
        let state = detect_state_change(line);
        assert!(matches!(state, Some(ConnectionState::Failed(_))));
    }

    #[test]
    fn detect_none_for_normal_line() {
        let line = "Connected to vpn.example.com port 443";
        let state = detect_state_change(line);
        assert_eq!(state, None);
    }

    // ── Edge case tests ───────────────────────────────────────────────────

    #[test]
    fn parse_line_extremely_long_output() {
        let long_line = "x".repeat(10_000);
        let event = parse_line(&long_line);
        assert_eq!(event.message.len(), 10_000);
        assert_eq!(event.level, "INFO");
    }

    #[test]
    fn parse_line_unicode_content() {
        let line = "Connected to 日本サーバー via 🔒";
        let event = parse_line(line);
        assert_eq!(event.message, line);
    }

    #[test]
    fn parse_line_null_bytes() {
        let line = "output\x00with\x00nulls";
        let event = parse_line(line);
        assert_eq!(event.message, line);
    }

    #[test]
    fn detect_state_change_partial_configured_as() {
        // "Configured as" without "SSL connected" should NOT trigger Connected
        let line = "Configured as 10.10.159.253, without DTLS";
        let state = detect_state_change(line);
        assert_eq!(state, None);
    }

    #[test]
    fn extract_server_cert_malformed_partial() {
        let line = "--servercert pin-sha256:";
        let cert = extract_server_cert(line);
        assert_eq!(cert, None);
    }

    #[test]
    fn extract_server_cert_malformed_no_prefix() {
        let line = "pin-sha256:hV5X6qtiHKZcDSyRIqUUY6OH6McchYkF7LJrmRrjzJk=";
        let cert = extract_server_cert(line);
        assert_eq!(cert, None);
    }

    #[test]
    fn timestamp_rollover_midnight() {
        // 2025-01-01T00:00:00Z = 1735689600
        let (year, month, day, hour, min, sec) = secs_to_datetime(1_735_689_600);
        assert_eq!((year, month, day, hour, min, sec), (2025, 1, 1, 0, 0, 0));
    }

    #[test]
    fn timestamp_year_2038() {
        // 2038-01-19T03:14:07Z (Unix 32-bit max) = 2147483647
        let (year, month, day, hour, min, sec) = secs_to_datetime(2_147_483_647);
        assert_eq!(year, 2038);
        assert_eq!(month, 1);
        assert_eq!(day, 19);
        assert_eq!(hour, 3);
        assert_eq!(min, 14);
        assert_eq!(sec, 7);
    }

    #[test]
    fn detect_level_case_sensitive() {
        // "error" lowercase should NOT match "ERROR"
        assert_eq!(detect_level("error: something"), "INFO");
    }

    #[test]
    fn parse_line_multiple_keywords() {
        let line = "ERROR: WARNING: DEBUG: all present";
        let event = parse_line(line);
        assert_eq!(event.level, "ERROR"); // ERROR takes priority
    }

    #[test]
    fn detect_state_change_failed_to_open() {
        let line = "Failed to open HTTPS connection to vpn.example.com";
        let state = detect_state_change(line);
        assert!(matches!(state, Some(ConnectionState::Failed(_))));
    }

    #[test]
    fn detect_state_change_dtls_attempt() {
        let line = "DTLS connection attempt started";
        let state = detect_state_change(line);
        assert_eq!(state, Some(ConnectionState::Connecting));
    }

    #[test]
    fn stress_parse_many_lines() {
        // Parse 1000 lines without panicking
        for i in 0..1000 {
            let line = format!("Line {i}: some output");
            let event = parse_line(&line);
            assert_eq!(event.message, line);
            assert!(!event.timestamp.is_empty());
        }
    }

    // ── Additional detect_level edge cases ───────────────────────────────

    #[test]
    fn detect_level_substring_within_word() {
        // "ERROR" as a substring of a larger word
        assert_eq!(detect_level("CUSTOM_ERROR_HANDLER"), "ERROR");
    }

    #[test]
    fn detect_level_warn_within_longer_word() {
        assert_eq!(detect_level("WARN_ABOUT_TLS"), "WARN");
    }

    #[test]
    fn detect_level_debug_within_longer_word() {
        assert_eq!(detect_level("DEBUG_MODE_ON"), "DEBUG");
    }

    #[test]
    fn detect_level_warn_misspelled() {
        // "WARN" not "WARN" - should fall through to INFO
        assert_eq!(detect_level("WARN: test"), "WARN");
    }

    #[test]
    fn detect_level_all_keywords_mixed() {
        assert_eq!(detect_level("DEBUG WARN ERROR"), "ERROR");
    }

    #[test]
    fn detect_level_only_numbers() {
        assert_eq!(detect_level("12345 67890"), "INFO");
    }

    #[test]
    fn detect_level_special_chars_only() {
        assert_eq!(detect_level("!@#$%^&*()"), "INFO");
    }

    // ── Additional detect_state_change edge cases ────────────────────────

    #[test]
    fn detect_state_change_ssl_negotiation_via_contains() {
        // "SSL negotiation" is emitted while the tunnel is being brought up, so
        // it must be reported as a Connecting transition.
        let line = "SSL negotiation with vpn.example.com";
        let state = detect_state_change(line);
        assert_eq!(state, Some(ConnectionState::Connecting));
    }

    #[test]
    fn detect_state_change_formal_connect_established() {
        // "Configured as" without "SSL connected" should not match Connected
        let line = "Configured as 10.0.0.2";
        let state = detect_state_change(line);
        assert_eq!(state, None);
    }

    #[test]
    fn detect_state_change_empty_line() {
        assert_eq!(detect_state_change(""), None);
    }

    #[test]
    fn detect_state_change_only_ssl_connected() {
        // Need both "Configured as" and "SSL connected"
        let line = "SSL connected to server";
        let state = detect_state_change(line);
        assert_eq!(state, None);
    }

    // ── Additional extract_server_cert edge cases ────────────────────────

    #[test]
    fn extract_server_cert_line_with_extra_args_after() {
        let line = "--servercert pin-sha256:abc123 --other-flag value";
        let cert = extract_server_cert(line);
        assert_eq!(cert, Some("pin-sha256:abc123".to_string()));
    }

    #[test]
    fn extract_server_cert_multiple_pins_in_line() {
        // Only the first occurrence is extracted via `find`
        let line = "--servercert pin-sha256:first --servercert pin-sha256:second";
        let cert = extract_server_cert(line);
        assert_eq!(cert, Some("pin-sha256:first".to_string()));
    }

    #[test]
    fn extract_server_cert_unicode_in_line() {
        let line = "--servercert pin-sha256:abc123 日本語";
        let cert = extract_server_cert(line);
        assert_eq!(cert, Some("pin-sha256:abc123".to_string()));
    }

    #[test]
    fn extract_server_cert_empty_line() {
        assert_eq!(extract_server_cert(""), None);
    }

    #[test]
    fn extract_server_cert_no_pin_prefix() {
        let line = "--servercert not-a-pin";
        let cert = extract_server_cert(line);
        assert_eq!(cert, None);
    }

    // ── secs_to_datetime additional edge cases ───────────────────────────

    #[test]
    fn secs_to_datetime_leap_year_non_leap() {
        // 2023-03-01T00:00:00Z = 1677628800 (year after non-leap Feb)
        let (year, month, day, _, _, _) = secs_to_datetime(1_677_628_800);
        assert_eq!((year, month, day), (2023, 3, 1));
    }

    #[test]
    fn secs_to_datetime_end_of_year() {
        // 2024-12-31T23:59:59Z = 1735689599
        let (year, month, day, hour, min, sec) = secs_to_datetime(1_735_689_599);
        assert_eq!((year, month, day, hour, min, sec), (2024, 12, 31, 23, 59, 59));
    }

    #[test]
    fn secs_to_datetime_epoch_plus_one_second() {
        let (year, month, day, hour, min, sec) = secs_to_datetime(1);
        assert_eq!((year, month, day, hour, min, sec), (1970, 1, 1, 0, 0, 1));
    }

    #[test]
    fn secs_to_datetime_one_day_after_epoch() {
        let (year, month, day, hour, min, sec) = secs_to_datetime(86400);
        assert_eq!((year, month, day, hour, min, sec), (1970, 1, 2, 0, 0, 0));
    }

    // ── parse_line edge cases ────────────────────────────────────────────

    #[test]
    fn parse_line_whitespace_only() {
        let line = "   ";
        let event = parse_line(line);
        assert_eq!(event.message, "   ");
        assert_eq!(event.level, "INFO");
    }

    #[test]
    fn parse_line_newline_in_middle() {
        let line = "line1\nline2";
        let event = parse_line(line);
        assert_eq!(event.message, "line1\nline2");
    }

    #[test]
    fn parse_line_tab_characters() {
        let line = "out\tput";
        let event = parse_line(line);
        assert_eq!(event.message, "out\tput");
    }

    #[test]
    fn parse_line_very_short() {
        let event = parse_line("a");
        assert_eq!(event.message, "a");
        assert_eq!(event.level, "INFO");
    }

    // ── parse_line_owned / _with_level ──────────────────────────────────────

    #[test]
    fn parse_line_owned_moves_message_and_uses_given_timestamp() {
        let event = parse_line_owned("ERROR: boom".to_string(), "2020-01-01T00:00:00Z".to_string());
        assert_eq!(event.message, "ERROR: boom");
        assert_eq!(event.level, "ERROR");
        assert_eq!(event.timestamp, "2020-01-01T00:00:00Z");
    }

    #[test]
    fn parse_line_owned_matches_parse_line_semantics() {
        let line = "WARN: something odd happened";
        let a = parse_line(line);
        let b = parse_line_owned(line.to_string(), a.timestamp.clone());
        assert_eq!(a, b);
    }

    #[test]
    fn parse_line_owned_with_level_trusts_supplied_level() {
        // Even though the text has no keyword, the caller-supplied level wins.
        let event = parse_line_owned_with_level(
            "plain text".to_string(),
            "2020-01-01T00:00:00Z".to_string(),
            "DEBUG",
        );
        assert_eq!(event.level, "DEBUG");
        assert_eq!(event.message, "plain text");
    }

    // ── analyze_line ────────────────────────────────────────────────────────

    #[test]
    fn analyze_line_plain_line_has_no_state_or_cert() {
        let a = analyze_line("INFO: routine heartbeat");
        assert_eq!(a.level, "INFO");
        assert!(a.state.is_none());
        assert!(a.server_cert.is_none());
    }

    #[test]
    fn analyze_line_level_matches_detect_level() {
        for line in [
            "ERROR: x",
            "WARN: y",
            "DEBUG: z",
            "ordinary message",
            "SSL connected",
            "Connection failed",
        ] {
            assert_eq!(analyze_line(line).level, detect_level(line), "line: {line}");
        }
    }

    #[test]
    fn analyze_line_detects_server_cert() {
        let line = "Server certificate --servercert pin-sha256:abc123 verify";
        let a = analyze_line(line);
        assert_eq!(a.server_cert, extract_server_cert(line));
        assert!(a.server_cert.is_some());
    }

    // ── extract_tunnel_info unit tests ─────────────────────────────────────

    #[test]
    fn extract_tunnel_info_ipv4_with_dtls() {
        let info = extract_tunnel_info("Connected as 10.0.0.5 (with DTLS)").unwrap();
        assert_eq!(info.ip, "10.0.0.5");
    }

    #[test]
    fn extract_tunnel_info_ipv6_accepted() {
        let info = extract_tunnel_info("Connected as 2001:db8::1").unwrap();
        assert_eq!(info.ip, "2001:db8::1");
    }

    #[test]
    fn extract_tunnel_info_rejects_non_ip() {
        assert!(extract_tunnel_info("Connected as not-an-ip").is_none());
    }

    #[test]
    fn extract_tunnel_info_none_for_unrelated_line() {
        assert!(extract_tunnel_info("Connected to vpn.example.com port 443").is_none());
    }

    /// The cheap keyword gate in `analyze_line` MUST be a superset of every
    /// token the standalone detectors key off, or transitions/certs would be
    /// silently dropped. This asserts parity across representative lines that
    /// exercise each state and the cert path.
    #[test]
    fn analyze_line_state_and_cert_match_standalone_detectors() {
        let lines = [
            "Configured as 10.0.0.2, with SSL connected",
            "Connected as 10.0.0.2",
            "Connection established",
            "SSL connection failure",
            "Failed to complete authentication",
            "Failed to open HTTPS connection to vpn.example.com",
            "Connection failed",
            "Establishing DTLS connection",
            "DTLS connection attempt",
            "SSL negotiation with vpn.example.com",
            "Attempting to connect to server",
            "Server certificate --servercert pin-sha256:deadbeef confirmed",
            "just a normal informational line",
            "",
        ];
        for line in lines {
            let a = analyze_line(line);
            assert_eq!(
                a.state,
                detect_state_change(line),
                "state mismatch for line: {line:?}"
            );
            assert_eq!(
                a.server_cert,
                extract_server_cert(line),
                "cert mismatch for line: {line:?}"
            );
        }
    }
}
