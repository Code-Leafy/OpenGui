//! # Bridge — the UI-agnostic contract between any frontend and OpenConnect.
//!
//! This module is the **stable, versioned public API** that a frontend consumes
//! to drive the VPN backend. It deliberately contains **no Tauri types** so that
//! a completely different frontend (web service, CLI, mobile shell) can reuse the
//! same contract by implementing two small traits.
//!
//! ## The two seams
//!
//! * [`EventSink`] — how backend → frontend messages are delivered. The Tauri
//!   application implements this by emitting Tauri events; tests implement it by
//!   collecting events into a `Vec`.
//! * [`VpnBackend`] — how the frontend → backend commands drive the underlying
//!   OpenConnect process. The real implementation is
//!   [`crate::process::ProcessManager`]; tests use an in-memory mock.
//!
//! ## Wire format
//!
//! Every backend → frontend message is a [`BridgeEvent`]. Each variant maps to a
//! stable **channel name** (see [`BridgeEvent::channel`]) and a JSON **payload**
//! (see [`BridgeEvent::payload`]). This mapping is what a new frontend subscribes
//! to; it is covered by round-trip tests so it cannot drift silently.
//!
//! ## Versioning
//!
//! [`BRIDGE_API_VERSION`] follows semantic versioning. Additive changes bump the
//! minor version; breaking changes to a channel name or payload shape bump the
//! major version. Frontends may read the version via the `bridge_version`
//! command to negotiate compatibility.

use serde::Serialize;

use crate::types::{ConnectionState, ParsedEvent, TunnelInfo};

/// Semantic version of the bridge API contract.
///
/// Bump the **minor** for backwards-compatible additions (new optional events),
/// the **major** for breaking changes to any channel name or payload shape.
pub const BRIDGE_API_VERSION: &str = "1.1.0";

/// Channel name for connection-state transitions.
pub const CHANNEL_STATE: &str = "openconnect://state";
/// Channel name for a single structured log line parsed from openconnect output.
pub const CHANNEL_EVENT: &str = "openconnect://event";
/// Channel name for a *batch* of structured log lines coalesced into one event.
///
/// During a log storm openconnect can emit hundreds of lines per second; the
/// runtime emitter coalesces them into a single `Vec<ParsedEvent>` per flush to
/// avoid flooding the IPC bridge and the frontend with one event per line.
pub const CHANNEL_EVENTS: &str = "openconnect://events";
/// Channel name for a server-certificate pin detected in openconnect output.
pub const CHANNEL_SERVER_CERT: &str = "openconnect://server-cert";
/// Channel name requesting the frontend prompt the user for an MFA code.
pub const CHANNEL_MFA_REQUIRED: &str = "openconnect://mfa-required";
/// Channel name carrying the tunnel's assigned local address (and, when known,
/// gateway) once the connection comes up. Consumed by NetShield (to locate the
/// tunnel adapter for DNS).
pub const CHANNEL_TUNNEL_INFO: &str = "openconnect://tunnel-info";

/// A single backend → frontend message.
///
/// This is the canonical, UI-agnostic representation of everything the backend
/// can push to a frontend. An [`EventSink`] implementation is responsible for
/// serialising it onto the appropriate transport (Tauri events, a WebSocket,
/// stdout for a CLI, etc.).
///
/// Use [`BridgeEvent::channel`] to get the stable channel/topic name and
/// [`BridgeEvent::payload`] to get the JSON body a frontend receives.
#[derive(Debug, Clone, PartialEq)]
pub enum BridgeEvent {
    /// The connection lifecycle state changed.
    State(ConnectionState),
    /// A structured log line was produced by openconnect.
    Log(ParsedEvent),
    /// A batch of structured log lines coalesced into a single event.
    LogBatch(Vec<ParsedEvent>),
    /// A server-certificate pin (`pin-sha256:...`) was observed.
    ServerCert(String),
    /// The backend needs an MFA/password code for the given profile id.
    MfaRequired(String),
    /// The tunnel came up; carries the assigned local IP (and optional gateway).
    TunnelInfo(TunnelInfo),
}

impl BridgeEvent {
    /// The stable channel/topic name this event is published on.
    pub fn channel(&self) -> &'static str {
        match self {
            BridgeEvent::State(_) => CHANNEL_STATE,
            BridgeEvent::Log(_) => CHANNEL_EVENT,
            BridgeEvent::LogBatch(_) => CHANNEL_EVENTS,
            BridgeEvent::ServerCert(_) => CHANNEL_SERVER_CERT,
            BridgeEvent::MfaRequired(_) => CHANNEL_MFA_REQUIRED,
            BridgeEvent::TunnelInfo(_) => CHANNEL_TUNNEL_INFO,
        }
    }

    /// The JSON payload a frontend receives for this event.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] only if the underlying value cannot be
    /// serialised, which is unreachable for these plain data types.
    pub fn payload(&self) -> Result<serde_json::Value, serde_json::Error> {
        match self {
            BridgeEvent::State(s) => serde_json::to_value(s),
            BridgeEvent::Log(e) => serde_json::to_value(e),
            BridgeEvent::LogBatch(e) => serde_json::to_value(e),
            BridgeEvent::ServerCert(c) => serde_json::to_value(c),
            BridgeEvent::MfaRequired(id) => serde_json::to_value(id),
            BridgeEvent::TunnelInfo(info) => serde_json::to_value(info),
        }
    }
}

/// Sink for backend → frontend messages.
///
/// Implementors deliver a [`BridgeEvent`] to whatever transport the frontend
/// listens on. Implementations must be cheap and non-blocking; the backend may
/// call [`emit`](EventSink::emit) from latency-sensitive paths.
pub trait EventSink: Send + Sync + 'static {
    /// Deliver a single event to the frontend. Delivery errors are the sink's
    /// responsibility to handle (typically logged and swallowed) — the backend
    /// treats emission as best-effort.
    fn emit(&self, event: BridgeEvent);
}

/// Metadata describing the bridge contract, returned by the `bridge_version`
/// command so a frontend can negotiate compatibility at startup.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BridgeInfo {
    /// Semantic version of the bridge API (see [`BRIDGE_API_VERSION`]).
    pub version: &'static str,
    /// The channel names a frontend must subscribe to, in a stable order:
    /// `[state, event, events, server-cert, mfa-required, tunnel-info]`.
    pub channels: [&'static str; 6],
}

impl BridgeInfo {
    /// Construct the current bridge metadata.
    pub fn current() -> Self {
        Self {
            version: BRIDGE_API_VERSION,
            channels: [
                CHANNEL_STATE,
                CHANNEL_EVENT,
                CHANNEL_EVENTS,
                CHANNEL_SERVER_CERT,
                CHANNEL_MFA_REQUIRED,
                CHANNEL_TUNNEL_INFO,
            ],
        }
    }
}

impl Default for BridgeInfo {
    fn default() -> Self {
        Self::current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A test [`EventSink`] that records every emitted event.
    struct CollectingSink {
        events: Mutex<Vec<BridgeEvent>>,
    }

    impl CollectingSink {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }
        fn take(&self) -> Vec<BridgeEvent> {
            std::mem::take(&mut self.events.lock().unwrap())
        }
    }

    impl EventSink for CollectingSink {
        fn emit(&self, event: BridgeEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn channel_names_are_stable() {
        assert_eq!(
            BridgeEvent::State(ConnectionState::Connected).channel(),
            "openconnect://state"
        );
        assert_eq!(
            BridgeEvent::Log(ParsedEvent {
                timestamp: "t".into(),
                level: "INFO".into(),
                message: "m".into(),
            })
            .channel(),
            "openconnect://event"
        );
        assert_eq!(
            BridgeEvent::LogBatch(vec![]).channel(),
            "openconnect://events"
        );
        assert_eq!(
            BridgeEvent::ServerCert("pin-sha256:x".into()).channel(),
            "openconnect://server-cert"
        );
        assert_eq!(
            BridgeEvent::MfaRequired("id".into()).channel(),
            "openconnect://mfa-required"
        );
    }

    #[test]
    fn state_payload_matches_connection_state_json() {
        let ev = BridgeEvent::State(ConnectionState::Connected);
        let payload = ev.payload().unwrap();
        let direct = serde_json::to_value(ConnectionState::Connected).unwrap();
        assert_eq!(payload, direct);
    }

    #[test]
    fn failed_state_payload_preserves_message() {
        let ev = BridgeEvent::State(ConnectionState::Failed("boom".into()));
        let payload = ev.payload().unwrap();
        assert_eq!(payload, serde_json::json!({ "Failed": "boom" }));
    }

    #[test]
    fn mfa_required_payload_is_bare_string() {
        let ev = BridgeEvent::MfaRequired("profile-1".into());
        assert_eq!(ev.payload().unwrap(), serde_json::json!("profile-1"));
    }

    #[test]
    fn server_cert_payload_is_bare_string() {
        let ev = BridgeEvent::ServerCert("pin-sha256:abc=".into());
        assert_eq!(ev.payload().unwrap(), serde_json::json!("pin-sha256:abc="));
    }

    #[test]
    fn tunnel_info_channel_and_payload() {
        let ev = BridgeEvent::TunnelInfo(crate::types::TunnelInfo {
            ip: "10.10.159.253".into(),
            gateway: None,
        });
        assert_eq!(ev.channel(), CHANNEL_TUNNEL_INFO);
        let payload = ev.payload().unwrap();
        assert_eq!(payload["ip"], "10.10.159.253");
    }

    #[test]
    fn log_payload_has_expected_fields() {
        let ev = BridgeEvent::Log(ParsedEvent {
            timestamp: "2025-01-01T00:00:00Z".into(),
            level: "WARN".into(),
            message: "hello".into(),
        });
        let payload = ev.payload().unwrap();
        assert_eq!(payload["timestamp"], "2025-01-01T00:00:00Z");
        assert_eq!(payload["level"], "WARN");
        assert_eq!(payload["message"], "hello");
    }

    #[test]
    fn log_batch_payload_is_json_array_of_events() {
        let ev = BridgeEvent::LogBatch(vec![
            ParsedEvent {
                timestamp: "t1".into(),
                level: "INFO".into(),
                message: "a".into(),
            },
            ParsedEvent {
                timestamp: "t2".into(),
                level: "ERROR".into(),
                message: "b".into(),
            },
        ]);
        let payload = ev.payload().unwrap();
        assert!(payload.is_array());
        assert_eq!(payload.as_array().unwrap().len(), 2);
        assert_eq!(payload[0]["message"], "a");
        assert_eq!(payload[1]["level"], "ERROR");
    }

    #[test]
    fn collecting_sink_records_in_order() {
        let sink = CollectingSink::new();
        sink.emit(BridgeEvent::State(ConnectionState::Connecting));
        sink.emit(BridgeEvent::State(ConnectionState::Connected));
        let events = sink.take();
        assert_eq!(
            events,
            vec![
                BridgeEvent::State(ConnectionState::Connecting),
                BridgeEvent::State(ConnectionState::Connected),
            ]
        );
    }

    #[test]
    fn bridge_info_lists_all_channels() {
        let info = BridgeInfo::current();
        assert_eq!(info.version, BRIDGE_API_VERSION);
        assert!(info.channels.contains(&CHANNEL_STATE));
        assert!(info.channels.contains(&CHANNEL_EVENT));
        assert!(info.channels.contains(&CHANNEL_EVENTS));
        assert!(info.channels.contains(&CHANNEL_SERVER_CERT));
        assert!(info.channels.contains(&CHANNEL_MFA_REQUIRED));
    }

    #[test]
    fn bridge_info_serialises() {
        let json = serde_json::to_value(BridgeInfo::current()).unwrap();
        assert_eq!(json["version"], BRIDGE_API_VERSION);
        assert_eq!(json["channels"][0], CHANNEL_STATE);
    }

    #[test]
    fn bridge_version_is_semver() {
        let parts: Vec<&str> = BRIDGE_API_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit())));
    }
}
