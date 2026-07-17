use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Resolve a Windows system executable (e.g. `netsh.exe`, `route.exe`,
/// `taskkill.exe`, `reg.exe`) to its absolute `System32` path.
///
/// Spawning these tools by bare name lets Windows resolve them via `PATH`/CWD,
/// which is a DLL/binary hijack vector for an elevated process. Always calling
/// the absolute `%SystemRoot%\System32\<exe>` path removes that surface.
#[cfg(target_os = "windows")]
pub(crate) fn system32_exe(exe: &str) -> std::path::PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    std::path::Path::new(&root).join("System32").join(exe)
}

/// A named VPN endpoint configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionProfile {
    /// Unique identifier (UUID v4 generated at creation time).
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// VPN server URL, e.g. "https://vpn.example.com".
    pub server: String,
    /// Username credential.
    pub username: String,
    /// Optional base32-encoded TOTP secret.
    ///
    /// **Input-only / never persisted to `profiles.json`.** The frontend sends
    /// this field when adding or updating a profile; the backend immediately
    /// moves it into Windows Credential Manager (target
    /// `openconnect-gui/<id>/totp`) and clears it to `None` before writing the
    /// profile to disk. On load and over IPC to the UI this field is always
    /// `None`; the real secret is fetched from Credential Manager at connect
    /// time. This keeps the TOTP seed out of the plaintext profile store.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub totp_secret: Option<String>,
    /// Optional server certificate pin (e.g. "pin-sha256:...").
    /// When set, passed as --servercert to openconnect.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub server_cert: Option<String>,
    /// When true, a firewall kill-switch blocks all non-tunnel outbound
    /// traffic while this profile is connected, preventing IP/DNS leaks if the
    /// tunnel drops. Defaults to `false` for backward compatibility.
    #[serde(default)]
    pub kill_switch: bool,
    /// ISO 3166-1 alpha-2 country code (lowercase, e.g. `"de"`, `"us"`) of the
    /// server, detected via GeoIP. Drives the profile's flag icon in the UI.
    /// `None`/empty means "unknown" (a generic globe flag is shown).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub country_code: Option<String>,

    // ── OpenConnect option coverage (all optional, backward-compatible) ──────
    //
    // These map onto `openconnect` command-line flags (verified against the
    // bundled v9.21 `--help`). Persisted plainly in profiles.json EXCEPT the
    // secret fields at the bottom, which are input-only and moved to Windows
    // Credential Manager (like `totp_secret`).
    /// `--protocol=<VALUE>`: one of anyconnect, nc, gp, pulse, f5, fortinet,
    /// array. `None`/empty means the openconnect default (anyconnect).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub protocol: Option<String>,
    /// `--authgroup=GROUP`: login group / realm / domain on multi-group servers.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub authgroup: Option<String>,
    /// `-g, --usergroup=GROUP`: path of the initial request URL.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub usergroup: Option<String>,
    /// `--token-mode=MODE`: rsa, totp, hotp or oidc. Uses openconnect's native
    /// token engine (alternative to the app-side TOTP in `totp_secret`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token_mode: Option<String>,
    /// `-c, --certificate=CERT`: SSL client certificate file path.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub certificate: Option<String>,
    /// `-k, --sslkey=KEY`: SSL private key file path.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sslkey: Option<String>,
    /// `--mca-certificate=MCACERT`: multiple-certificate-auth certificate.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mca_certificate: Option<String>,
    /// `--mca-key=MCAKEY`: multiple-certificate-auth key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mca_key: Option<String>,
    /// `--external-browser=BROWSER`: external browser executable for SSO/SAML.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub external_browser: Option<String>,
    /// `--no-external-auth`: refuse auth methods that require an external
    /// browser.
    #[serde(default)]
    pub no_external_auth: bool,
    /// `-P, --proxy=URL`: proxy server URL.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proxy: Option<String>,
    /// `--proxy-auth=METHODS`: allowed proxy authentication methods.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proxy_auth: Option<String>,
    /// `--no-proxy`: disable all proxy use.
    #[serde(default)]
    pub no_proxy: bool,
    /// `--resolve=HOST:IP`: static host->IP override when connecting.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resolve: Option<String>,
    /// `--sni=HOST`: TLS client SNI to send (domain fronting).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sni: Option<String>,
    /// `--cafile=FILE`: CA cert file for server verification.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cafile: Option<String>,
    /// `--no-system-trust`: disable default system certificate authorities.
    #[serde(default)]
    pub no_system_trust: bool,
    /// `--allow-insecure-crypto`: allow ancient 3DES/RC4 ciphers.
    #[serde(default)]
    pub allow_insecure_crypto: bool,
    /// `--dtls-ciphers=LIST`: OpenSSL cipher list for DTLS.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dtls_ciphers: Option<String>,
    /// `--base-mtu=MTU`: indicate path MTU to/from the server.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub base_mtu: Option<u32>,
    /// `--no-dtls`: disable DTLS and ESP (force TLS-only transport).
    #[serde(default)]
    pub no_dtls: bool,
    /// `--pfs`: require perfect forward secrecy.
    #[serde(default)]
    pub pfs: bool,
    /// `--dtls-local-port=PORT`: local port for DTLS/ESP datagrams.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dtls_local_port: Option<u16>,
    /// `--force-dpd=INTERVAL`: dead-peer-detection interval override (seconds).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub force_dpd: Option<u32>,
    /// `--passtos`: copy TOS/TCLASS field into DTLS and ESP packets.
    #[serde(default)]
    pub passtos: bool,
    /// `-Q, --queue-len=LEN`: packet queue limit (packets).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub queue_len: Option<u32>,
    /// `--disable-ipv6`: do not request IPv6 connectivity.
    #[serde(default)]
    pub disable_ipv6: bool,
    /// `-d, --deflate`: enable stateful compression.
    #[serde(default)]
    pub deflate: bool,
    /// `--useragent=STRING`: HTTP User-Agent header.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub useragent: Option<String>,
    /// `--version-string=STRING`: reported version during authentication.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version_string: Option<String>,
    /// `--os=STRING`: OS type to report (linux, linux-64, win, mac-intel,
    /// android, apple-ios). Overrides the wrapper default of `win`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub os_override: Option<String>,
    /// `--local-hostname=STRING`: local hostname advertised to the server.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub local_hostname: Option<String>,

    // ── Secret fields: input-only, moved to Credential Manager, never in JSON ─
    /// `--token-secret=STRING`: software token secret / oidc token. Stored in
    /// Credential Manager under `openconnect-gui/<id>/token-secret`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token_secret: Option<String>,
    /// `-p, --key-password=PASS`: SSL key passphrase / TPM SRK PIN. Stored under
    /// `openconnect-gui/<id>/key-password`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key_password: Option<String>,
    /// `--mca-key-password=MCAPASS`: MCA key passphrase. Stored under
    /// `openconnect-gui/<id>/mca-key-password`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mca_key_password: Option<String>,
}

/// The lifecycle state of the VPN connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionState {
    /// No active connection.
    Disconnected,
    /// Connection attempt is in progress.
    Connecting,
    /// VPN tunnel is established.
    Connected,
    /// Graceful teardown is in progress.
    Disconnecting,
    /// Connection failed; contains diagnostic message.
    Failed(String),
}

/// The local address assigned to the tunnel adapter once the connection is up.
///
/// Derived from openconnect's `Connected as <ip>` line. `ip` is the tunnel's
/// assigned address; `gateway` is best-effort (often absent from the log).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TunnelInfo {
    /// Tunnel-local IP address (e.g. `10.10.159.253`).
    pub ip: String,
    /// Optional gateway address for the tunnel subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

/// A structured event produced by parsing one line of openconnect output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParsedEvent {
    /// ISO-8601 timestamp when the line was received.
    pub timestamp: String,
    /// Log level: one of "INFO", "WARN", "ERROR", "DEBUG".
    pub level: String,
    /// The parsed message text.
    pub message: String,
}

/// Unified application error type.
#[derive(Debug, Error)]
pub enum AppError {
    /// Wraps std::io::Error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization or deserialization failure.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Windows Credential Manager API failure.
    #[error("Credential error (Win32 code {0})")]
    CredentialError(u32),
    /// TOTP secret decoding or generation failure.
    #[error("TOTP error: {0}")]
    TotpError(String),
    /// Child process spawn or management failure.
    #[error("Process error: {0}")]
    ProcessError(String),
    /// Referenced profile does not exist.
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ConnectionState serialization tests ───────────────────────────────

    #[test]
    fn connection_state_disconnected_roundtrip() {
        let state = ConnectionState::Disconnected;
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ConnectionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn connection_state_connecting_roundtrip() {
        let state = ConnectionState::Connecting;
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ConnectionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn connection_state_connected_roundtrip() {
        let state = ConnectionState::Connected;
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ConnectionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn connection_state_disconnecting_roundtrip() {
        let state = ConnectionState::Disconnecting;
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ConnectionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn connection_state_failed_roundtrip() {
        let state = ConnectionState::Failed("test error".to_string());
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ConnectionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn connection_state_failed_empty_string() {
        let state = ConnectionState::Failed("".to_string());
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ConnectionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn connection_state_partial_eq_disconnected_vs_failed() {
        assert_ne!(ConnectionState::Disconnected, ConnectionState::Failed("x".to_string()));
    }

    #[test]
    fn connection_state_partial_eq_connecting_vs_connected() {
        assert_ne!(ConnectionState::Connecting, ConnectionState::Connected);
    }

    // ── ConnectionProfile serialization tests ─────────────────────────────

    #[test]
    fn profile_serialization_roundtrip() {
        let profile = ConnectionProfile {
            id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            name: "Test VPN".to_string(),
            server: "https://vpn.example.com".to_string(),
            username: "alice".to_string(),
            totp_secret: Some("GEZDGNBVGY3TQOJQ".to_string()),
            server_cert: Some("pin-sha256:abc123=".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: ConnectionProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile.id, deserialized.id);
        assert_eq!(profile.name, deserialized.name);
        assert_eq!(profile.server, deserialized.server);
        assert_eq!(profile.username, deserialized.username);
        assert_eq!(profile.totp_secret, deserialized.totp_secret);
        assert_eq!(profile.server_cert, deserialized.server_cert);
    }

    #[test]
    fn profile_optional_fields_none_omitted() {
        let profile = ConnectionProfile {
            id: "test".to_string(),
            name: "Test".to_string(),
            server: "https://vpn.example.com".to_string(),
            username: "user".to_string(),
            ..Default::default()
        };
        let json = serde_json::to_string(&profile).unwrap();
        // Optional fields should be omitted when None
        assert!(!json.contains("totp_secret"));
        assert!(!json.contains("server_cert"));
    }

    #[test]
    fn profile_deserializes_without_optional_fields() {
        let json = r#"{"id":"test","name":"Test","server":"https://vpn.example.com","username":"user"}"#;
        let profile: ConnectionProfile = serde_json::from_str(json).unwrap();
        assert!(profile.totp_secret.is_none());
        assert!(profile.server_cert.is_none());
    }

    #[test]
    fn profile_deserializes_with_only_totp() {
        let json = r#"{"id":"t1","name":"T","server":"https://v","username":"u","totp_secret":"GEZDGNBVGY3TQOJQ"}"#;
        let profile: ConnectionProfile = serde_json::from_str(json).unwrap();
        assert_eq!(profile.totp_secret.as_deref(), Some("GEZDGNBVGY3TQOJQ"));
        assert!(profile.server_cert.is_none());
    }

    #[test]
    fn profile_deserializes_with_only_cert() {
        let json = r#"{"id":"t2","name":"T","server":"https://v","username":"u","server_cert":"pin-sha256:abc="}"#;
        let profile: ConnectionProfile = serde_json::from_str(json).unwrap();
        assert!(profile.totp_secret.is_none());
        assert_eq!(profile.server_cert.as_deref(), Some("pin-sha256:abc="));
    }

    #[test]
    fn profile_serialization_with_empty_optional_is_omitted() {
        // Even if totp_secret is Some(""), it will be serialized because it's Some
        let profile = ConnectionProfile {
            id: "x".to_string(),
            name: "x".to_string(),
            server: "https://x".to_string(),
            username: "x".to_string(),
            totp_secret: Some("".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&profile).unwrap();
        assert!(json.contains("totp_secret"));
        assert!(!json.contains("server_cert"));
    }

    // ── ParsedEvent serialization tests ───────────────────────────────────

    #[test]
    fn parsed_event_serialization_roundtrip() {
        let event = ParsedEvent {
            timestamp: "2025-01-15T10:30:00Z".to_string(),
            level: "INFO".to_string(),
            message: "Connected to vpn.example.com".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ParsedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.timestamp, deserialized.timestamp);
        assert_eq!(event.level, deserialized.level);
        assert_eq!(event.message, deserialized.message);
    }

    #[test]
    fn parsed_event_json_shape() {
        let event = ParsedEvent {
            timestamp: "2025-01-15T10:30:00Z".to_string(),
            level: "ERROR".to_string(),
            message: "Something failed".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["timestamp"], "2025-01-15T10:30:00Z");
        assert_eq!(parsed["level"], "ERROR");
        assert_eq!(parsed["message"], "Something failed");
    }

    #[test]
    fn parsed_event_empty_message() {
        let event = ParsedEvent {
            timestamp: "2025-01-15T10:30:00Z".to_string(),
            level: "INFO".to_string(),
            message: "".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ParsedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.message, "");
    }

    #[test]
    fn parsed_event_long_message() {
        let msg = "a".repeat(10000);
        let event = ParsedEvent {
            timestamp: "2025-01-15T10:30:00Z".to_string(),
            level: "WARN".to_string(),
            message: msg.clone(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ParsedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.message.len(), 10000);
        assert_eq!(deserialized.level, "WARN");
    }

    // ── AppError display tests ────────────────────────────────────────────

    #[test]
    fn app_error_io_display() {
        let err = AppError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "file missing"));
        let msg = format!("{}", err);
        assert!(msg.contains("I/O error"));
        assert!(msg.contains("file missing"));
    }

    #[test]
    fn app_error_serialization_display() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = AppError::Serialization(json_err);
        let msg = format!("{}", err);
        assert!(msg.contains("Serialization error"));
    }

    #[test]
    fn app_error_credential_display() {
        let err = AppError::CredentialError(1168);
        let msg = format!("{}", err);
        assert!(msg.contains("1168"));
    }

    #[test]
    fn app_error_credential_zero_code() {
        let err = AppError::CredentialError(0);
        let msg = format!("{}", err);
        assert!(msg.contains("0"));
    }

    #[test]
    fn app_error_totp_display() {
        let err = AppError::TotpError("bad secret".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("TOTP error"));
        assert!(msg.contains("bad secret"));
    }

    #[test]
    fn app_error_totp_empty_string() {
        let err = AppError::TotpError("".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("TOTP error"));
    }

    #[test]
    fn app_error_process_display() {
        let err = AppError::ProcessError("spawn failed".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Process error"));
        assert!(msg.contains("spawn failed"));
    }

    #[test]
    fn app_error_process_empty_message() {
        let err = AppError::ProcessError("".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Process error"));
    }

    #[test]
    fn app_error_profile_not_found_display() {
        let err = AppError::ProfileNotFound("my-profile".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Profile not found"));
        assert!(msg.contains("my-profile"));
    }

    #[test]
    fn app_error_profile_not_found_empty() {
        let err = AppError::ProfileNotFound("".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Profile not found"));
    }

    // ── TunnelInfo serialization tests ───────────────────────────────────

    #[test]
    fn tunnel_info_serialization_roundtrip() {
        let info = TunnelInfo {
            ip: "10.10.159.253".to_string(),
            gateway: Some("10.10.159.1".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: TunnelInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info.ip, back.ip);
        assert_eq!(info.gateway, back.gateway);
    }

    #[test]
    fn tunnel_info_omits_none_gateway() {
        let info = TunnelInfo {
            ip: "10.10.159.253".to_string(),
            gateway: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("gateway"));
    }
}
