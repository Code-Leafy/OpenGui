//! Global application settings and tool-toggle state.
//!
//! Unlike [`crate::config`] (which stores per-profile VPN configurations), this
//! module persists *global* UI state: the persistent toggles the redesigned
//! frontend exposes (NetShield sub-features, Kill Switch, Auto
//! Retry) plus the general Settings panel (start with OS, auto-connect, default
//! protocol).
//!
//! The data is a single JSON object at `<app_data_dir>/settings.json`, written
//! atomically via a temp-file + rename so a crash mid-write never leaves a
//! corrupt file.

use serde::{Deserialize, Serialize};

/// The default DNS resolver advertised by the tunnel when NetShield is off.
pub const ADGUARD_IPV4: &[&str] = &["94.140.14.14", "94.140.15.15"];
/// AdGuard DNS-over-TLS / family variants are not used directly; we point the
/// tunnel adapter's plain DNS at the standard AdGuard resolvers above.
pub const ADGUARD_IPV6: &[&str] = &["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"];

/// Per-feature NetShield toggles. These are independently switchable sub-functions
/// of the NetShield umbrella: malware blocking, a "more secure connection"
/// (hardened DNS / no fallback to insecure resolvers), and ad-blocking — all
/// delivered through AdGuard DNS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetShieldConfig {
    /// Block malware domains via AdGuard DNS.
    #[serde(default = "default_true")]
    pub block_malware: bool,
    /// Harden the connection: only resolve through the protected AdGuard DNS.
    #[serde(default = "default_true")]
    pub secure_connection: bool,
    /// Block ads and trackers via AdGuard DNS.
    #[serde(default = "default_true")]
    pub block_ads: bool,
}

impl Default for NetShieldConfig {
    fn default() -> Self {
        Self {
            block_malware: true,
            secure_connection: true,
            block_ads: true,
        }
    }
}

/// Global settings persisted across launches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppSettings {
    /// NetShield master switch. When off, none of the sub-features apply.
    #[serde(default)]
    pub netshield_enabled: bool,
    /// NetShield sub-feature toggles (only meaningful when `netshield_enabled`).
    #[serde(default)]
    pub netshield: NetShieldConfig,
    /// Global kill-switch toggle (engages the firewall block on connect).
    #[serde(default)]
    pub killswitch_enabled: bool,
    /// Auto-retry a dropped connection.
    #[serde(default)]
    pub auto_retry_enabled: bool,
    /// Launch the app when the OS starts.
    #[serde(default)]
    pub start_with_os: bool,
    /// Automatically connect the last-used profile on launch.
    #[serde(default)]
    pub auto_connect: bool,
    /// Id of the most recently connected profile (used by auto-connect).
    #[serde(default)]
    pub last_profile_id: Option<String>,
    /// Selected default protocol label ("OpenConnect" | "WireGuard").
    #[serde(default = "default_protocol")]
    pub default_protocol: String,
    /// Minimize the window to the tray instead of quitting when it is closed.
    #[serde(default = "default_true")]
    pub minimize_on_close: bool,
    /// Automatically check for (and install) updates on startup.
    #[serde(default = "default_true")]
    pub auto_update: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            netshield_enabled: false,
            netshield: NetShieldConfig::default(),
            killswitch_enabled: false,
            auto_retry_enabled: false,
            start_with_os: false,
            auto_connect: false,
            last_profile_id: None,
            default_protocol: "OpenConnect".to_string(),
            minimize_on_close: true,
            auto_update: true,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_protocol() -> String {
    "OpenConnect".to_string()
}

/// Path of the settings file relative to the app data directory.
const SETTINGS_FILE: &str = "settings.json";

/// Load the global settings, returning [`AppSettings::default`] if the file does
/// not yet exist.
///
/// # Errors
///
/// Returns [`crate::types::AppError::Io`] on any I/O error other than
/// "file not found", or [`crate::types::AppError::Serialization`] if the file
/// cannot be parsed.
pub fn load_settings(app_data_dir: &std::path::Path) -> Result<AppSettings, crate::types::AppError> {
    let path = app_data_dir.join(SETTINGS_FILE);
    let contents = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(AppSettings::default()),
        Err(e) => return Err(crate::types::AppError::Io(e)),
    };
    let settings: AppSettings = serde_json::from_str(&contents)?;
    Ok(settings)
}

/// Persist `settings` atomically.
///
/// # Errors
///
/// Returns [`crate::types::AppError::Serialization`] or
/// [`crate::types::AppError::Io`] on failure.
pub fn save_settings(
    app_data_dir: &std::path::Path,
    settings: &AppSettings,
) -> Result<(), crate::types::AppError> {
    std::fs::create_dir_all(app_data_dir)?;
    let unique = format!(
        "settings.json.{}.{}.tmp",
        std::process::id(),
        SETTINGS_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let tmp_path = app_data_dir.join(unique);
    let final_path = app_data_dir.join(SETTINGS_FILE);

    let json = serde_json::to_string_pretty(settings)?;
    if let Err(e) = std::fs::write(&tmp_path, json) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(crate::types::AppError::Io(e));
    }
    if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(crate::types::AppError::Io(e));
    }
    Ok(())
}

static SETTINGS_TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn defaults_roundtrip() {
        let s = AppSettings::default();
        let json = serde_json::to_string(&s).unwrap();
        let back: AppSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn netshield_defaults_true() {
        let ns = NetShieldConfig::default();
        assert!(ns.block_malware && ns.secure_connection && ns.block_ads);
    }

    #[test]
    fn load_returns_default_when_missing() {
        let dir = std::env::temp_dir().join("oc_test_settings_missing");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let s = load_settings(&dir).unwrap();
        assert!(!s.netshield_enabled);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_then_load_persists() {
        let dir = std::env::temp_dir().join("oc_test_settings_save");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let s = AppSettings {
            netshield_enabled: true,
            auto_retry_enabled: true,
            ..AppSettings::default()
        };
        save_settings(&dir, &s).unwrap();
        let loaded = load_settings(&dir).unwrap();
        assert!(loaded.netshield_enabled && loaded.auto_retry_enabled);
        let _ = fs::remove_dir_all(&dir);
    }
}
