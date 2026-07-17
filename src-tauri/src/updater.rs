//! Auto-update commands backed by `tauri-plugin-updater`.
//!
//! The frontend calls [`check_for_update`] to learn whether a newer signed
//! release is available (metadata only — nothing is downloaded), then
//! [`install_update`] to download, verify the signature against the embedded
//! public key, install it, and relaunch the app.

use serde::Serialize;
use tauri::{AppHandle, Manager};
use tauri_plugin_updater::UpdaterExt;

/// Metadata about an available update, returned to the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateInfo {
    /// Whether a newer version than the running one is available.
    pub available: bool,
    /// The available version string (semver), when `available` is true.
    pub version: Option<String>,
    /// The currently running version.
    pub current_version: String,
    /// Optional release notes / changelog body from the update manifest.
    pub notes: Option<String>,
}

/// Check the configured update endpoint for a newer signed release.
///
/// This only fetches and verifies the update *manifest*; it does not download
/// the installer. On any network/parse error it returns an error string so the
/// UI can show a "couldn't check" message without crashing.
///
/// # Errors
///
/// Returns an error string if the updater cannot be built or the endpoint
/// cannot be reached / parsed.
#[tauri::command]
pub async fn check_for_update(app: AppHandle) -> Result<UpdateInfo, String> {
    let current_version = app.package_info().version.to_string();

    let updater = app.updater().map_err(|e| e.to_string())?;

    match updater.check().await {
        Ok(Some(update)) => Ok(UpdateInfo {
            available: true,
            version: Some(update.version.clone()),
            current_version,
            notes: update.body.clone(),
        }),
        Ok(None) => Ok(UpdateInfo {
            available: false,
            version: None,
            current_version,
            notes: None,
        }),
        Err(e) => Err(e.to_string()),
    }
}

/// Download, verify, install the latest update and relaunch the app.
///
/// The signature is verified against the public key embedded in
/// `tauri.conf.json`; an update with a missing or invalid signature is
/// rejected by the plugin before installation.
///
/// # Errors
///
/// Returns an error string if no update is available, or if the download,
/// signature verification, or installation fails.
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<(), String> {
    let updater = app.updater().map_err(|e| e.to_string())?;

    let update = updater
        .check()
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "No update available".to_string())?;

    update
        .download_and_install(|_downloaded, _total| {}, || {})
        .await
        .map_err(|e| e.to_string())?;

    // Installation succeeded; relaunch into the new version.
    tauri::process::restart(&app.env());
}
