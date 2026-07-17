//! Profile persistence — loads and saves [`ConnectionProfile`] records as a
//! JSON array to `<app_data_dir>/profiles.json`.
//!
//! Atomic writes are achieved by writing to a `.tmp` sibling file first and
//! then renaming it over the target, so a crash mid-write never leaves a
//! corrupt file on disk.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::types::{AppError, ConnectionProfile};

/// Path of the profiles file relative to the app data directory.
const PROFILES_FILE: &str = "profiles.json";

/// Monotonic counter used to build unique temp-file names so concurrent writers
/// (multiple threads, or a second app instance) never share the same temp file.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Load all saved profiles from `<app_data_dir>/profiles.json`.
///
/// If the file does not yet exist (e.g. first launch), an empty [`Vec`] is
/// returned instead of an error.
///
/// # Errors
///
/// Returns [`AppError::Io`] on any I/O error other than "file not found", or
/// [`AppError::Serialization`] if the file contents cannot be parsed as a JSON
/// array of [`ConnectionProfile`] objects.
pub fn load_profiles(app_data_dir: &Path) -> Result<Vec<ConnectionProfile>, AppError> {
    let path = app_data_dir.join(PROFILES_FILE);

    let contents = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(AppError::Io(e)),
    };

    let profiles: Vec<ConnectionProfile> = serde_json::from_str(&contents)?;
    Ok(profiles)
}

/// Persist `profiles` to `<app_data_dir>/profiles.json` atomically.
///
/// The data is written to a unique `profiles.json.<pid>.<n>.tmp` sibling first,
/// then that file is renamed over `profiles.json`. This ensures a crash
/// mid-write never leaves a corrupt or empty profiles file, and concurrent
/// writers never collide on a shared temp file.
///
/// # Errors
///
/// Returns [`AppError::Serialization`] if serialization fails, or
/// [`AppError::Io`] if the write or rename fails.
pub fn save_profiles(app_data_dir: &Path, profiles: &[ConnectionProfile]) -> Result<(), AppError> {
    std::fs::create_dir_all(app_data_dir)?;
    let unique = format!(
        "profiles.json.{}.{}.tmp",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let tmp_path = app_data_dir.join(unique);
    let final_path = app_data_dir.join(PROFILES_FILE);

    let json = serde_json::to_string_pretty(profiles)?;
    if let Err(e) = std::fs::write(&tmp_path, json) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(AppError::Io(e));
    }
    if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(AppError::Io(e));
    }

    Ok(())
}

/// Add a new profile and persist the updated list.
///
/// The profile is appended to the existing list. No uniqueness check is
/// performed on `profile.id`; callers are responsible for generating a unique
/// identifier (e.g. a UUID v4).
///
/// # Errors
///
/// Propagates any error returned by [`load_profiles`] or [`save_profiles`].
pub fn add_profile(app_data_dir: &Path, profile: ConnectionProfile) -> Result<(), AppError> {
    let mut profiles = load_profiles(app_data_dir)?;
    profiles.push(profile);
    save_profiles(app_data_dir, &profiles)
}

/// Replace the profile whose `id` matches `profile.id` in place and persist
/// the updated list.
///
/// # Errors
///
/// Returns [`AppError::ProfileNotFound`] if no profile with the given `id`
/// exists. Propagates any error returned by [`load_profiles`] or
/// [`save_profiles`].
pub fn update_profile(app_data_dir: &Path, profile: ConnectionProfile) -> Result<(), AppError> {
    let mut profiles = load_profiles(app_data_dir)?;

    let pos = profiles
        .iter()
        .position(|p| p.id == profile.id)
        .ok_or_else(|| AppError::ProfileNotFound(profile.id.clone()))?;

    profiles[pos] = profile;
    save_profiles(app_data_dir, &profiles)
}

/// Remove the profile with the given `id` and persist the updated list.
///
/// # Errors
///
/// Returns [`AppError::ProfileNotFound`] if no profile with the given `id`
/// exists. Propagates any error returned by [`load_profiles`] or
/// [`save_profiles`].
pub fn delete_profile(app_data_dir: &Path, id: &str) -> Result<(), AppError> {
    let mut profiles = load_profiles(app_data_dir)?;

    let pos = profiles
        .iter()
        .position(|p| p.id == id)
        .ok_or_else(|| AppError::ProfileNotFound(id.to_owned()))?;

    profiles.remove(pos);
    save_profiles(app_data_dir, &profiles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_profile(id: &str, name: &str) -> ConnectionProfile {
        ConnectionProfile {
            id: id.to_owned(),
            name: name.to_owned(),
            server: "https://vpn.example.com".to_owned(),
            username: "alice".to_owned(),
            ..Default::default()
        }
    }

    // ── load_profiles ────────────────────────────────────────────────────────

    #[test]
    fn load_returns_empty_when_file_missing() {
        let dir = std::env::temp_dir().join("oc_test_load_missing");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let result = load_profiles(&dir).expect("should not error on missing file");
        assert!(result.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_returns_profiles_when_file_exists() {
        let dir = std::env::temp_dir().join("oc_test_load_exists");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let profiles = vec![make_profile("id1", "Test VPN")];
        save_profiles(&dir, &profiles).unwrap();

        let loaded = load_profiles(&dir).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "id1");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── save_profiles ────────────────────────────────────────────────────────

    #[test]
    fn save_writes_atomically_via_tmp() {
        let dir = std::env::temp_dir().join("oc_test_save_atomic");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let profiles = vec![make_profile("id2", "Atomic VPN")];
        save_profiles(&dir, &profiles).unwrap();

        // Final file should exist; no temp file should survive.
        assert!(dir.join(PROFILES_FILE).exists());
        let leftover_tmp = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover_tmp);

        let _ = fs::remove_dir_all(&dir);
    }

    // ── add_profile ──────────────────────────────────────────────────────────

    #[test]
    fn add_profile_appends_and_persists() {
        let dir = std::env::temp_dir().join("oc_test_add");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        add_profile(&dir, make_profile("a", "First")).unwrap();
        add_profile(&dir, make_profile("b", "Second")).unwrap();

        let loaded = load_profiles(&dir).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, "a");
        assert_eq!(loaded[1].id, "b");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── update_profile ───────────────────────────────────────────────────────

    #[test]
    fn update_profile_replaces_in_place() {
        let dir = std::env::temp_dir().join("oc_test_update");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        add_profile(&dir, make_profile("u1", "Original")).unwrap();

        let mut updated = make_profile("u1", "Updated");
        updated.server = "https://new.example.com".to_owned();
        update_profile(&dir, updated).unwrap();

        let loaded = load_profiles(&dir).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Updated");
        assert_eq!(loaded[0].server, "https://new.example.com");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_profile_returns_not_found_for_unknown_id() {
        let dir = std::env::temp_dir().join("oc_test_update_notfound");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let err = update_profile(&dir, make_profile("ghost", "Ghost")).unwrap_err();
        assert!(
            matches!(err, AppError::ProfileNotFound(ref id) if id == "ghost"),
            "expected ProfileNotFound(\"ghost\"), got: {err:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── delete_profile ───────────────────────────────────────────────────────

    #[test]
    fn delete_profile_removes_correct_entry() {
        let dir = std::env::temp_dir().join("oc_test_delete");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        add_profile(&dir, make_profile("d1", "Keep")).unwrap();
        add_profile(&dir, make_profile("d2", "Remove")).unwrap();

        delete_profile(&dir, "d2").unwrap();

        let loaded = load_profiles(&dir).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "d1");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_profile_returns_not_found_for_unknown_id() {
        let dir = std::env::temp_dir().join("oc_test_delete_notfound");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let err = delete_profile(&dir, "nobody").unwrap_err();
        assert!(
            matches!(err, AppError::ProfileNotFound(ref id) if id == "nobody"),
            "expected ProfileNotFound(\"nobody\"), got: {err:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Edge case tests ───────────────────────────────────────────────────

    #[test]
    fn load_corrupted_json_returns_error() {
        let dir = std::env::temp_dir().join("oc_test_corrupted");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(PROFILES_FILE), "{not valid json!!!").unwrap();

        let result = load_profiles(&dir);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::Serialization(_)));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_empty_file_returns_empty() {
        let dir = std::env::temp_dir().join("oc_test_empty_file");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(PROFILES_FILE), "").unwrap();

        let result = load_profiles(&dir);
        assert!(result.is_err()); // Empty string is not valid JSON array

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_invalid_utf8_returns_error() {
        let dir = std::env::temp_dir().join("oc_test_invalid_utf8");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Write invalid UTF-8 bytes
        fs::write(dir.join(PROFILES_FILE), [0xFF, 0xFE, 0x00]).unwrap();

        let result = load_profiles(&dir);
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn profile_with_optional_fields_none() {
        let dir = std::env::temp_dir().join("oc_test_optional_none");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let profile = ConnectionProfile {
            id: "test-optional-none".to_string(),
            name: "No Optionals".to_string(),
            server: "https://vpn.example.com".to_string(),
            username: "user".to_string(),
            ..Default::default()
        };

        add_profile(&dir, profile).unwrap();
        let loaded = load_profiles(&dir).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].totp_secret.is_none());
        assert!(loaded[0].server_cert.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn profile_special_chars_in_name() {
        let dir = std::env::temp_dir().join("oc_test_special_chars");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let profile = ConnectionProfile {
            id: "test-special".to_string(),
            name: "VPN: \"Work\" <Site>".to_string(),
            server: "https://vpn.example.com".to_string(),
            username: "user".to_string(),
            ..Default::default()
        };

        add_profile(&dir, profile).unwrap();
        let loaded = load_profiles(&dir).unwrap();
        assert_eq!(loaded[0].name, "VPN: \"Work\" <Site>");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn profile_with_all_optional_fields() {
        let dir = std::env::temp_dir().join("oc_test_all_optionals");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let profile = ConnectionProfile {
            id: "test-all-opt".to_string(),
            name: "Full Profile".to_string(),
            server: "https://vpn.example.com".to_string(),
            username: "alice".to_string(),
            totp_secret: Some("GEZDGNBVGY3TQOJQ".to_string()),
            server_cert: Some("pin-sha256:abc123=".to_string()),
            ..Default::default()
        };

        add_profile(&dir, profile).unwrap();
        let loaded = load_profiles(&dir).unwrap();
        assert_eq!(loaded[0].totp_secret.as_deref(), Some("GEZDGNBVGY3TQOJQ"));
        assert_eq!(loaded[0].server_cert.as_deref(), Some("pin-sha256:abc123="));

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Stress tests ──────────────────────────────────────────────────────

    #[test]
    fn stress_large_profile_set() {
        let dir = std::env::temp_dir().join("oc_test_stress_large");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Add 100 profiles
        for i in 0..100 {
            let profile = make_profile(&format!("id-{}", i), &format!("VPN {}", i));
            add_profile(&dir, profile).unwrap();
        }

        let loaded = load_profiles(&dir).unwrap();
        assert_eq!(loaded.len(), 100);

        // Verify all are present
        for i in 0..100 {
            assert!(loaded.iter().any(|p| p.id == format!("id-{}", i)));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stress_rapid_add_delete() {
        let dir = std::env::temp_dir().join("oc_test_stress_rapid");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Rapid add/delete cycle
        for i in 0..50 {
            add_profile(&dir, make_profile(&format!("rapid-{}", i), &format!("Rapid {}", i))).unwrap();
        }
        for i in 0..50 {
            delete_profile(&dir, &format!("rapid-{}", i)).unwrap();
        }

        let loaded = load_profiles(&dir).unwrap();
        assert!(loaded.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    // Profile mutations are always serialized through the single-threaded Tauri
    // command layer, so `config` intentionally does not lock across threads.
    // This test exercises the write/rename path under sustained sequential load.
    #[test]
    fn stress_sequential_file_writes() {
        let dir = std::env::temp_dir().join("oc_test_stress_sequential");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        for i in 0..100 {
            let profile = make_profile(&format!("item-{}", i), &format!("Profile {}", i));
            add_profile(&dir, profile).unwrap();
        }

        let loaded = load_profiles(&dir).unwrap();
        assert_eq!(loaded.len(), 100);

        let leftover_tmp = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover_tmp);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_idempotent() {
        let dir = std::env::temp_dir().join("oc_test_delete_idempotent");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        add_profile(&dir, make_profile("id1", "Test")).unwrap();
        delete_profile(&dir, "id1").unwrap();

        // Second delete should return error (not panic)
        let result = delete_profile(&dir, "id1");
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
