//! Windows Credential Manager integration.
//!
//! This module stores, retrieves, and deletes VPN passwords using the
//! Windows Credential Manager API (`advapi32.dll`).  It is the **only**
//! module in this crate that is allowed to contain `unsafe` code; all
//! other modules inherit the crate-level `#![deny(unsafe_code)]`.
//!
//! Credential target keys follow the format `openconnect-gui/<profile-id>`.

#![allow(unsafe_code)]

use crate::types::AppError;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{GetLastError, TRUE};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_ENTERPRISE,
    CRED_TYPE_GENERIC,
};

/// Convert a UTF-8 `&str` to a null-terminated UTF-16 `Vec<u16>`.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

/// Store `password` for `username` under `target` in Windows Credential Manager.
///
/// The credential is stored as `CRED_TYPE_GENERIC` with
/// `CRED_PERSIST_ENTERPRISE` persistence, which ties the secret to the
/// current user's logon (DPAPI user key) so that other local users and
/// unrelated processes cannot read it.  The password is saved as raw
/// UTF-8 bytes in the `CredentialBlob` field.
///
/// # Errors
///
/// Returns [`AppError::CredentialError`] with the Win32 error code on failure.
pub fn store_credential(
    target: &str,
    username: &str,
    password: &str,
) -> Result<(), AppError> {
    let target_wide = to_wide(target);
    let username_wide = to_wide(username);
    let password_bytes = password.as_bytes();
    let blob_size: u32 = password_bytes
        .len()
        .try_into()
        .unwrap_or(u32::MAX);

    // SAFETY: We construct the CREDENTIALW in place, ensuring all pointer
    // fields are either null or point to valid data that lives at least as
    // long as the CredWriteW call.
    let result = unsafe {
        #[allow(clippy::cast_ptr_alignment)]
        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target_wide.as_ptr() as *mut u16,
            Comment: std::ptr::null_mut(),
            LastWritten: std::mem::zeroed(),
            CredentialBlobSize: blob_size,
            CredentialBlob: password_bytes.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_ENTERPRISE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: username_wide.as_ptr() as *mut u16,
        };
        CredWriteW(&cred, 0)
    };

    if result == TRUE {
        Ok(())
    } else {
        let code = unsafe { GetLastError() };
        Err(AppError::CredentialError(code))
    }
}

/// Retrieve the stored password for `target` from Windows Credential Manager.
///
/// The password blob is interpreted as UTF-8 bytes (the format used by
/// [`store_credential`]).  Memory allocated by the OS is freed via
/// `CredFree` before this function returns.
///
/// # Errors
///
/// Returns [`AppError::CredentialError`] with the Win32 error code when the
/// credential is not found or any other OS-level error occurs.
pub fn read_credential(target: &str) -> Result<String, AppError> {
    let target_wide = to_wide(target);
    let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();

    // SAFETY: CredReadW writes a pointer to a CREDENTIALW into cred_ptr.
    // On success, cred_ptr is guaranteed non-null by the Win32 contract.
    let result = unsafe {
        CredReadW(
            target_wide.as_ptr(),
            CRED_TYPE_GENERIC,
            0,
            &mut cred_ptr,
        )
    };

    if result != TRUE {
        let code = unsafe { GetLastError() };
        return Err(AppError::CredentialError(code));
    }

    // SAFETY: CredReadW succeeded, so cred_ptr is non-null and points to a
    // valid CREDENTIALW allocated by the OS.  We copy the blob data out
    // before calling CredFree to release the allocation.
    let password = unsafe {
        let cred = &*cred_ptr;
        let blob_size = cred.CredentialBlobSize as usize;
        let blob_ptr = cred.CredentialBlob;

        let password = if blob_size == 0 || blob_ptr.is_null() {
            Ok(String::new())
        } else {
            let bytes = std::slice::from_raw_parts(blob_ptr, blob_size);
            // Strict UTF-8: the blob was written by store_credential as raw
            // UTF-8, so any decode failure indicates corruption or a foreign
            // writer. Returning an error avoids silently substituting U+FFFD
            // replacement characters into a password.
            std::str::from_utf8(bytes).map(|s| s.to_owned())
        };

        CredFree(cred_ptr as *const c_void);
        password
    };

    // Map a decode failure onto the credential error space (ERROR_INVALID_DATA
    // = 13) so callers see a consistent AppError::CredentialError.
    password.map_err(|_| AppError::CredentialError(13))
}

/// Delete the credential for `target` from Windows Credential Manager.
///
/// # Errors
///
/// Returns [`AppError::CredentialError`] with the Win32 error code on
/// failure, including when the credential does not exist.
pub fn delete_credential(target: &str) -> Result<(), AppError> {
    let target_wide = to_wide(target);

    // SAFETY: target_wide is a valid null-terminated UTF-16 buffer.
    let result = unsafe { CredDeleteW(target_wide.as_ptr(), CRED_TYPE_GENERIC, 0) };

    if result == TRUE {
        Ok(())
    } else {
        let code = unsafe { GetLastError() };
        Err(AppError::CredentialError(code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The tests exercise the *real* Windows Credential Manager, a single shared
    // OS-wide store. Running them in parallel makes concurrent store/read/delete
    // calls race (a store may not yet be visible to a delete on another thread),
    // producing spurious ERROR_NOT_FOUND (1168). Serialize every test that
    // touches the store behind this mutex so they are deterministic.
    static STORE_LOCK: Mutex<()> = Mutex::new(());

    /// Round-trip: store a credential and read it back.
    #[test]
    fn store_and_read_roundtrip() {
        let _guard = STORE_LOCK.lock().unwrap();
        let target = "openconnect-gui/test-roundtrip-4321";
        let username = "testuser";
        let password = "s3cr3t!";

        store_credential(target, username, password).expect("store failed");
        let retrieved = read_credential(target).expect("read failed");
        // Clean up before asserting so the entry doesn't linger on failure.
        let _ = delete_credential(target);
        assert_eq!(retrieved, password);
    }

    /// Deleting a non-existent credential should return an error.
    #[test]
    fn delete_nonexistent_returns_error() {
        let _guard = STORE_LOCK.lock().unwrap();
        let result = delete_credential("openconnect-gui/does-not-exist-xyz-9999");
        assert!(result.is_err());
    }

    /// Reading a non-existent credential should return an error.
    #[test]
    fn read_nonexistent_returns_error() {
        let _guard = STORE_LOCK.lock().unwrap();
        let result = read_credential("openconnect-gui/does-not-exist-xyz-9998");
        assert!(result.is_err());
    }

    /// Empty password is stored and retrieved correctly.
    #[test]
    fn store_and_read_empty_password() {
        let _guard = STORE_LOCK.lock().unwrap();
        let target = "openconnect-gui/test-empty-pwd-5678";
        store_credential(target, "user", "").expect("store failed");
        let retrieved = read_credential(target).expect("read failed");
        let _ = delete_credential(target);
        assert_eq!(retrieved, "");
    }

    /// Unicode password round-trip.
    #[test]
    fn store_and_read_unicode_password() {
        let _guard = STORE_LOCK.lock().unwrap();
        let target = "openconnect-gui/test-unicode-1234";
        let password = "pässwörд🔑";
        store_credential(target, "unicode_user", password).expect("store failed");
        let retrieved = read_credential(target).expect("read failed");
        let _ = delete_credential(target);
        assert_eq!(retrieved, password);
    }

    /// Large password round-trip. Windows caps a credential blob at
    /// CRED_MAX_CREDENTIAL_BLOB_SIZE (2560 bytes), so we use a large but
    /// valid password that stays within that limit as UTF-16.
    #[test]
    fn store_and_read_large_password() {
        let _guard = STORE_LOCK.lock().unwrap();
        let target = "openconnect-gui/test-large-5678";
        let password = "a".repeat(1024);
        store_credential(target, "large_user", &password).expect("store failed");
        let retrieved = read_credential(target).expect("read failed");
        let _ = delete_credential(target);
        assert_eq!(retrieved, password);
    }

    /// Password with special characters round-trip.
    #[test]
    fn store_and_read_special_chars_password() {
        let _guard = STORE_LOCK.lock().unwrap();
        let target = "openconnect-gui/test-special-9012";
        let password = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
        store_credential(target, "special_user", password).expect("store failed");
        let retrieved = read_credential(target).expect("read failed");
        let _ = delete_credential(target);
        assert_eq!(retrieved, password);
    }

    /// Delete is idempotent — second delete returns error, not panic.
    #[test]
    fn delete_idempotent() {
        let _guard = STORE_LOCK.lock().unwrap();
        let target = "openconnect-gui/test-idempotent-3456";
        store_credential(target, "user", "pass").expect("store failed");
        delete_credential(target).expect("first delete failed");
        // Second delete should error (not panic)
        let result = delete_credential(target);
        assert!(result.is_err());
    }

    /// Overwrite existing credential.
    #[test]
    fn store_overwrites_existing() {
        let _guard = STORE_LOCK.lock().unwrap();
        let target = "openconnect-gui/test-overwrite-7890";
        store_credential(target, "user", "old_pass").expect("store failed");
        store_credential(target, "user", "new_pass").expect("overwrite failed");
        let retrieved = read_credential(target).expect("read failed");
        let _ = delete_credential(target);
        assert_eq!(retrieved, "new_pass");
    }

    /// to_wide produces null-terminated UTF-16.
    #[test]
    fn to_wide_produces_null_terminated() {
        let wide = to_wide("abc");
        assert_eq!(wide, vec![0x0061, 0x0062, 0x0063, 0x0000]);
    }

    /// to_wide handles empty string.
    #[test]
    fn to_wide_empty_string() {
        let wide = to_wide("");
        assert_eq!(wide, vec![0x0000]);
    }

    /// to_wide handles unicode.
    #[test]
    fn to_wide_handles_unicode() {
        let wide = to_wide("日本語");
        assert!(wide.len() > 1);
        assert_eq!(*wide.last().unwrap(), 0x0000); // null-terminated
    }
}
