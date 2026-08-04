//! Tauri command surface and TOTP generation helpers.
//!
//! Exposes Tauri `#[command]` functions for profile management, credential
//! storage, and TOTP generation.

use totp_rs::{Algorithm, Secret, TOTP};

use crate::config;
use crate::credentials;
use crate::types::{AppError, ConnectionProfile};
use tauri::AppHandle;
use tauri::Manager;

// ── Input validation ────────────────────────────────────────────────────────

const MAX_NAME_LEN: usize = 128;
const MAX_SERVER_LEN: usize = 2048;
const MAX_USERNAME_LEN: usize = 256;
const MAX_MFA_CODE_LEN: usize = 10;

/// Validate a profile before persisting.
pub fn validate_profile(profile: &ConnectionProfile) -> Result<(), String> {
    if !is_valid_uuid(&profile.id) {
        return Err("Invalid profile ID: must be a UUID".to_string());
    }
    if profile.name.is_empty() || profile.name.len() > MAX_NAME_LEN {
        return Err(format!("Name must be 1-{} characters", MAX_NAME_LEN));
    }
    if profile.name.chars().any(|c| c.is_control()) {
        return Err("Name must not contain control characters".to_string());
    }
    if profile.server.is_empty() || profile.server.len() > MAX_SERVER_LEN {
        return Err(format!("Server URL must be 1-{} characters", MAX_SERVER_LEN));
    }
    if !profile.server.starts_with("https://") && !profile.server.starts_with("http://") {
        return Err("Server URL must start with https:// or http://".to_string());
    }
    if profile.server.chars().any(|c| c == '\n' || c == '\r' || c == '\0') {
        return Err("Server URL must not contain newlines or null bytes".to_string());
    }
    // Defence-in-depth: a URL never legitimately contains whitespace. Rejecting
    // it removes any ambiguity about how the value is tokenised downstream.
    if profile.server.chars().any(|c| c.is_whitespace()) {
        return Err("Server URL must not contain whitespace".to_string());
    }
    {
        // Require a non-empty host and reject embedded credentials
        // (user:pass@host) so secrets never end up on the command line or logs.
        let after_scheme = profile
            .server
            .strip_prefix("https://")
            .or_else(|| profile.server.strip_prefix("http://"))
            .unwrap_or("");
        let authority = after_scheme.split('/').next().unwrap_or("");
        if authority.is_empty() {
            return Err("Server URL must include a host".to_string());
        }
        if authority.contains('@') {
            return Err("Server URL must not embed credentials (user:pass@host)".to_string());
        }
    }
    if profile.username.is_empty() || profile.username.len() > MAX_USERNAME_LEN {
        return Err(format!("Username must be 1-{} characters", MAX_USERNAME_LEN));
    }
    if profile.username.chars().any(|c| c.is_control()) {
        return Err("Username must not contain control characters".to_string());
    }
    if let Some(ref secret) = profile.totp_secret {
        if secret.is_empty() {
            return Err("TOTP secret must not be empty".to_string());
        }
        if !secret
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c) || c == '=')
        {
            return Err("TOTP secret must be valid base32 (A-Z, 2-7, =)".to_string());
        }
    }
    if let Some(ref cert) = profile.server_cert {
        if !cert.starts_with("pin-sha256:") {
            return Err("Server certificate must start with pin-sha256:".to_string());
        }
        let pin_data = &cert["pin-sha256:".len()..];
        if pin_data.is_empty()
            || !pin_data
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            return Err("Server certificate contains invalid characters".to_string());
        }
    }
    validate_openconnect_options(profile)?;
    Ok(())
}

/// Protocols supported by the bundled openconnect v9.21 (`--protocol`).
const VALID_PROTOCOLS: &[&str] =
    &["anyconnect", "nc", "gp", "pulse", "f5", "fortinet", "array"];
/// Native software-token modes (`--token-mode`).
const VALID_TOKEN_MODES: &[&str] = &["rsa", "totp", "hotp", "oidc"];
/// OS values accepted by `--os`.
const VALID_OS_VALUES: &[&str] =
    &["linux", "linux-64", "win", "mac-intel", "android", "apple-ios"];

/// Maximum length for free-form option strings (paths, header values, etc.).
const MAX_OPTION_LEN: usize = 4096;

/// Reject a value that contains characters unsafe to pass as a CLI argument or
/// enforce a length bound. `None` values pass. Empty strings are rejected so a
/// user cannot save a blank option that would emit a dangling flag.
fn check_opt_str(value: Option<&String>, label: &str) -> Result<(), String> {
    if let Some(v) = value {
        if v.is_empty() {
            return Err(format!("{label} must not be empty when set"));
        }
        if v.len() > MAX_OPTION_LEN {
            return Err(format!("{label} must be at most {MAX_OPTION_LEN} characters"));
        }
        if v.chars().any(|c| c.is_control()) {
            return Err(format!("{label} must not contain control characters"));
        }
    }
    Ok(())
}

/// Validate all curated OpenConnect option fields on a profile.
fn validate_openconnect_options(profile: &ConnectionProfile) -> Result<(), String> {
    if let Some(ref p) = profile.protocol {
        if !VALID_PROTOCOLS.contains(&p.as_str()) {
            return Err(format!(
                "Protocol must be one of: {}",
                VALID_PROTOCOLS.join(", ")
            ));
        }
    }
    if let Some(ref m) = profile.token_mode {
        if !VALID_TOKEN_MODES.contains(&m.as_str()) {
            return Err(format!(
                "Token mode must be one of: {}",
                VALID_TOKEN_MODES.join(", ")
            ));
        }
    }
    if let Some(ref o) = profile.os_override {
        if !VALID_OS_VALUES.contains(&o.as_str()) {
            return Err(format!(
                "OS override must be one of: {}",
                VALID_OS_VALUES.join(", ")
            ));
        }
    }

    // Free-form string options: reject control chars / empties / over-length.
    check_opt_str(profile.authgroup.as_ref(), "Auth group")?;
    check_opt_str(profile.usergroup.as_ref(), "User group")?;
    check_opt_str(profile.certificate.as_ref(), "Certificate path")?;
    check_opt_str(profile.sslkey.as_ref(), "SSL key path")?;
    check_opt_str(profile.mca_certificate.as_ref(), "MCA certificate path")?;
    check_opt_str(profile.mca_key.as_ref(), "MCA key path")?;
    check_opt_str(profile.external_browser.as_ref(), "External browser")?;
    check_opt_str(profile.proxy.as_ref(), "Proxy URL")?;
    check_opt_str(profile.proxy_auth.as_ref(), "Proxy auth methods")?;
    check_opt_str(profile.cafile.as_ref(), "CA file path")?;
    check_opt_str(profile.dtls_ciphers.as_ref(), "DTLS ciphers")?;
    check_opt_str(profile.useragent.as_ref(), "User agent")?;
    check_opt_str(profile.version_string.as_ref(), "Version string")?;
    check_opt_str(profile.local_hostname.as_ref(), "Local hostname")?;
    check_opt_str(profile.token_secret.as_ref(), "Token secret")?;
    check_opt_str(profile.key_password.as_ref(), "Key password")?;
    check_opt_str(profile.mca_key_password.as_ref(), "MCA key password")?;

    // `--resolve=HOST:IP` must contain a colon separating host and IP.
    if let Some(ref r) = profile.resolve {
        check_opt_str(Some(r), "Resolve")?;
        if !r.contains(':') {
            return Err("Resolve must be in HOST:IP form".to_string());
        }
    }
    if let Some(ref s) = profile.sni {
        check_opt_str(Some(s), "SNI")?;
        if s.contains('/') || s.contains(' ') {
            return Err("SNI must be a bare hostname".to_string());
        }
    }

    // Numeric ranges.
    if let Some(mtu) = profile.base_mtu {
        if !(576..=9000).contains(&mtu) {
            return Err("Base MTU must be between 576 and 9000".to_string());
        }
    }
    if let Some(dpd) = profile.force_dpd {
        if dpd == 0 || dpd > 3600 {
            return Err("Force DPD interval must be between 1 and 3600 seconds".to_string());
        }
    }
    if let Some(q) = profile.queue_len {
        if q == 0 || q > 65535 {
            return Err("Queue length must be between 1 and 65535".to_string());
        }
    }
    // dtls_local_port: u16, any value 1..=65535 is fine; 0 means "unset" but the
    // field is Option so None already means unset. Reject explicit 0.
    if profile.dtls_local_port == Some(0) {
        return Err("DTLS local port must be between 1 and 65535".to_string());
    }

    // country_code: ISO 3166-1 alpha-2 (two ASCII letters) if present.
    if let Some(ref cc) = profile.country_code {
        if cc.len() != 2 || !cc.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err("Country code must be two letters (ISO 3166-1 alpha-2)".to_string());
        }
    }

    Ok(())
}

/// Validate an MFA code (must be 1-10 digits).
pub fn validate_mfa_code(code: &str) -> Result<(), String> {
    if code.is_empty() || code.len() > MAX_MFA_CODE_LEN {
        return Err(format!("MFA code must be 1-{} digits", MAX_MFA_CODE_LEN));
    }
    if !code.chars().all(|c| c.is_ascii_digit()) {
        return Err("MFA code must contain only digits".to_string());
    }
    Ok(())
}

/// Check if a string is a valid UUID format.
fn is_valid_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    if parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
    {
        return false;
    }
    parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Sanitize an error message for user display — strip internal paths, hostnames,
/// and OS codes so no sensitive infrastructure detail leaks to the frontend.
pub fn sanitize_error(err: &str) -> String {
    if err.is_empty() {
        String::new()
    } else if err.contains("Credential error") {
        "A credential store error occurred".to_string()
    } else if err.contains("I/O error") {
        "A file system error occurred".to_string()
    } else if err.contains("failed to spawn") {
        "Failed to start VPN connection".to_string()
    } else if err.contains("profile not found") {
        "Profile not found".to_string()
    } else {
        // Strip anything that looks like a hostname/URL or filesystem path, plus
        // trailing OS codes, so no server name or local path (which may embed a
        // username) ever leaks to the frontend.
        let cleaned = err
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>();
        // Drop whole tokens that look like a path (contain a separator or a
        // drive-letter colon) BEFORE splitting them apart, so path components
        // such as user names are removed rather than exposed as bare words.
        let cleaned = cleaned
            .split_whitespace()
            .filter(|tok| !(tok.contains('\\') || tok.contains('/') || tok.contains(':')))
            // Remove tokens that resemble hostnames (contain a dot) unless the
            // token is a bare IP literal.
            .filter(|tok| !tok.contains('.') || tok.trim_end_matches('.').parse::<std::net::IpAddr>().is_ok())
            .collect::<Vec<_>>()
            .join(" ");
        if cleaned.trim().is_empty() {
            "An error occurred".to_string()
        } else {
            cleaned.trim().to_string()
        }
    }
}

/// Resolve the absolute path to the bundled `openconnect.exe`.
///
/// Resolution is anchored **only** to the running executable's own directory
/// (`current_exe()`), which for an installed app lives in an admin-writable
/// location (e.g. `Program Files`). This deliberately does NOT fall back to a
/// current-working-directory-relative path: because the app runs elevated, a
/// CWD-relative engine path would let a non-privileged user plant a malicious
/// `openconnect.exe` in a directory they control and have it executed as
/// administrator (local privilege escalation). If the engine cannot be located
/// under an app-owned directory, resolution fails loudly instead.
fn resolve_openconnect_exe() -> std::path::PathBuf {
    // The executable location is fixed for the life of the process, so resolve
    // it once and cache the result instead of touching the filesystem
    // (`current_exe` + `exists`) on every connect.
    static CACHE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    CACHE.get_or_init(resolve_openconnect_exe_uncached).clone()
}

fn resolve_openconnect_exe_uncached() -> std::path::PathBuf {
    let rel: &[&str] = &[".toolchain", "openconnect", "openconnect.exe"];
    resolve_app_owned_path(rel)
        // Absolute, app-owned dirs exhausted. Fall back to a path under the exe
        // directory (still absolute + app-owned) so the error surfaced later
        // ("engine not found") is actionable, never a CWD-relative path.
        .unwrap_or_else(|| app_dir_join(rel))
}

/// Directory of the running executable (absolute), or `.` only if it truly
/// cannot be determined (should never happen on Windows).
fn exe_dir() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Join `rel` onto the executable directory (release layout).
fn app_dir_join(rel: &[&str]) -> std::path::PathBuf {
    let mut p = exe_dir();
    for c in rel {
        p.push(c);
    }
    p
}

/// Try to locate `rel` under an app-owned, absolute base directory.
///
/// Checks the release layout (next to the exe) and the dev layout (three levels
/// up from `target/<profile>/` to the project root). Only returns paths that
/// actually exist AND are absolute, so a relative/CWD path can never be used to
/// spawn an elevated child. Returns `None` if not found.
fn resolve_app_owned_path(rel: &[&str]) -> Option<std::path::PathBuf> {
    let base = exe_dir();
    // release layout: <exe_dir>/<rel>
    let release = {
        let mut p = base.clone();
        for c in rel {
            p.push(c);
        }
        p
    };
    if release.is_absolute() && release.exists() {
        return Some(release);
    }
    // dev layout: <exe_dir>/../../../<rel>  (target/<profile>/ -> project root)
    let dev = {
        let mut p = base.join("..").join("..").join("..");
        for c in rel {
            p.push(c);
        }
        // Canonicalize so the `..` segments collapse to a real absolute path
        // and any symlink trickery is resolved.
        std::fs::canonicalize(&p).unwrap_or(p)
    };
    if dev.is_absolute() && dev.exists() {
        return Some(dev);
    }
    None
}

/// Resolve the absolute path to the bundled `vpnc-script-win.js`.
///
/// This script applies the DNS servers and routing table changes that make the
/// tunnel actually carry traffic. openconnect ships a compiled-in default path,
/// but on this Windows build that default is malformed (it mixes `\` and
/// `/usr/share/...` separators), so it may silently fail to run — which would
/// leave DNS and routes pointed at the physical interface (**DNS / IP leak**).
///
/// We therefore always resolve and pass an explicit, correct absolute path via
/// `--script`. Returns `None` only if the script cannot be located, in which
/// case openconnect falls back to its (possibly broken) default.
fn resolve_vpnc_script() -> Option<std::path::PathBuf> {
    // Cached for the same reason as `resolve_openconnect_exe`: the script path
    // is stable for the process lifetime, so avoid re-probing the filesystem on
    // every connect.
    static CACHE: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    CACHE.get_or_init(resolve_vpnc_script_uncached).clone()
}

fn resolve_vpnc_script_uncached() -> Option<std::path::PathBuf> {
    // Anchored to app-owned absolute directories only (never CWD-relative), for
    // the same privilege-escalation reason as `resolve_openconnect_exe`: the
    // elevated openconnect executes this script, so a user-plantable path would
    // be an admin-code-execution vector.
    resolve_app_owned_path(&[
        ".toolchain",
        "openconnect",
        "usr",
        "share",
        "vpnc-scripts",
        "vpnc-script-win.js",
    ])
}

/// Build the openconnect command-line arguments for a profile.
///
/// Security policy (trust-on-first-use with explicit consent):
///
/// * **`--non-inter`** is always passed so openconnect never blocks on an
///   interactive prompt (which cannot be answered when driving it via stdin).
/// * If the profile has a pinned `server_cert`, **`--servercert <pin>`** is
///   passed — the connection is fully certificate-validated.
/// * If no cert is pinned, **certificate verification is NOT disabled**.
///   openconnect will reject the untrusted certificate and print its
///   `--servercert pin-sha256:...` fingerprint hint, which the parser captures
///   and forwards to the frontend as a `server-cert` event so the user can
///   review and pin it. `--no-cert-check` is deliberately never used.
///
/// Reliability / performance policy:
///
/// * **`--script <abs path>`** — an explicit, correct vpnc-script path is
///   always passed when the script can be located, so DNS servers and routes
///   are actually applied. Without this, traffic and DNS can leak.
/// * **`--os win`** — report the correct OS to the server.
/// * **`--reconnect-timeout 60`** — keep retrying a dropped transport for 60s
///   (down from openconnect's 300s default) so brief network blips self-heal
///   quickly instead of hanging.
/// * DTLS/ESP is left **enabled** (the fast UDP data path); `--no-dtls` is
///   never passed. No MTU is hardcoded, since a wrong MTU hurts throughput.
///
pub fn build_openconnect_args(profile: &ConnectionProfile) -> Vec<String> {
    let mut args = vec![
        "--user".to_string(),
        profile.username.clone(),
        "--passwd-on-stdin".to_string(),
        "--non-inter".to_string(),
    ];

    // Protocol selection (defaults to anyconnect when unset).
    if let Some(ref proto) = profile.protocol {
        if !proto.is_empty() {
            args.push(format!("--protocol={proto}"));
        }
    }

    // Reliability + performance flags (leak fix + fast, self-healing tunnel).
    if let Some(script) = resolve_vpnc_script() {
        args.push("--script".to_string());
        args.push(script.to_string_lossy().into_owned());
    }
    // OS to report: wrapper default is `win`, overridable per profile.
    args.push("--os".to_string());
    args.push(
        profile
            .os_override
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "win".to_string()),
    );
    // Heal transport blips *inside* the existing session (no re-auth/MFA) for up
    // to 60s before the process exits and the app has to do a full reconnect.
    args.push("--reconnect-timeout".to_string());
    args.push("60".to_string());
    // Dead-peer detection / keepalive. Default 30s, overridable via --force-dpd.
    // openconnect only exposes --force-dpd (there is no --dpd option); it forces
    // the DPD timer even if the server did not advertise one.
    let dpd = profile.force_dpd.unwrap_or(30);
    args.push("--force-dpd".to_string());
    args.push(dpd.to_string());

    // ── Authentication options ──────────────────────────────────────────────
    if let Some(ref g) = profile.authgroup {
        args.push(format!("--authgroup={g}"));
    }
    if let Some(ref g) = profile.usergroup {
        args.push("--usergroup".to_string());
        args.push(g.clone());
    }
    if let Some(ref c) = profile.certificate {
        args.push("--certificate".to_string());
        args.push(c.clone());
    }
    if let Some(ref k) = profile.sslkey {
        args.push("--sslkey".to_string());
        args.push(k.clone());
    }
    if let Some(ref kp) = profile.key_password {
        if !kp.is_empty() {
            args.push("--key-password".to_string());
            args.push(kp.clone());
        }
    }
    if let Some(ref c) = profile.mca_certificate {
        args.push("--mca-certificate".to_string());
        args.push(c.clone());
    }
    if let Some(ref k) = profile.mca_key {
        args.push("--mca-key".to_string());
        args.push(k.clone());
    }
    if let Some(ref kp) = profile.mca_key_password {
        if !kp.is_empty() {
            args.push("--mca-key-password".to_string());
            args.push(kp.clone());
        }
    }
    if let Some(ref m) = profile.token_mode {
        args.push(format!("--token-mode={m}"));
        if let Some(ref s) = profile.token_secret {
            if !s.is_empty() {
                args.push("--token-secret".to_string());
                args.push(s.clone());
            }
        }
    }
    if let Some(ref b) = profile.external_browser {
        args.push("--external-browser".to_string());
        args.push(b.clone());
    }
    if profile.no_external_auth {
        args.push("--no-external-auth".to_string());
    }

    // ── Server validation / TLS ─────────────────────────────────────────────
    if let Some(ref cafile) = profile.cafile {
        args.push("--cafile".to_string());
        args.push(cafile.clone());
    }
    if profile.no_system_trust {
        args.push("--no-system-trust".to_string());
    }
    if profile.allow_insecure_crypto {
        args.push("--allow-insecure-crypto".to_string());
    }
    if let Some(ref ciphers) = profile.dtls_ciphers {
        args.push("--dtls-ciphers".to_string());
        args.push(ciphers.clone());
    }

    // ── Connectivity / proxy ────────────────────────────────────────────────
    if profile.no_proxy {
        args.push("--no-proxy".to_string());
    } else if let Some(ref p) = profile.proxy {
        args.push("--proxy".to_string());
        args.push(p.clone());
        if let Some(ref pa) = profile.proxy_auth {
            args.push("--proxy-auth".to_string());
            args.push(pa.clone());
        }
    }
    if let Some(ref r) = profile.resolve {
        args.push("--resolve".to_string());
        args.push(r.clone());
    }
    if let Some(ref s) = profile.sni {
        args.push("--sni".to_string());
        args.push(s.clone());
    }

    // ── Tunnel / transport tuning ───────────────────────────────────────────
    if let Some(mtu) = profile.base_mtu {
        args.push("--base-mtu".to_string());
        args.push(mtu.to_string());
    }
    if profile.no_dtls {
        args.push("--no-dtls".to_string());
    }
    if profile.pfs {
        args.push("--pfs".to_string());
    }
    if let Some(port) = profile.dtls_local_port {
        args.push("--dtls-local-port".to_string());
        args.push(port.to_string());
    }
    if profile.passtos {
        args.push("--passtos".to_string());
    }
    if let Some(q) = profile.queue_len {
        args.push("--queue-len".to_string());
        args.push(q.to_string());
    }
    if profile.disable_ipv6 {
        args.push("--disable-ipv6".to_string());
    }
    if profile.deflate {
        args.push("--deflate".to_string());
    }

    // ── Local system identity ───────────────────────────────────────────────
    if let Some(ref ua) = profile.useragent {
        args.push("--useragent".to_string());
        args.push(ua.clone());
    }
    if let Some(ref vs) = profile.version_string {
        args.push("--version-string".to_string());
        args.push(vs.clone());
    }
    if let Some(ref lh) = profile.local_hostname {
        args.push("--local-hostname".to_string());
        args.push(lh.clone());
    }

    if let Some(ref cert) = profile.server_cert {
        args.push("--servercert".to_string());
        args.push(cert.clone());
    }
    args.push(profile.server.clone());
    args
}

/// Generate a 6-digit TOTP code from a base32-encoded secret.
///
/// Decodes the RFC 4648 base32 `secret_b32` string into raw bytes, constructs
/// a standard SHA-1/6-digit/30-second TOTP instance, and returns the current
/// time-step token as a zero-padded decimal string.
///
/// # Errors
///
/// Returns [`AppError::TotpError`] if the secret cannot be decoded from base32
/// or if the current system time cannot be read.
pub fn generate_totp(secret_b32: &str) -> Result<String, AppError> {
    // Decode the base32 secret into raw bytes.
    let secret_bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| AppError::TotpError(e.to_string()))?;

    // Build a standard RFC-6238 TOTP (SHA-1, 6 digits, 1-step skew, 30-second period).
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
        .map_err(|e| AppError::TotpError(e.to_string()))?;

    // Generate the token for the current system time.
    totp.generate_current()
        .map_err(|e| AppError::TotpError(e.to_string()))
}

/// List all saved VPN profiles from the app data directory.
///
/// Reads `<app_data_dir>/profiles.json` and returns its contents.  If the
/// file does not yet exist (first launch), an empty list is returned.
///
/// # Errors
///
/// Returns a string-encoded [`AppError`] if the app data directory cannot be
/// resolved or if the profiles file exists but cannot be read or parsed.
#[tauri::command]
pub fn list_profiles(app: AppHandle) -> Result<Vec<ConnectionProfile>, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    config::load_profiles(&dir).map_err(|e: AppError| e.to_string())
}

/// Add a new VPN profile and persist it to the app data directory.
///
/// The profile is appended to the existing list.  Callers are responsible for
/// supplying a unique `profile.id` (e.g. a UUID v4).
///
/// # Errors
///
/// Returns a string-encoded [`AppError`] if the app data directory cannot be
/// resolved or if the profiles file cannot be written.
#[tauri::command]
pub fn add_profile(app: AppHandle, mut profile: ConnectionProfile) -> Result<(), String> {
    validate_profile(&profile)?;
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    persist_profile_secrets(&mut profile)?;
    config::add_profile(&dir, profile).map_err(|e: AppError| e.to_string())
}

/// The credential-manager sub-key suffixes for every input-only secret field
/// that is moved out of `profiles.json`. Kept in one place so `delete_profile`
/// and `connect` stay in sync with `persist_profile_secrets`.
const SECRET_SUFFIXES: &[&str] = &["totp", "token-secret", "key-password", "mca-key-password"];

/// Credential Manager target key for a profile's TOTP secret.
fn totp_target(profile_id: &str) -> String {
    secret_target(profile_id, "totp")
}

/// Credential Manager target key for a named profile secret, e.g.
/// `openconnect-gui/<id>/token-secret`.
fn secret_target(profile_id: &str, suffix: &str) -> String {
    format!("openconnect-gui/{}/{}", profile_id, suffix)
}

/// Store one secret in Credential Manager, or delete the stale entry when unset.
/// The in-memory `slot` is taken (zeroized after write) so it is never persisted.
fn persist_one_secret(
    profile_id: &str,
    suffix: &str,
    slot: &mut Option<String>,
) -> Result<(), String> {
    let target = secret_target(profile_id, suffix);
    match slot.take() {
        Some(mut secret) if !secret.is_empty() => {
            let res = credentials::store_credential(&target, suffix, &secret)
                .map_err(|e: AppError| e.to_string());
            zeroize::Zeroize::zeroize(&mut secret);
            res
        }
        _ => {
            let _ = credentials::delete_credential(&target);
            Ok(())
        }
    }
}

/// Move every input-only secret field (TOTP seed, native token secret, SSL key
/// password, MCA key password) into Windows Credential Manager and clear them
/// from the in-memory profile so none are ever written to `profiles.json`.
fn persist_profile_secrets(profile: &mut ConnectionProfile) -> Result<(), String> {
    let id = profile.id.clone();
    persist_one_secret(&id, "totp", &mut profile.totp_secret)?;
    persist_one_secret(&id, "token-secret", &mut profile.token_secret)?;
    persist_one_secret(&id, "key-password", &mut profile.key_password)?;
    persist_one_secret(&id, "mca-key-password", &mut profile.mca_key_password)?;
    Ok(())
}

/// Update an existing VPN profile matched by `profile.id`.
///
/// The matching entry is replaced in place and the list is persisted.
///
/// # Errors
///
/// Returns a string-encoded [`AppError`] if the app data directory cannot be
/// resolved, if no profile with the given `id` exists, or if the file cannot
/// be written.
#[tauri::command]
pub fn update_profile(app: AppHandle, mut profile: ConnectionProfile) -> Result<(), String> {
    validate_profile(&profile)?;
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    persist_profile_secrets(&mut profile)?;
    config::update_profile(&dir, profile).map_err(|e: AppError| e.to_string())
}

/// Delete a VPN profile and its associated Windows Credential Manager entry.
///
/// The stored credential (if any) is deleted on a best-effort basis — a
/// not-found error from the credential store is silently ignored.  The profile
/// is then removed from `profiles.json`.
///
/// # Errors
///
/// Returns a string-encoded [`AppError`] if the app data directory cannot be
/// resolved, if no profile with the given `id` exists, or if the profiles file
/// cannot be written.
#[tauri::command]
pub fn delete_profile(app: AppHandle, id: String) -> Result<(), String> {
    if !is_valid_uuid(&id) {
        return Err("Invalid profile ID: must be a UUID".to_string());
    }
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let target = format!("openconnect-gui/{}", id);
    // Best-effort credential deletion — ignore not-found errors.
    let _ = credentials::delete_credential(&target);
    // Also remove every separately-stored secret entry for this profile.
    for suffix in SECRET_SUFFIXES {
        let _ = credentials::delete_credential(&secret_target(&id, suffix));
    }
    config::delete_profile(&dir, &id).map_err(|e: AppError| e.to_string())
}

/// Store a password credential for a profile in Windows Credential Manager.
///
/// The credential is keyed as `openconnect-gui/<profile_id>` and can be
/// retrieved later via [`read_credential`](crate::credentials::read_credential).
///
/// # Errors
///
/// Returns a string-encoded [`AppError`] if the Windows Credential Manager
/// write operation fails.
#[tauri::command]
pub fn store_credential(
    profile_id: String,
    username: String,
    mut password: String,
) -> Result<(), String> {
    if !is_valid_uuid(&profile_id) {
        zeroize::Zeroize::zeroize(&mut password);
        return Err("Invalid profile ID: must be a UUID".to_string());
    }
    let target = format!("openconnect-gui/{}", profile_id);
    let result = credentials::store_credential(&target, &username, &password)
        .map_err(|e: AppError| e.to_string());
    zeroize::Zeroize::zeroize(&mut password);
    result
}

/// Detect the ISO 3166-1 alpha-2 country code (lowercase) for a VPN server via
/// GeoIP, so the UI can show the matching country flag as the profile icon.
///
/// The lookup resolves the server host to an IP and queries a GeoIP service.
/// It is best-effort: on any failure (bad host, no network, unknown IP) it
/// returns `Ok(None)` rather than an error, so the UI simply falls back to a
/// generic flag. Runs the blocking network I/O off the async runtime.
///
/// # Errors
///
/// Returns an error string only if the blocking task itself fails to join.
#[tauri::command]
pub async fn detect_country(server: String) -> Result<Option<String>, String> {
    // Bound the length defensively; a server URL is validated elsewhere but this
    // command can be called with in-progress form input.
    if server.len() > MAX_SERVER_LEN {
        return Ok(None);
    }
    tokio::task::spawn_blocking(move || crate::geoip::detect_country(&server))
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 160-bit base32 secret (RFC 6238 appendix test vector: "12345678901234567890" as bytes).
    /// Must be at least 128 bits to satisfy RFC 4226 §4, as enforced by totp-rs 5.x.
    const TEST_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn make_valid_profile() -> ConnectionProfile {
        ConnectionProfile {
            id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            name: "Test VPN".to_string(),
            server: "https://vpn.example.com".to_string(),
            username: "alice".to_string(),
            ..Default::default()
        }
    }

    // ── TOTP tests ───────────────────────────────────────────────────────

    #[test]
    fn generate_totp_returns_six_digits() {
        let code = generate_totp(TEST_SECRET).expect("should generate a TOTP code");
        assert_eq!(code.len(), 6, "TOTP code must be exactly 6 characters");
        assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "TOTP code must consist only of digits"
        );
    }

    #[test]
    fn generate_totp_invalid_secret_returns_error() {
        let result = generate_totp("not-valid-base32!!!");
        assert!(
            result.is_err(),
            "invalid base32 input should return an error"
        );
        if let Err(AppError::TotpError(_)) = result {
            // expected variant
        } else {
            panic!("expected AppError::TotpError");
        }
    }

    #[test]
    fn generate_totp_deterministic_within_step() {
        let code1 = generate_totp(TEST_SECRET).unwrap();
        let code2 = generate_totp(TEST_SECRET).unwrap();
        assert_eq!(code1, code2);
    }

    #[test]
    fn generate_totp_empty_secret_returns_error() {
        let result = generate_totp("");
        assert!(result.is_err());
    }

    // ── validate_profile tests ────────────────────────────────────────────

    #[test]
    fn validate_profile_accepts_valid() {
        assert!(validate_profile(&make_valid_profile()).is_ok());
    }

    #[test]
    fn validate_profile_rejects_empty_id() {
        let mut p = make_valid_profile();
        p.id = "".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_non_uuid_id() {
        let mut p = make_valid_profile();
        p.id = "not-a-uuid".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_short_uuid_segments() {
        let mut p = make_valid_profile();
        p.id = "550e8400-e29b-41d4-a716".to_string(); // too few parts
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_empty_name() {
        let mut p = make_valid_profile();
        p.name = "".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_long_name() {
        let mut p = make_valid_profile();
        p.name = "x".repeat(MAX_NAME_LEN + 1);
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_control_chars_in_name() {
        let mut p = make_valid_profile();
        p.name = "test\x00name".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_empty_server() {
        let mut p = make_valid_profile();
        p.server = "".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_long_server() {
        let mut p = make_valid_profile();
        p.server = format!("https://{}", "a".repeat(MAX_SERVER_LEN));
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_ftp_url() {
        let mut p = make_valid_profile();
        p.server = "ftp://vpn.example.com".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_allows_http_url() {
        // http:// is accepted (some gateways redirect http->https); openconnect
        // itself enforces TLS. The scheme check only rejects non-http(s).
        let mut p = make_valid_profile();
        p.server = "http://vpn.example.com".to_string();
        assert!(validate_profile(&p).is_ok());
    }

    #[test]
    fn validate_profile_rejects_newline_in_server() {
        let mut p = make_valid_profile();
        p.server = "https://vpn.example.com\nmalicious".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_null_in_server() {
        let mut p = make_valid_profile();
        p.server = "https://vpn.example.com\x00bad".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_empty_username() {
        let mut p = make_valid_profile();
        p.username = "".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_long_username() {
        let mut p = make_valid_profile();
        p.username = "x".repeat(MAX_USERNAME_LEN + 1);
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_control_in_username() {
        let mut p = make_valid_profile();
        p.username = "user\x01name".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_invalid_totp_secret() {
        let mut p = make_valid_profile();
        p.totp_secret = Some("not-valid-base32!!!".to_string());
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_empty_totp_secret() {
        let mut p = make_valid_profile();
        p.totp_secret = Some("".to_string());
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_accepts_valid_totp_secret() {
        let mut p = make_valid_profile();
        p.totp_secret = Some("GEZDGNBVGY3TQOJQ".to_string());
        assert!(validate_profile(&p).is_ok());
    }

    // ── OpenConnect option validation ────────────────────────────────────

    #[test]
    fn validate_profile_accepts_known_protocol() {
        for proto in VALID_PROTOCOLS {
            let mut p = make_valid_profile();
            p.protocol = Some((*proto).to_string());
            assert!(validate_profile(&p).is_ok(), "protocol {proto} should be ok");
        }
    }

    #[test]
    fn validate_profile_rejects_unknown_protocol() {
        let mut p = make_valid_profile();
        p.protocol = Some("wireguard".to_string());
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_unknown_token_mode() {
        let mut p = make_valid_profile();
        p.token_mode = Some("magic".to_string());
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_unknown_os_override() {
        let mut p = make_valid_profile();
        p.os_override = Some("solaris".to_string());
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_accepts_win_os_override() {
        let mut p = make_valid_profile();
        p.os_override = Some("win".to_string());
        assert!(validate_profile(&p).is_ok());
    }

    #[test]
    fn validate_profile_rejects_option_with_control_chars() {
        let mut p = make_valid_profile();
        p.authgroup = Some("Emp\nloyees".to_string());
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_empty_option_string() {
        let mut p = make_valid_profile();
        p.proxy = Some(String::new());
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_out_of_range_mtu() {
        let mut p = make_valid_profile();
        p.base_mtu = Some(100);
        assert!(validate_profile(&p).is_err());
        p.base_mtu = Some(1400);
        assert!(validate_profile(&p).is_ok());
    }

    #[test]
    fn validate_profile_rejects_zero_force_dpd() {
        let mut p = make_valid_profile();
        p.force_dpd = Some(0);
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_resolve_without_colon() {
        let mut p = make_valid_profile();
        p.resolve = Some("vpn.example.com".to_string());
        assert!(validate_profile(&p).is_err());
        p.resolve = Some("vpn.example.com:203.0.113.5".to_string());
        assert!(validate_profile(&p).is_ok());
    }

    #[test]
    fn validate_profile_rejects_zero_dtls_local_port() {
        let mut p = make_valid_profile();
        p.dtls_local_port = Some(0);
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_invalid_cert_format() {
        let mut p = make_valid_profile();
        p.server_cert = Some("sha256:abc123".to_string());
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_empty_cert_pin() {
        let mut p = make_valid_profile();
        p.server_cert = Some("pin-sha256:".to_string());
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_accepts_valid_cert() {
        let mut p = make_valid_profile();
        p.server_cert = Some("pin-sha256:hV5X6qtiHKZcDSyRIqUUY6OH6McchYkF7LJrmRrjzJk=".to_string());
        assert!(validate_profile(&p).is_ok());
    }

    // ── validate_mfa_code tests ───────────────────────────────────────────

    #[test]
    fn validate_mfa_code_accepts_six_digits() {
        assert!(validate_mfa_code("123456").is_ok());
    }

    #[test]
    fn validate_mfa_code_rejects_empty() {
        assert!(validate_mfa_code("").is_err());
    }

    #[test]
    fn validate_mfa_code_rejects_letters() {
        assert!(validate_mfa_code("123abc").is_err());
    }

    #[test]
    fn validate_mfa_code_rejects_too_long() {
        assert!(validate_mfa_code(&"1".repeat(MAX_MFA_CODE_LEN + 1)).is_err());
    }

    #[test]
    fn validate_mfa_code_rejects_special_chars() {
        assert!(validate_mfa_code("12-345").is_err());
    }

    #[test]
    fn validate_mfa_code_accepts_single_digit() {
        assert!(validate_mfa_code("0").is_ok());
    }

    #[test]
    fn validate_mfa_code_accepts_max_length() {
        assert!(validate_mfa_code(&"9".repeat(MAX_MFA_CODE_LEN)).is_ok());
    }

    #[test]
    fn validate_mfa_code_rejects_whitespace() {
        assert!(validate_mfa_code("123 456").is_err());
    }

    // ── is_valid_uuid tests ───────────────────────────────────────────────

    #[test]
    fn uuid_valid_format() {
        assert!(is_valid_uuid("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn uuid_rejects_short() {
        assert!(!is_valid_uuid("550e8400-e29b-41d4"));
    }

    #[test]
    fn uuid_rejects_no_dashes() {
        assert!(!is_valid_uuid("550e8400e29b41d4a716446655440000"));
    }

    #[test]
    fn uuid_rejects_non_hex() {
        assert!(!is_valid_uuid("zzzzzzzz-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn uuid_rejects_empty() {
        assert!(!is_valid_uuid(""));
    }

    #[test]
    fn uuid_accepts_uppercase_hex() {
        assert!(is_valid_uuid("550E8400-E29B-41D4-A716-446655440000"));
    }

    #[test]
    fn uuid_rejects_too_many_parts() {
        assert!(!is_valid_uuid("550e8400-e29b-41d4-a716-446655440000-extra"));
    }

    #[test]
    fn uuid_rejects_all_dashes() {
        assert!(!is_valid_uuid("------------------------------------"));
    }

    #[test]
    fn uuid_rejects_incorrect_segment_lengths() {
        // First segment is 9 chars instead of 8
        assert!(!is_valid_uuid("123456789-e29b-41d4-a716-446655440000"));
        // Last segment is 11 chars instead of 12
        assert!(!is_valid_uuid("550e8400-e29b-41d4-a716-44665544000"));
    }

    #[test]
    fn uuid_rejects_non_hex_in_middle_segments() {
        assert!(!is_valid_uuid("550e8400-zzzz-41d4-a716-446655440000"));
    }

    // ── sanitize_error tests ──────────────────────────────────────────────

    #[test]
    fn sanitize_error_masks_credential_details() {
        let msg = sanitize_error("Credential error (Win32 code 1168)");
        assert_eq!(msg, "A credential store error occurred");
    }

    #[test]
    fn sanitize_error_masks_io_paths() {
        let msg = sanitize_error("I/O error: permission denied (os error 5)");
        assert_eq!(msg, "A file system error occurred");
    }

    #[test]
    fn sanitize_error_masks_spawn_path() {
        let msg = sanitize_error("failed to spawn openconnect: No such file");
        assert_eq!(msg, "Failed to start VPN connection");
    }

    #[test]
    fn sanitize_error_masks_profile_not_found() {
        let msg = sanitize_error("profile not found: 550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(msg, "Profile not found");
    }

    #[test]
    fn sanitize_error_preserves_other_messages() {
        let msg = sanitize_error("already connected");
        assert_eq!(msg, "already connected");
    }

    #[test]
    fn sanitize_error_strips_hostname() {
        // Hostnames/URLs should be scrubbed so server names never leak to the UI.
        let msg = sanitize_error("connection to vpn.corp.example.com timed out");
        assert!(!msg.contains("vpn.corp.example.com"));
        assert!(!msg.contains("example.com"));
    }

    #[test]
    fn sanitize_error_strips_path_separators() {
        let msg = sanitize_error("config read from C:\\Users\\alice\\profiles.json failed");
        assert!(!msg.contains('\\'));
        assert!(!msg.contains("alice"));
    }

    #[test]
    fn sanitize_error_empty_string() {
        let msg = sanitize_error("");
        assert_eq!(msg, "");
    }

    #[test]
    fn sanitize_error_credential_partial_word() {
        let msg = sanitize_error("CredentialBasedError should not match");
        assert_eq!(msg, "CredentialBasedError should not match");
    }

    #[test]
    fn sanitize_error_profile_not_found_variation() {
        let msg = sanitize_error("Profile not found (case sensitivity)");
        assert_eq!(msg, "Profile not found (case sensitivity)");
    }

    #[test]
    fn sanitize_error_io_uppercase() {
        let msg = sanitize_error("I/O error: disk full");
        assert_eq!(msg, "A file system error occurred");
    }

    // ── validate_profile additional edge cases ────────────────────────────

    #[test]
    fn validate_profile_rejects_space_in_server() {
        let mut p = make_valid_profile();
        p.server = "https://vpn.example.com --script evil".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_tab_in_server() {
        let mut p = make_valid_profile();
        p.server = "https://vpn.example.com\t--foo".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_carriage_return_in_server() {
        let mut p = make_valid_profile();
        p.server = "https://vpn.example.com\rbad".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_accepts_valid_cert_with_special_chars() {
        let mut p = make_valid_profile();
        p.server_cert = Some("pin-sha256:abc123+def456/ghi789=".to_string());
        assert!(validate_profile(&p).is_ok());
    }

    #[test]
    fn validate_profile_rejects_name_at_max_plus_one() {
        let mut p = make_valid_profile();
        p.name = "a".repeat(MAX_NAME_LEN + 1);
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_accepts_name_at_max() {
        let mut p = make_valid_profile();
        p.name = "a".repeat(MAX_NAME_LEN);
        assert!(validate_profile(&p).is_ok());
    }

    #[test]
    fn validate_profile_rejects_server_with_only_protocol() {
        let mut p = make_valid_profile();
        p.server = "https://".to_string();
        // Rejected: a scheme with no host is not a usable server URL.
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_server_with_embedded_credentials() {
        let mut p = make_valid_profile();
        p.server = "https://user:pass@vpn.example.com".to_string();
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_totp_secret_with_lowercase() {
        let mut p = make_valid_profile();
        p.totp_secret = Some("gezdgnbvgy3tqojq".to_string());
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_rejects_totp_secret_with_digit_1() {
        let mut p = make_valid_profile();
        // Base32 allows 2-7, not 0,1,8,9
        p.totp_secret = Some("GEZDGNBVGY3TQOJ1".to_string());
        assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn validate_profile_accepts_totp_secret_with_padding() {
        let mut p = make_valid_profile();
        p.totp_secret = Some("GEZDGNBVGY3TQOJQ=".to_string());
        assert!(validate_profile(&p).is_ok());
    }

    #[test]
    fn validate_profile_rejects_cert_with_invalid_chars() {
        let mut p = make_valid_profile();
        p.server_cert = Some("pin-sha256:abc def!".to_string());
        assert!(validate_profile(&p).is_err());
    }
}

// ── Connection management commands ────────────────────────────────────────────

use std::sync::Arc;
use crate::bridge::{BridgeEvent, BridgeInfo, EventSink};
use crate::process::ProcessManager;
use crate::types::ConnectionState;

/// [`EventSink`] implementation that delivers [`BridgeEvent`]s over Tauri's
/// event system. This is the single place that couples the UI-agnostic bridge
/// contract to Tauri; a different frontend would provide its own sink.
pub struct TauriEventSink {
    app: AppHandle,
}

impl TauriEventSink {
    /// Create a sink that emits on the given app handle.
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl EventSink for TauriEventSink {
    fn emit(&self, event: BridgeEvent) {
        use tauri::Emitter;
        // Emission is best-effort: a failure here means the webview is gone,
        // in which case there is nothing useful to do but drop the event.
        match event.payload() {
            Ok(payload) => {
                let _ = self.app.emit(event.channel(), payload);
            }
            Err(_) => { /* unreachable for plain data types */ }
        }
    }
}

/// Return the bridge API version and channel list so a frontend can negotiate
/// compatibility at startup. Part of the stable bridge contract.
#[tauri::command]
pub fn bridge_version() -> BridgeInfo {
    BridgeInfo::current()
}

/// Return the version string of the bundled `openconnect.exe`.
///
/// Runs `openconnect --version` and returns the first line (e.g.
/// `"OpenConnect version v9.21"`). Returns an error string if the binary cannot
/// be located or executed.
#[tauri::command]
pub fn openconnect_version() -> Result<String, String> {
    use std::process::Command;
    let exe = resolve_openconnect_exe();
    #[allow(unused_mut)]
    let mut cmd = Command::new(&exe);
    cmd.arg("--version");
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run openconnect: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("unknown")
        .trim()
        .to_string();
    Ok(first)
}

/// Return `true` if the app is running elevated (administrator).
///
/// The kill-switch configures the Windows firewall via `netsh`, which requires
/// elevation. The frontend can call this to warn the user before attempting a
/// connection with the kill-switch enabled.
#[tauri::command]
pub fn is_elevated() -> bool {
    crate::killswitch::is_elevated()
}

/// Engage the firewall kill-switch for `server`, running the blocking `netsh`
/// work on a dedicated thread so it never stalls the async runtime.
///
/// Returns `Err` (and leaves the firewall clean) if the server cannot be
/// resolved or `netsh` fails — the caller must abort the connection in that
/// case to avoid a traffic leak.
async fn engage_kill_switch(server: String) -> Result<(), String> {
    let outcome = tokio::task::spawn_blocking(move || crate::killswitch::enable(&server))
        .await
        .map_err(|e| e.to_string())?;
    match outcome {
        Ok(true) => Ok(()),
        Ok(false) => {
            let _ = tokio::task::spawn_blocking(crate::killswitch::disable).await;
            Err(
                "kill-switch could not be engaged (server address unresolved); aborting to avoid leaks"
                    .to_string(),
            )
        }
        Err(e) => {
            let _ = tokio::task::spawn_blocking(crate::killswitch::disable).await;
            Err(format!("kill-switch failed to engage: {e}"))
        }
    }
}

/// Connect to a VPN profile by ID.
///
/// Loads the profile, reads the stored credential, attempts TOTP generation
/// if the profile has a TOTP secret. On TOTP success, spawns the openconnect
/// process immediately. On missing/failed TOTP, emits `openconnect://mfa-required`
/// so the frontend can prompt the user.
///
/// If the stored credential is not found (error 1168), the connection parameters
/// are saved as a pending connection and `openconnect://mfa-required` is emitted
/// so the user can provide the password manually.
#[tauri::command]
pub async fn connect(
    profile_id: String,
    app: tauri::AppHandle,
    manager: tauri::State<'_, Arc<ProcessManager>>,
) -> Result<(), String> {
    use tauri::Emitter;

    // Run blocking I/O off the async runtime to avoid stalling the event loop
    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let profiles = tokio::task::spawn_blocking({
        let dir = app_data_dir.clone();
        move || config::load_profiles(&dir)
    })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e: AppError| e.to_string())?;
    let mut profile = profiles
        .into_iter()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| format!("profile not found: {profile_id}"))?;

    // Secrets are never stored in profiles.json; fetch each (if any) from
    // Windows Credential Manager so the connect flow below can use them. A
    // missing entry simply means that secret is not configured.
    profile.totp_secret = credentials::read_credential(&totp_target(&profile.id)).ok();
    profile.token_secret =
        credentials::read_credential(&secret_target(&profile.id, "token-secret")).ok();
    profile.key_password =
        credentials::read_credential(&secret_target(&profile.id, "key-password")).ok();
    profile.mca_key_password =
        credentials::read_credential(&secret_target(&profile.id, "mca-key-password")).ok();

    // Re-validate on the read path. The profile store is a plain JSON file the
    // user (or malware) could edit out-of-band to smuggle malformed fields
    // (embedded newlines, bogus URLs, injected args) past the add/update
    // validation. Re-checking here ensures nothing unvalidated ever reaches the
    // openconnect argument builder.
    validate_profile(&profile)?;

    // Remember this profile as the most recent one so auto-connect-on-launch can
    // reconnect to it next time. Best-effort; a persistence failure must not
    // block the connection.
    {
        let mut settings = crate::settings::load_settings(&app_data_dir).unwrap_or_default();
        if settings.last_profile_id.as_deref() != Some(profile.id.as_str()) {
            settings.last_profile_id = Some(profile.id.clone());
            let _ = crate::settings::save_settings(&app_data_dir, &settings);
        }
    }

    // Discard any stale pending connection from a previous, abandoned attempt
    // so a later submit_mfa cannot resurrect the wrong profile's connection.
    let _ = manager.take_pending();

    let target = format!("openconnect-gui/{}", profile.id);
    let password = {
        let target_clone = target.clone();
        tokio::task::spawn_blocking(move || credentials::read_credential(&target_clone))
            .await
            .map_err(|e| e.to_string())?
    };
    let password = match password {
        Ok(pw) => pw,
        // 1168 = credential not found; 13 = stored credential failed UTF-8
        // decode (corrupted). In both cases we cannot use a stored password, so
        // fall through to the MFA/password-entry flow rather than hard-failing.
        Err(crate::types::AppError::CredentialError(1168))
        | Err(crate::types::AppError::CredentialError(13)) => {
            // Prompt user for password via MFA flow.
            // Store pending connection so submit_mfa can pick it up.
            let exe_path = resolve_openconnect_exe();
            let settings_dir = app_data_dir.clone();
            let settings = crate::settings::load_settings(&settings_dir).unwrap_or_default();
            let args_owned = build_openconnect_args(&profile);

            let pending = crate::process::PendingConnection {
                app_handle: app.clone(),
                exe_path,
                args: args_owned,
                profile_id: profile.id.clone(),
                username: profile.username.clone(),
                server: profile.server.clone(),
                kill_switch: profile.kill_switch || settings.killswitch_enabled,
            };
            manager.set_pending(pending).map_err(|e| e.to_string())?;
            let _ = app.emit("openconnect://mfa-required", &profile_id);
            return Ok(());
        }
        Err(e) => return Err(e.to_string()),
    };

    let exe_path = resolve_openconnect_exe();
    let settings_dir = app_data_dir.clone();
    let settings = crate::settings::load_settings(&settings_dir).unwrap_or_default();
    let args_owned = build_openconnect_args(&profile);

    // Try TOTP if secret present — run blocking crypto off the async runtime
    let mfa_code = if let Some(ref secret) = profile.totp_secret {
        let secret_clone = secret.clone();
        match tokio::task::spawn_blocking(move || {
            let code = generate_totp(&secret_clone);
            let mut secret_clone = secret_clone;
            zeroize::Zeroize::zeroize(&mut secret_clone);
            code
        })
            .await
            .map_err(|e| e.to_string())?
        {
            Ok(code) => Some(code),
            Err(_) => {
                // TOTP failed — ask frontend for manual MFA
                let _ = app.emit("openconnect://mfa-required", &profile_id);
                return Ok(());
            }
        }
    } else {
        // No TOTP secret — send password as MFA directly
        Some(password)
    };

    // Engage the kill-switch (if the profile OR the global toggle requests it)
    // BEFORE spawning, so there is never a window where traffic could leak.
    let kill_switch = profile.kill_switch || settings.killswitch_enabled;
    if kill_switch {
        engage_kill_switch(profile.server.clone()).await?;
    }

    let args_refs: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
    let result = manager
        .connect(app.clone(), &exe_path, &args_refs, mfa_code)
        .await
        .map_err(|e| e.to_string());
    if result.is_err() && kill_switch {
        crate::killswitch::disable();
    }
    result
}

/// Submit an MFA code for a pending connection.
///
/// If there is a pending connection (credential was missing), stores the
/// submitted code as the credential and spawns the openconnect process.
/// Otherwise, writes the code directly to the openconnect process stdin.
#[tauri::command]
pub async fn submit_mfa(
    code: String,
    manager: tauri::State<'_, Arc<ProcessManager>>,
) -> Result<(), String> {
    // Validate the code up front so BOTH the pending-spawn path and the
    // stdin-write path are guarded. Reject empty input and anything with
    // control characters (newlines, NUL) that would corrupt the line-oriented
    // stdin protocol or be stored as a malformed credential. We intentionally
    // do NOT force digits-only, since some MFA/challenge responses are
    // alphanumeric.
    if code.is_empty() {
        return Err("MFA code must not be empty".to_string());
    }
    if code.chars().any(|c| c.is_control()) {
        return Err("MFA code must not contain control characters".to_string());
    }
    if code.len() > 256 {
        return Err("MFA code is too long".to_string());
    }

    // Check for a pending connection (credential was missing).
    //
    // A pending connection is created ONLY on the credential-not-found / corrupt
    // path in `connect`, i.e. the user is supplying their account *password* for
    // the first time — so persisting it here is correct. A one-time TOTP/MFA
    // challenge response never reaches this branch: `connect` returns without
    // setting `pending` in that case, so such codes flow through the
    // stdin-write branch below and are never stored.
    if let Some(pending) = manager.take_pending().map_err(|e| e.to_string())? {
        // Store the (password) credential for future connections.
        let target = format!("openconnect-gui/{}", pending.profile_id);
        let _ = credentials::store_credential(&target, &pending.username, &code);

        // Engage the kill-switch before spawning if this profile requires it.
        if pending.kill_switch {
            engage_kill_switch(pending.server.clone()).await?;
        }

        // Spawn the openconnect process with the provided password.
        let args_refs: Vec<&str> = pending.args.iter().map(|s| s.as_str()).collect();
        let result = manager
            .connect(pending.app_handle.clone(), &pending.exe_path, &args_refs, Some(code))
            .await
            .map_err(|e| e.to_string());
        if result.is_err() && pending.kill_switch {
            crate::killswitch::disable();
        }
        result?;

        return Ok(());
    }

    // Otherwise, write to stdin of an already-running process. The code has
    // already been validated above.
    manager.write_stdin(&format!("{code}\n")).await.map_err(|e| e.to_string())
}

/// Disconnect from the current VPN session.
///
/// Emits `Disconnecting` immediately for responsive UI, then tears down the
/// process. [`ProcessManager::disconnect`] emits the terminal `Disconnected`
/// state so the frontend never gets stuck on `Disconnecting`.
#[tauri::command]
pub fn disconnect(
    app: tauri::AppHandle,
    manager: tauri::State<'_, Arc<ProcessManager>>,
) -> Result<(), String> {
    let sink = TauriEventSink::new(app.clone());
    sink.emit(BridgeEvent::State(ConnectionState::Disconnecting));
    manager.disconnect(&app).map_err(|e| e.to_string())
}

/// Get the current VPN connection state.
#[tauri::command]
pub fn get_connection_state(
    manager: tauri::State<'_, Arc<ProcessManager>>,
) -> ConnectionState {
    manager.get_state()
}

/// Get the tunnel's assigned local IP (empty string if not connected).
#[tauri::command]
pub fn get_tunnel_ip(manager: tauri::State<'_, Arc<ProcessManager>>) -> String {
    manager.get_tunnel_ip()
}

/// Query the current public IP address as seen from the internet.
///
/// While the VPN tunnel is up, this reflects the exit IP of the VPN server,
/// which is what the user actually wants to see. Several lightweight
/// plain-text endpoints are tried in order so a single outage doesn't break
/// the feature.
///
/// # Errors
///
/// Returns an error string if every endpoint fails or returns a value that
/// does not look like an IP address.
#[tauri::command]
pub async fn get_public_ip() -> Result<String, String> {
    const ENDPOINTS: [&str; 3] = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| e.to_string())?;

    let mut last_err = String::from("no endpoints tried");
    for url in ENDPOINTS {
        match client.get(url).send().await {
            Ok(resp) => match resp.text().await {
                Ok(body) => {
                    let ip = body.trim();
                    if looks_like_ip(ip) {
                        return Ok(ip.to_string());
                    }
                    last_err = format!("unexpected response from {url}");
                }
                Err(e) => last_err = format!("{url}: {e}"),
            },
            Err(e) => last_err = format!("{url}: {e}"),
        }
    }

    Err(last_err)
}

/// Cheap sanity check that a string looks like an IPv4 or IPv6 address, so we
/// never surface a stray HTML error page as if it were an IP.
fn looks_like_ip(s: &str) -> bool {
    if s.is_empty() || s.len() > 45 {
        return false;
    }
    s.parse::<std::net::IpAddr>().is_ok()
}

// ── Real network telemetry ────────────────────────────────────────────────────

/// Real cumulative RX/TX byte counters for the tunnel adapter.
///
/// The frontend samples this on an interval and derives throughput from the
/// difference between successive samples. Returns an error string while
/// disconnected (no tunnel IP) or if the adapter counters can't be read.
///
/// # Errors
///
/// Returns an error string if there is no active tunnel or its statistics are
/// unavailable.
#[tauri::command]
pub async fn get_adapter_stats(
    manager: tauri::State<'_, Arc<ProcessManager>>,
) -> Result<crate::netstats::AdapterStats, String> {
    let ip = manager.get_tunnel_ip();
    tokio::task::spawn_blocking(move || crate::netstats::get_adapter_stats(&ip))
        .await
        .map_err(|e| e.to_string())?
}

/// Measure a real ICMP round-trip time (ms) through the tunnel.
///
/// Resolves the tunnel adapter's gateway (next hop) and pings it; if no gateway
/// can be resolved it falls back to a well-known public host (`1.1.1.1`), which
/// is routed through the tunnel while connected. Returns the RTT in
/// milliseconds.
///
/// # Errors
///
/// Returns an error string if the target is unreachable or the reply can't be
/// parsed.
#[tauri::command]
pub async fn ping_tunnel(
    manager: tauri::State<'_, Arc<ProcessManager>>,
) -> Result<u32, String> {
    let ip = manager.get_tunnel_ip();
    tokio::task::spawn_blocking(move || {
        let target = resolve_ping_target(&ip);
        crate::netstats::ping_host(&target)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Pick the best real host to ping: the tunnel adapter's gateway if resolvable,
/// otherwise a reliable public anchor routed through the tunnel.
#[cfg(target_os = "windows")]
fn resolve_ping_target(tunnel_ip: &str) -> String {
    resolve_tunnel_gateway(tunnel_ip).unwrap_or_else(|| "1.1.1.1".to_string())
}

#[cfg(not(target_os = "windows"))]
fn resolve_ping_target(_tunnel_ip: &str) -> String {
    "1.1.1.1".to_string()
}

/// Resolve the next-hop gateway of the adapter that owns `tunnel_ip` via
/// `Get-NetRoute`. Returns `None` if it can't be determined.
#[cfg(target_os = "windows")]
fn resolve_tunnel_gateway(tunnel_ip: &str) -> Option<String> {
    use crate::types::system32_exe;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let ip = tunnel_ip.split('/').next().unwrap_or(tunnel_ip).trim();
    ip.parse::<std::net::IpAddr>().ok()?;

    let script = format!(
        "$a = Get-NetIPAddress -IPAddress '{ip}' -ErrorAction SilentlyContinue | Select-Object -First 1; \
         if (-not $a) {{ exit 2 }}; \
         $r = Get-NetRoute -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue | \
              Where-Object {{ $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' }} | \
              Select-Object -First 1; \
         if ($r) {{ Write-Output $r.NextHop }}"
    );

    let out = Command::new(system32_exe("WindowsPowerShell\\v1.0\\powershell.exe"))
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&out.stdout);
    let gw = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    if gw.parse::<std::net::IpAddr>().is_ok() {
        Some(gw.to_string())
    } else {
        None
    }
}

// ── Global settings & tool toggles ────────────────────────────────────────────

use crate::settings::{AppSettings, NetShieldConfig};

/// Return the persisted global settings (tool toggles + preferences).
#[tauri::command]
pub fn get_settings(app: tauri::AppHandle) -> Result<AppSettings, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(crate::settings::load_settings(&dir).unwrap_or_default())
}

/// Persist the full global settings object.
#[tauri::command]
pub fn set_settings(app: tauri::AppHandle, settings: AppSettings) -> Result<(), String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    crate::settings::save_settings(&dir, &settings).map_err(|e: AppError| e.to_string())
}

/// Toggle the NetShield master switch and persist it.
#[tauri::command]
pub fn set_netshield(app: tauri::AppHandle, enabled: bool) -> Result<AppSettings, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let mut settings = crate::settings::load_settings(&dir).unwrap_or_default();
    settings.netshield_enabled = enabled;
    crate::settings::save_settings(&dir, &settings).map_err(|e: AppError| e.to_string())?;
    Ok(settings)
}

/// Update the NetShield sub-feature toggles (block_malware / secure_connection /
/// block_ads) and persist them.
#[tauri::command]
pub fn set_netshield_config(
    app: tauri::AppHandle,
    config: NetShieldConfig,
) -> Result<AppSettings, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let mut settings = crate::settings::load_settings(&dir).unwrap_or_default();
    settings.netshield = config;
    crate::settings::save_settings(&dir, &settings).map_err(|e: AppError| e.to_string())?;
    Ok(settings)
}

/// Toggle the global kill-switch and persist it.
#[tauri::command]
pub fn set_killswitch(app: tauri::AppHandle, enabled: bool) -> Result<AppSettings, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let mut settings = crate::settings::load_settings(&dir).unwrap_or_default();
    settings.killswitch_enabled = enabled;
    crate::settings::save_settings(&dir, &settings).map_err(|e: AppError| e.to_string())?;
    Ok(settings)
}

/// Toggle Auto Retry and persist it.
#[tauri::command]
pub fn set_auto_retry(app: tauri::AppHandle, enabled: bool) -> Result<AppSettings, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let mut settings = crate::settings::load_settings(&dir).unwrap_or_default();
    settings.auto_retry_enabled = enabled;
    crate::settings::save_settings(&dir, &settings).map_err(|e: AppError| e.to_string())?;
    Ok(settings)
}
