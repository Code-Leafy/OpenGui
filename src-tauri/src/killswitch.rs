//! Firewall kill-switch (Windows).
//!
//! When enabled, this blocks **all** outbound network traffic except:
//!   * loopback (127.0.0.0/8),
//!   * traffic to the VPN server itself (so the tunnel can be (re)established),
//!   * traffic to private/link-local ranges needed for DHCP/gateway discovery,
//!   * traffic to the AdGuard DNS resolvers (DNS only) used by NetShield.
//!
//! The effect is that if the VPN tunnel drops, no packet can escape over the
//! physical interface — preventing an IP or DNS leak. Once the tunnel is up,
//! openconnect's routes send everything through the tunnel adapter, which is
//! itself allowed (its packets are encapsulated to the server, which is
//! permitted).
//!
//! # Safety
//!
//! A kill-switch that fails to clean up would strand the user with no internet.
//! This module is therefore defensive:
//!   * All rules live in a single named group ([`RULE_GROUP`]) and are removed
//!     by that name, so cleanup is idempotent and complete.
//!   * [`disable`] is called on disconnect, on unexpected process exit, on
//!     `Drop`, on the window-close hook, **and** once at startup — so a rule
//!     set left behind by a crash is always torn down.
//!   * Cleanup never returns an error that could abort teardown.

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Name shared by every firewall rule this module creates. Used to delete the
/// whole set in one idempotent call.
pub const RULE_GROUP: &str = "OpenConnectGUI-KillSwitch";

/// Resolve a hostname or URL to its IPv4/IPv6 literal(s) for firewall scoping.
///
/// Accepts `https://host:port`, `host`, or a bare IP. Returns every resolved
/// address as a string. Returns an empty vec if resolution fails (in which case
/// the caller must NOT enable the kill-switch, to avoid locking out the server).
#[cfg(target_os = "windows")]
fn resolve_server_ips(server: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;

    // Strip scheme and path, keep host[:port].
    let host = server
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = host.split('/').next().unwrap_or(host);
    // If a port is present keep it; otherwise assume 443 for resolution.
    let host_port = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:443")
    };

    match host_port.to_socket_addrs() {
        // Re-parse each formatted address as a strict IP literal before it is
        // ever interpolated into a `netsh remoteip=` argument. Values from
        // `SocketAddr::ip()` are already valid, but round-tripping through
        // `IpAddr::from_str` is a cheap, explicit guarantee that only canonical
        // IP literals (no separators, no injected tokens) reach the firewall
        // command line — defence-in-depth against any future change to the
        // resolution path.
        Ok(addrs) => addrs
            .filter_map(|a| {
                let s = a.ip().to_string();
                s.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Enable the kill-switch for a connection to `server`.
///
/// Returns `Ok(false)` (kill-switch NOT enabled) if the server address cannot
/// be resolved — enabling in that case could block the very traffic needed to
/// reach the VPN. Returns `Ok(true)` if the rules were installed.
#[cfg(target_os = "windows")]
pub fn enable(server: &str) -> Result<bool, String> {
    // Always clear any stale rules first so enable() is idempotent.
    disable();

    let ips = resolve_server_ips(server);
    if ips.is_empty() {
        crate::log_warn!(
            "killswitch",
            "could not resolve server '{}'; kill-switch NOT enabled",
            server
        );
        return Ok(false);
    }

    // 1. Block ALL outbound traffic (both profiles) in our named group.
    //    `remoteip=any` covers IPv4 AND IPv6, so global IPv6 traffic is also
    //    blocked while the kill-switch is engaged — there is no separate IPv6
    //    rule needed. (We deliberately do NOT disable IPv6 per-interface via
    //    netsh: that change is not reliably reversible and risks stranding the
    //    user's connectivity.)
    run_netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={RULE_GROUP}"),
        "dir=out",
        "action=block",
        "enable=yes",
        "profile=any",
        "remoteip=any",
    ])?;

    // 2. Allow loopback (IPv4 + IPv6).
    add_allow("remoteip=127.0.0.1/8,::1/128")?;
    // 3. Allow private/link-local ranges (DHCP, gateway, LAN, and IPv6
    //    link-local needed to bring up / keep the physical link).
    add_allow(
        "remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fe80::/10,fc00::/7",
    )?;
    // 4. Allow the VPN server address(es) so the tunnel can be established.
    let joined = ips.join(",");
    add_allow(&format!("remoteip={joined}"))?;
    // 5. Allow the AdGuard DNS resolvers so NetShield DNS keeps working while
    //    the kill-switch is engaged (queries go straight to AdGuard, not the
    //    VPN server, so they would otherwise be blocked).
    //
    //    These are scoped to DNS only (UDP port 53 and TCP port 53). Scoping
    //    prevents the AdGuard IPs from being used as a general outbound escape
    //    hatch — without the port restriction, ANY traffic to those IPs (e.g. an
    //    app opening a connection to 94.140.14.14:443) would be allowed and
    //    could leak past the tunnel. NetShield (netshield.rs) configures plain
    //    DNS on the tunnel adapter, which is port 53, so this does NOT break
    //    DoT/DoH (those are not used here) and does NOT affect the VPN tunnel,
    //    which is covered separately by the server allow rule above. Each
    //    protocol needs its own rule because `netsh advfirewall` accepts only a
    //    single `protocol=` value per rule.
    let mut dns_ips: Vec<&str> = Vec::new();
    dns_ips.extend_from_slice(crate::settings::ADGUARD_IPV4);
    dns_ips.extend_from_slice(crate::settings::ADGUARD_IPV6);
    let dns = dns_ips.join(",");
    add_allow_dns(&format!("remoteip={dns}"), "UDP")?;
    add_allow_dns(&format!("remoteip={dns}"), "TCP")?;

    crate::log_info!(
        "killswitch",
        "enabled (server ips: {}, dns ips: {})",
        joined,
        dns
    );
    Ok(true)
}

/// Install a single "allow outbound" rule in the kill-switch group.
///
/// Allow rules take precedence over block rules of the same specificity in
/// Windows Firewall, so these carve exceptions out of the blanket block.
#[cfg(target_os = "windows")]
fn add_allow(remoteip_arg: &str) -> Result<(), String> {
    run_netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={RULE_GROUP}"),
        "dir=out",
        "action=allow",
        "enable=yes",
        "profile=any",
        remoteip_arg,
    ])
}

/// Install a single "allow outbound" DNS rule in the kill-switch group.
///
/// Like [`add_allow`] but additionally restricts the exception to DNS on the
/// given transport (`UDP` or `TCP`) at remote port 53. This prevents the
/// allowed destination (e.g. the AdGuard resolvers) from being used as a
/// general outbound escape hatch while still permitting the plain-DNS queries
/// NetShield needs. `netsh advfirewall` accepts only one `protocol=` value per
/// rule, so the caller installs one of these per protocol.
#[cfg(target_os = "windows")]
fn add_allow_dns(remoteip_arg: &str, protocol: &str) -> Result<(), String> {
    let args = dns_allow_args(remoteip_arg, protocol);
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_netsh(&refs)
}

/// Build the `netsh advfirewall firewall add rule` argument vector for a
/// DNS-scoped allow exception (see [`add_allow_dns`]). Pure and side-effect
/// free so it can be unit-tested without touching the firewall.
#[cfg(target_os = "windows")]
fn dns_allow_args(remoteip_arg: &str, protocol: &str) -> Vec<String> {
    vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={RULE_GROUP}"),
        "dir=out".to_string(),
        "action=allow".to_string(),
        "enable=yes".to_string(),
        "profile=any".to_string(),
        remoteip_arg.to_string(),
        format!("protocol={protocol}"),
        "remoteport=53".to_string(),
    ]
}

/// Remove every kill-switch rule. Idempotent and never fails hard.
///
/// Safe to call when no rules exist (netsh reports "No rules match" — treated
/// as success). Always call this on any teardown path.
#[cfg(target_os = "windows")]
pub fn disable() {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    let _ = Command::new(crate::types::system32_exe("netsh.exe"))
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={RULE_GROUP}"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    crate::log_info!("killswitch", "disabled (rules removed)");
}

/// Run a netsh command, mapping non-zero exit to an error string.
#[cfg(target_os = "windows")]
fn run_netsh(args: &[&str]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    let out = Command::new(crate::types::system32_exe("netsh.exe"))
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("failed to run netsh: {e}"))?;
    if out.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stderr}{stdout}").to_lowercase();
    // netsh reports elevation failures with these phrases depending on locale.
    if combined.contains("elevat")
        || combined.contains("requested operation requires")
        || combined.contains("access is denied")
        || combined.contains("run as administrator")
    {
        return Err(
            "administrator privileges are required to configure the firewall. \
             Run OpenGui as administrator to use the kill-switch."
                .to_string(),
        );
    }
    Err(format!(
        "netsh exited with {}: {}",
        out.status,
        stderr.trim()
    ))
}

/// Return `true` if the current process is running with an elevated token
/// (i.e. "Run as administrator") and can therefore configure the firewall.
///
/// This queries the process token's `TokenElevation` — it is side-effect free
/// (no firewall rules are touched) and does not require elevation itself. If
/// any Win32 call fails we conservatively report `false`.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
pub fn is_elevated() -> bool {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

// ── Non-Windows stubs (compile everywhere; the app targets Windows) ──────────

#[cfg(not(target_os = "windows"))]
pub fn enable(_server: &str) -> Result<bool, String> {
    Ok(false)
}

#[cfg(not(target_os = "windows"))]
pub fn disable() {}

#[cfg(not(target_os = "windows"))]
pub fn is_elevated() -> bool {
    false
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "windows")]
    use super::*;

    #[cfg(target_os = "windows")]
    #[test]
    fn resolve_strips_scheme_and_path() {
        // Loopback resolves deterministically without network access.
        let ips = resolve_server_ips("https://127.0.0.1/some/path");
        assert!(ips.iter().any(|ip| ip == "127.0.0.1"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn resolve_bare_ip() {
        let ips = resolve_server_ips("127.0.0.1");
        assert!(ips.iter().any(|ip| ip == "127.0.0.1"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn resolve_unresolvable_returns_empty() {
        let ips = resolve_server_ips("https://this-host-does-not-exist.invalid");
        assert!(ips.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn rule_group_name_is_stable() {
        assert_eq!(RULE_GROUP, "OpenConnectGUI-KillSwitch");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn is_elevated_returns_without_panicking() {
        // The token-elevation query must be side-effect free and safe to call
        // regardless of the current elevation level. We only assert it runs.
        let _ = is_elevated();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dns_allow_args_are_dns_scoped() {
        // The AdGuard exception must be DNS-only (UDP/TCP, port 53) so those
        // IPs cannot be used as a general outbound escape hatch.
        let udp = dns_allow_args("remoteip=94.140.14.14", "UDP");
        assert!(udp.contains(&"protocol=UDP".to_string()));
        assert!(udp.contains(&"remoteport=53".to_string()));
        assert!(udp.contains(&"action=allow".to_string()));
        assert!(!udp.iter().any(|a| a.starts_with("protocol=TCP")));

        let tcp = dns_allow_args("remoteip=94.140.14.14", "TCP");
        assert!(tcp.contains(&"protocol=TCP".to_string()));
        assert!(tcp.contains(&"remoteport=53".to_string()));
    }
}
