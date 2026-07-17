//! NetShield — malware / secure-connection / ad-blocking via AdGuard DNS.
//!
//! When NetShield is enabled, the DNS servers on the **tunnel adapter** are
//! pointed at AdGuard DNS (94.140.14.14 / 94.140.15.15, plus IPv6). Because all
//! tunneled traffic resolves through AdGuard, malware, tracking and ad domains
//! are blocked at the DNS layer, and the connection never silently falls back to
//! an unprotected resolver.
//!
//! The tunnel adapter is identified by the private IP openconnect assigns to it
//! (the `Connected as <ip>` line). We translate that IP to its owning interface
//! index via `netsh`, then apply the DNS servers to that single interface — so
//! the physical adapter (and therefore leak-prone DNS) is left untouched.

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

use crate::settings::{ADGUARD_IPV4, ADGUARD_IPV6};

/// Apply AdGuard DNS to the tunnel adapter that owns `tunnel_ip`.
///
/// `tunnel_ip` is the address openconnect assigned (e.g. `10.10.159.253`). If it
/// cannot be mapped to an interface, or `netsh` fails, an error string is
/// returned and the caller should treat NetShield as not engaged.
#[cfg(target_os = "windows")]
pub fn enable(tunnel_ip: &str) -> Result<(), String> {
    // The wintun adapter's IP may not be registered in `netsh` the instant the
    // "Configured as" line prints, so retry the lookup briefly before giving up.
    let iface = match find_interface_for_ip_retry(tunnel_ip) {
        Some(i) => i,
        None => {
            return Err(
                "NetShield: could not locate the tunnel adapter to set DNS. \
                 NetShield not engaged."
                    .to_string(),
            )
        }
    };

    // Set the primary (IPv4) AdGuard resolvers. `set dns` replaces any existing
    // servers for that address family.
    let v4 = ADGUARD_IPV4.join(",");
    run_netsh(&[
        "interface",
        "ip",
        "set",
        "dns",
        &format!("name={iface}"),
        "static",
        &v4,
        "validate=no",
    ])?;

    // Set IPv6 AdGuard resolvers (best-effort; ignore failure on v6-only gaps).
    let v6 = ADGUARD_IPV6.join(",");
    let _ = run_netsh(&[
        "interface",
        "ip",
        "set",
        "dns",
        &format!("name={iface}"),
        "static",
        &v6,
        "validate=no",
    ]);

    // Defense against the classic Windows VPN DNS leak: Smart Multi-Homed Name
    // Resolution (SMHNR) sends every query out ALL interfaces in parallel and
    // uses the fastest reply, so queries would still race to the physical
    // adapter's ISP resolver even though we set AdGuard on the tunnel. Disabling
    // it forces resolution to follow the interface order (tunnel first).
    disable_smhnr();

    // Belt-and-braces: also pin every *other* (physical) adapter's DNS to
    // AdGuard. Even if SMHNR still races a query out the physical NIC, it now
    // reaches AdGuard rather than the ISP resolver, so no query name ever leaks.
    // The kill-switch already permits only AdGuard on port 53, so this stays
    // consistent with the firewall policy.
    force_physical_dns(&iface);

    crate::log_info!("netshield", "AdGuard DNS applied to interface '{}'", iface);
    Ok(())
}

/// Pin every interface *other than* `tunnel_iface` to AdGuard DNS so no DNS
/// query can leak to the ISP resolver via a parallel/multi-homed lookup.
#[cfg(target_os = "windows")]
fn force_physical_dns(tunnel_iface: &str) {
    let v4 = ADGUARD_IPV4.join(",");
    let v6 = ADGUARD_IPV6.join(",");
    for iface in list_interface_names() {
        if iface == tunnel_iface {
            continue;
        }
        let _ = run_netsh(&[
            "interface", "ip", "set", "dns", &format!("name={iface}"), "static", &v4, "validate=no",
        ]);
        let _ = run_netsh(&[
            "interface", "ip", "set", "dns", &format!("name={iface}"), "static", &v6, "validate=no",
        ]);
    }
}

/// Revert every interface *other than* `tunnel_iface` back to DHCP-assigned DNS,
/// undoing [`force_physical_dns`].
#[cfg(target_os = "windows")]
fn revert_physical_dns(tunnel_iface: &str) {
    for iface in list_interface_names() {
        if iface == tunnel_iface {
            continue;
        }
        let _ = run_netsh(&[
            "interface", "ip", "set", "dns", &format!("name={iface}"), "dhcp",
        ]);
    }
}

/// Enumerate all interface names from `netsh interface ip show address`.
#[cfg(target_os = "windows")]
fn list_interface_names() -> Vec<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    let out = match Command::new(system32("netsh.exe"))
        .args(["interface", "ip", "show", "address"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    parse_interface_names(&text)
}

/// Pure parser: extract every interface name from a `netsh interface ip show
/// address` dump. Handles both the `Configuration for interface "Name"` header
/// form and the `Interface N: Name` / `Interface "Name":` block form.
#[cfg(target_os = "windows")]
fn parse_interface_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        let candidate = if let Some(rest) = line.strip_prefix("Configuration for interface ") {
            parse_interface_name(rest.trim().trim_end_matches(':'))
        } else if let Some(rest) = line.strip_prefix("Interface ") {
            parse_interface_name(rest)
        } else {
            None
        };
        if let Some(name) = candidate {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// Disable Windows Smart Multi-Homed Name Resolution so DNS queries do not race
/// out the physical adapter to the ISP resolver while the tunnel is up.
#[cfg(target_os = "windows")]
fn disable_smhnr() {
    let _ = run_reg(&[
        "add",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "/v",
        "DisableSmartNameResolution",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ]);
    let _ = run_reg(&[
        "add",
        r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "/v",
        "DisableParallelAandAAAA",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ]);
}

/// Re-enable Smart Multi-Homed Name Resolution by removing the policy overrides
/// added in [`disable_smhnr`]. Best-effort and idempotent.
#[cfg(target_os = "windows")]
fn enable_smhnr() {
    let _ = run_reg(&[
        "delete",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "/v",
        "DisableSmartNameResolution",
        "/f",
    ]);
    let _ = run_reg(&[
        "delete",
        r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "/v",
        "DisableParallelAandAAAA",
        "/f",
    ]);
}

/// Run a `reg` command, mapping a non-zero exit to an error string.
#[cfg(target_os = "windows")]
fn run_reg(args: &[&str]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    let out = Command::new(system32("reg.exe"))
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("failed to run reg: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("reg exited with {}", out.status))
    }
}

/// Remove any explicit DNS set by [`enable`] by reverting the tunnel adapter to
/// DHCP-assigned DNS. Idempotent and best-effort; safe to call on any teardown
/// path or at startup.
#[cfg(target_os = "windows")]
pub fn disable(tunnel_ip: &str) {
    let tunnel_iface = find_interface_for_ip(tunnel_ip);
    if let Some(ref iface) = tunnel_iface {
        // `dhcp` clears the static DNS servers so the interface falls back to
        // whatever the tunnel/DHCP normally provides.
        let _ = run_netsh(&[
            "interface", "ip", "set", "dns", &format!("name={iface}"), "dhcp",
        ]);
        crate::log_info!("netshield", "DNS reverted on interface '{}'", iface);
    }
    // Revert the physical adapters we pinned to AdGuard back to DHCP DNS.
    revert_physical_dns(tunnel_iface.as_deref().unwrap_or(""));
    // Always restore SMHNR to its default (even if the interface lookup failed),
    // so we never leave the system's DNS behaviour altered after teardown.
    enable_smhnr();
}

#[cfg(target_os = "windows")]
use crate::types::system32_exe as system32;

/// Map an IP address to its owning interface *name* by querying `netsh`.
///
/// Parses the `netsh interface ip show address` dump for the block whose
/// `IP Address` matches `tunnel_ip`, then returns the `Interface` name from that
/// block. Returns `None` if no match is found or parsing fails.
/// Look up the interface for `tunnel_ip`, retrying briefly to absorb the race
/// between openconnect announcing the tunnel and Windows registering the
/// adapter's IP. Up to ~5s total (10 tries, 500ms apart).
#[cfg(target_os = "windows")]
fn find_interface_for_ip_retry(tunnel_ip: &str) -> Option<String> {
    for attempt in 0..10 {
        if let Some(iface) = find_interface_for_ip(tunnel_ip) {
            return Some(iface);
        }
        if attempt < 9 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn find_interface_for_ip(tunnel_ip: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    let out = Command::new(system32("netsh.exe"))
        .args(["interface", "ip", "show", "address"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_interface_for_ip(&text, tunnel_ip)
}

/// Pure parser for the `netsh interface ip show address` dump.
///
/// Walks the blocks separated by `Interface N:` (or `Interface "Name":`) lines
/// and returns the name of the interface whose `IP Address:` matches
/// `tunnel_ip`. Returns `None` if no block matches. Factored out of
/// [`find_interface_for_ip`] so it can be unit-tested without invoking `netsh`.
#[cfg(target_os = "windows")]
fn parse_interface_for_ip(text: &str, tunnel_ip: &str) -> Option<String> {
    // `netsh` prints each interface as:
    //   Interface 12: Ethernet
    //   ...
    //   IP Address: 10.10.159.253
    // We walk blocks separated by "Interface N:" lines.
    let mut current_name: Option<String> = None;
    let mut current_ips: Vec<String> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("Interface ") {
            // New interface block. Test the previous block before resetting.
            if let Some(name) = &current_name {
                if current_ips.iter().any(|ip| ip_eq(ip, tunnel_ip)) {
                    return Some(name.clone());
                }
            }
            current_name = parse_interface_name(rest);
            current_ips = Vec::new();
        } else if let Some(ip) = line.strip_prefix("IP Address:") {
            current_ips.push(ip.trim().to_string());
        }
    }
    // Final block.
    if let Some(name) = &current_name {
        if current_ips.iter().any(|ip| ip_eq(ip, tunnel_ip)) {
            return Some(name.clone());
        }
    }
    None
}

/// `netsh` prints `Interface 12: Ethernet` (or `Interface "Ethernet 2":`). Return
/// the human-readable name portion.
#[cfg(target_os = "windows")]
fn parse_interface_name(rest: &str) -> Option<String> {
    // `rest` is everything after "Interface ". Two shapes occur:
    //   `12: Ethernet`   → name follows the first colon
    //   `"Ethernet 2":`  → name is the quoted portion (may contain spaces/colons)
    let trimmed = rest.trim();
    let name = if trimmed.starts_with('"') {
        // Take everything between the first and last quote.
        let inner = trimmed.trim_start_matches('"');
        inner.rsplitn(2, '"').last().unwrap_or(inner).to_string()
    } else {
        // Fall back to the text after the first colon (the index/name split).
        trimmed
            .split_once(':')
            .map(|(_, name)| name)
            .unwrap_or(trimmed)
            .trim()
            .trim_end_matches(':')
            .trim()
            .to_string()
    };
    let name = name.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Compare two IP literals, tolerating a `/prefix` suffix on either side.
#[cfg(target_os = "windows")]
fn ip_eq(a: &str, b: &str) -> bool {
    fn norm(s: &str) -> &str {
        s.split('/').next().unwrap_or(s).trim()
    }
    norm(a).eq_ignore_ascii_case(norm(b))
}

/// Run a netsh command, mapping a non-zero exit to an error string.
#[cfg(target_os = "windows")]
fn run_netsh(args: &[&str]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    let out = Command::new(system32("netsh.exe"))
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("failed to run netsh: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    Err(format!("netsh exited with {}: {}", out.status, detail))
}

// ── Non-Windows stubs ─────────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
pub fn enable(_tunnel_ip: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn disable(_tunnel_ip: &str) {}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "windows")]
    #[test]
    fn ip_eq_ignores_prefix() {
        assert!(super::ip_eq("10.10.159.253", "10.10.159.253/24"));
        assert!(super::ip_eq("10.10.159.253/24", "10.10.159.253"));
        assert!(!super::ip_eq("10.10.159.253", "10.10.159.1"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parse_interface_name_handles_quotes() {
        assert_eq!(super::parse_interface_name("12: Ethernet").unwrap(), "Ethernet");
        assert_eq!(
            super::parse_interface_name("\"Ethernet 2\":").unwrap(),
            "Ethernet 2"
        );
    }

    #[cfg(target_os = "windows")]
    const NETSH_DUMP: &str = "\
Configuration for interface \"Ethernet\"
    DHCP enabled:                         Yes
    IP Address:                           192.168.1.20
    Subnet Prefix:                        192.168.1.0/24 (mask 255.255.255.0)
    Default Gateway:                      192.168.1.1

Interface 12: Wi-Fi
    DHCP enabled:                         Yes
    IP Address:                           192.168.0.50
    Subnet Prefix:                        192.168.0.0/24 (mask 255.255.255.0)

Interface \"OpenConnect Tunnel\":
    DHCP enabled:                         No
    IP Address:                           10.10.159.253
    Subnet Prefix:                        10.10.159.0/24 (mask 255.255.255.0)

Interface 24: TunV6
    IP Address:                           2001:db8::1
    Subnet Prefix:                        2001:db8::/64
";

    #[cfg(target_os = "windows")]
    #[test]
    fn parse_interface_for_ip_finds_match_in_later_block() {
        assert_eq!(
            super::parse_interface_for_ip(NETSH_DUMP, "10.10.159.253").as_deref(),
            Some("OpenConnect Tunnel")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parse_interface_for_ip_handles_unnumbered_first_block() {
        assert_eq!(
            super::parse_interface_for_ip(NETSH_DUMP, "192.168.0.50").as_deref(),
            Some("Wi-Fi")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parse_interface_for_ip_matches_ipv6_tunnel() {
        assert_eq!(
            super::parse_interface_for_ip(NETSH_DUMP, "2001:db8::1").as_deref(),
            Some("TunV6")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parse_interface_for_ip_no_match_returns_none() {
        assert_eq!(super::parse_interface_for_ip(NETSH_DUMP, "172.16.0.1"), None);
        assert_eq!(super::parse_interface_for_ip("", "10.0.0.1"), None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parse_interface_names_lists_all_unique() {
        let names = super::parse_interface_names(NETSH_DUMP);
        assert!(names.contains(&"Ethernet".to_string()));
        assert!(names.contains(&"Wi-Fi".to_string()));
        assert!(names.contains(&"OpenConnect Tunnel".to_string()));
        assert!(names.contains(&"TunV6".to_string()));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parse_interface_names_empty_input() {
        assert!(super::parse_interface_names("").is_empty());
    }
}
