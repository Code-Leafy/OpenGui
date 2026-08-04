//! Real network telemetry for the tunnel adapter.
//!
//! Everything here reflects *actual* system state — no synthetic values. Two
//! pieces of data are exposed:
//!
//! * [`get_adapter_stats`] — cumulative bytes received/sent on the wintun
//!   adapter that owns the tunnel IP, read from Windows' per-adapter counters.
//!   The frontend turns successive samples into throughput (Δbytes / Δt).
//! * [`ping_host`] — a real ICMP round-trip time to a host, used for the
//!   latency display. The frontend pings the tunnel gateway / a well-known
//!   host through the tunnel.

use serde::Serialize;

/// Cumulative byte counters for a network adapter at a point in time.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct AdapterStats {
    /// Total bytes received on the adapter since it came up.
    pub rx_bytes: u64,
    /// Total bytes sent on the adapter since it came up.
    pub tx_bytes: u64,
}

/// Read the wintun adapter's cumulative RX/TX byte counters.
///
/// `tunnel_ip` is the address openconnect assigned; it is used to locate the
/// matching adapter so counters for the correct interface are returned.
///
/// # Errors
///
/// Returns an error string if the adapter cannot be found or its statistics
/// cannot be read.
#[cfg(target_os = "windows")]
pub fn get_adapter_stats(tunnel_ip: &str) -> Result<AdapterStats, String> {
    use crate::types::system32_exe;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    if tunnel_ip.trim().is_empty() {
        return Err("no tunnel IP".to_string());
    }

    // Resolve the adapter that owns the tunnel IP, then read its cumulative
    // byte counters. The tunnel is often a *hidden* virtual (wintun/TAP)
    // adapter, so we pass -IncludeHidden and fall back to the raw perf counter
    // (keyed by InterfaceDescription), which reports totals for every adapter
    // including virtual ones. Done in a single PowerShell invocation.
    let script = format!(
        "$ipObj = Get-NetIPAddress -IPAddress '{}' -ErrorAction SilentlyContinue | Select-Object -First 1; \
         if (-not $ipObj) {{ exit 2 }}; \
         $ad = Get-NetAdapter -InterfaceIndex $ipObj.InterfaceIndex -IncludeHidden -ErrorAction SilentlyContinue | Select-Object -First 1; \
         if (-not $ad) {{ exit 3 }}; \
         $s = Get-NetAdapterStatistics -Name $ad.Name -IncludeHidden -ErrorAction SilentlyContinue | Select-Object -First 1; \
         if ($s -and ($s.ReceivedBytes -gt 0 -or $s.SentBytes -gt 0)) {{ \
            Write-Output ('{{0}} {{1}}' -f $s.ReceivedBytes, $s.SentBytes); exit 0 }}; \
         $safe = ($ad.InterfaceDescription -replace '[\\\\/\\(\\)#]','_') -replace '\\[','[' -replace '\\]',']'; \
         $p = Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue | \
              Where-Object {{ $_.Name -eq $safe }} | Select-Object -First 1; \
         if ($p) {{ Write-Output ('{{0}} {{1}}' -f $p.BytesReceivedPersec, $p.BytesSentPersec); exit 0 }}; \
         if ($s) {{ Write-Output ('{{0}} {{1}}' -f $s.ReceivedBytes, $s.SentBytes); exit 0 }}; \
         exit 4",
        sanitize_ip(tunnel_ip)?
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
        .map_err(|e| format!("failed to run powershell: {e}"))?;

    if !out.status.success() {
        return Err(format!(
            "adapter stats unavailable (exit {})",
            out.status.code().unwrap_or(-1)
        ));
    }

    let text = String::from_utf8_lossy(&out.stdout);
    parse_adapter_stats(&text)
}

/// Pure parser for the `"<rx> <tx>"` line emitted by the stats PowerShell.
///
/// Factored out so it can be unit-tested without invoking PowerShell.
pub fn parse_adapter_stats(text: &str) -> Result<AdapterStats, String> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or_else(|| "empty stats output".to_string())?;

    let mut parts = line.split_whitespace();
    let rx = parts
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| format!("could not parse rx bytes from '{line}'"))?;
    let tx = parts
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| format!("could not parse tx bytes from '{line}'"))?;

    Ok(AdapterStats {
        rx_bytes: rx,
        tx_bytes: tx,
    })
}

/// Measure the ICMP round-trip time to `host` in milliseconds.
///
/// Uses the system `ping` with a single echo and a short timeout so the UI
/// stays responsive. Returns the RTT in milliseconds.
///
/// # Errors
///
/// Returns an error string if the host is unreachable, the request times out,
/// or the reply cannot be parsed.
#[cfg(target_os = "windows")]
pub fn ping_host(host: &str) -> Result<u32, String> {
    use crate::types::system32_exe;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let host = sanitize_host(host)?;

    let out = Command::new(system32_exe("ping.exe"))
        .args(["-n", "1", "-w", "2000", &host])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("failed to run ping: {e}"))?;

    let text = String::from_utf8_lossy(&out.stdout);
    parse_ping_ms(&text).ok_or_else(|| "no reply".to_string())
}

/// Pure parser for `ping` output. Returns the RTT in ms if a reply was received.
///
/// Handles both `time=12ms` and `time<1ms` (the latter maps to 0ms), and is
/// tolerant of localization by matching the `time` token rather than full
/// phrases where possible.
pub fn parse_ping_ms(text: &str) -> Option<u32> {
    for raw in text.lines() {
        let line = raw.trim();
        // Find a `time` / `time=` / `time<` token.
        let Some(idx) = line.find("time") else {
            continue;
        };
        let after = &line[idx + 4..];
        let after = after.trim_start();
        if let Some(rest) = after.strip_prefix('<') {
            // "time<1ms" — sub-millisecond, report 0.
            if rest.trim_start().starts_with(|c: char| c.is_ascii_digit()) {
                return Some(0);
            }
        }
        if let Some(rest) = after.strip_prefix('=') {
            let digits: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(ms) = digits.parse::<u32>() {
                return Some(ms);
            }
        }
    }
    None
}

/// Reject anything that isn't a bare IPv4/IPv6 literal so it can't be abused as
/// a PowerShell injection vector.
#[cfg(target_os = "windows")]
fn sanitize_ip(ip: &str) -> Result<String, String> {
    let ip = ip.split('/').next().unwrap_or(ip).trim();
    ip.parse::<std::net::IpAddr>()
        .map(|p| p.to_string())
        .map_err(|_| format!("invalid IP: {ip}"))
}

/// Restrict a ping target to a hostname/IP with no shell-significant chars.
#[cfg(target_os = "windows")]
fn sanitize_host(host: &str) -> Result<String, String> {
    let host = host.trim().trim_start_matches("https://").trim_start_matches("http://");
    let host = host.split('/').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    if host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
    {
        Ok(host.to_string())
    } else {
        Err(format!("invalid host: {host}"))
    }
}

// Non-Windows stubs so the crate still builds elsewhere (dev on other OSes).
#[cfg(not(target_os = "windows"))]
pub fn get_adapter_stats(_tunnel_ip: &str) -> Result<AdapterStats, String> {
    Err("adapter stats only available on Windows".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn ping_host(_host: &str) -> Result<u32, String> {
    Err("ping only available on Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stats_basic() {
        let s = parse_adapter_stats("123456 7890\n").unwrap();
        assert_eq!(s.rx_bytes, 123456);
        assert_eq!(s.tx_bytes, 7890);
    }

    #[test]
    fn parse_stats_skips_blank_lines() {
        let s = parse_adapter_stats("\n\n  42 24 \n").unwrap();
        assert_eq!(s.rx_bytes, 42);
        assert_eq!(s.tx_bytes, 24);
    }

    #[test]
    fn parse_stats_rejects_garbage() {
        assert!(parse_adapter_stats("not numbers here").is_err());
        assert!(parse_adapter_stats("").is_err());
        assert!(parse_adapter_stats("100").is_err());
    }

    #[test]
    fn parse_ping_equals() {
        let out = "Reply from 8.8.8.8: bytes=32 time=14ms TTL=115";
        assert_eq!(parse_ping_ms(out), Some(14));
    }

    #[test]
    fn parse_ping_submillisecond() {
        let out = "Reply from 10.0.0.1: bytes=32 time<1ms TTL=64";
        assert_eq!(parse_ping_ms(out), Some(0));
    }

    #[test]
    fn parse_ping_timeout() {
        let out = "Request timed out.";
        assert_eq!(parse_ping_ms(out), None);
    }

    #[test]
    fn parse_ping_three_digit() {
        let out = "Reply from 1.1.1.1: bytes=32 time=142ms TTL=55";
        assert_eq!(parse_ping_ms(out), Some(142));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sanitize_ip_rejects_injection() {
        assert!(sanitize_ip("'; Remove-Item C:\\ #").is_err());
        assert_eq!(sanitize_ip("10.10.0.5").unwrap(), "10.10.0.5");
        assert_eq!(sanitize_ip("10.10.0.5/24").unwrap(), "10.10.0.5");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sanitize_host_strips_scheme() {
        assert_eq!(sanitize_host("https://vpn.example.com/foo").unwrap(), "vpn.example.com");
        assert_eq!(sanitize_host("vpn.example.com:443").unwrap(), "vpn.example.com");
        assert!(sanitize_host("bad;rm -rf").is_err());
    }
}
