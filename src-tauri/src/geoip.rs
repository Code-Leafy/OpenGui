//! Lightweight GeoIP country detection for VPN server hostnames.
//!
//! Given a server URL/host, this resolves the host to an IP address via the
//! system resolver and asks a free GeoIP HTTP API (`ip-api.com`) for the ISO
//! 3166-1 alpha-2 country code. The result drives the profile's flag icon.
//!
//! Design constraints (kept deliberately dependency-free):
//! * No `reqwest`/TLS stack is pulled in (it was removed for security earlier).
//!   The GeoIP endpoint is queried over plain HTTP with a hand-rolled HTTP/1.1
//!   `GET` on a `std::net::TcpStream`, with strict timeouts.
//! * The reply is parsed with `serde_json`, which is already a dependency.
//! * All work is blocking and must be run via `spawn_blocking` from async code.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Network timeouts. Country detection is best-effort and must never stall the
/// UI, so these are intentionally short.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const IO_TIMEOUT: Duration = Duration::from_secs(4);

/// GeoIP API host (plain HTTP; the free tier does not offer HTTPS without a key).
const GEOIP_HOST: &str = "ip-api.com";

/// Extract the bare hostname from a user-supplied server string.
///
/// Accepts `https://host/path`, `host:port`, or a bare `host`. Returns `None`
/// if no plausible host can be isolated.
pub fn host_from_server(server: &str) -> Option<String> {
    let s = server.trim();
    if s.is_empty() {
        return None;
    }
    // Strip scheme.
    let after_scheme = match s.find("://") {
        Some(i) => &s[i + 3..],
        None => s,
    };
    // Strip userinfo (user:pass@host) — should never be present, defensively.
    let after_user = match after_scheme.rfind('@') {
        Some(i) => &after_scheme[i + 1..],
        None => after_scheme,
    };
    // Cut at first '/', '?' or '#'.
    let host_port = after_user
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_user);
    // Strip a trailing :port (but keep IPv6 bracket form intact).
    let host = if host_port.starts_with('[') {
        // [::1]:443 -> [::1]
        match host_port.find(']') {
            Some(i) => &host_port[..=i],
            None => host_port,
        }
    } else {
        match host_port.rfind(':') {
            Some(i) => &host_port[..i],
            None => host_port,
        }
    };
    let host = host.trim().trim_matches(['[', ']']);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Resolve `host` to its first IP address (v4 or v6) using the system resolver.
fn resolve_ip(host: &str) -> Option<std::net::IpAddr> {
    // `to_socket_addrs` needs a port; 443 is arbitrary and unused.
    (host, 443u16)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .map(|sa| sa.ip())
}

/// Query the GeoIP API for the country code of `ip` over plain HTTP.
///
/// Returns the lowercase ISO alpha-2 code (e.g. `"de"`) on success.
fn lookup_country_code(ip: std::net::IpAddr) -> Option<String> {
    // Resolve the API host itself and connect with a timeout.
    let api_addr = (GEOIP_HOST, 80u16)
        .to_socket_addrs()
        .ok()?
        .next()?;
    let mut stream = TcpStream::connect_timeout(&api_addr, CONNECT_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok()?;

    // Only request the single field we need to keep the response tiny.
    let request = format!(
        "GET /json/{ip}?fields=status,countryCode HTTP/1.1\r\n\
         Host: {GEOIP_HOST}\r\n\
         User-Agent: OpenConnectGUI\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;

    // Read the whole (small) response. Cap the buffer defensively.
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 8192 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let text = String::from_utf8_lossy(&buf);
    // Split headers from body at the blank line.
    let body = text.split("\r\n\r\n").nth(1)?;
    // The body may be chunked; take the substring from the first '{' to last '}'.
    let start = body.find('{')?;
    let end = body.rfind('}')?;
    let json = &body[start..=end];
    let parsed: serde_json::Value = serde_json::from_str(json).ok()?;

    if parsed.get("status").and_then(|s| s.as_str()) != Some("success") {
        return None;
    }
    let cc = parsed.get("countryCode").and_then(|c| c.as_str())?;
    let cc = cc.trim();
    // Sanity: alpha-2 only.
    if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_alphabetic()) {
        Some(cc.to_ascii_lowercase())
    } else {
        None
    }
}

/// Detect the ISO alpha-2 country code for a server URL/host (blocking).
///
/// Returns `None` if the host cannot be parsed, resolved, or geolocated. Callers
/// treat `None` as "unknown" and fall back to a generic flag.
pub fn detect_country(server: &str) -> Option<String> {
    let host = host_from_server(server)?;
    let ip = resolve_ip(&host)?;
    lookup_country_code(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_from_https_url() {
        assert_eq!(
            host_from_server("https://vpn.example.com/path?x=1"),
            Some("vpn.example.com".to_string())
        );
    }

    #[test]
    fn host_from_url_with_port() {
        assert_eq!(
            host_from_server("https://vpn.example.com:8443"),
            Some("vpn.example.com".to_string())
        );
    }

    #[test]
    fn host_from_bare_host() {
        assert_eq!(
            host_from_server("vpn.example.com"),
            Some("vpn.example.com".to_string())
        );
    }

    #[test]
    fn host_from_ipv6_bracket() {
        assert_eq!(
            host_from_server("https://[2001:db8::1]:443/x"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn host_strips_userinfo() {
        assert_eq!(
            host_from_server("https://user:pass@vpn.example.com"),
            Some("vpn.example.com".to_string())
        );
    }

    #[test]
    fn host_from_empty_is_none() {
        assert_eq!(host_from_server(""), None);
        assert_eq!(host_from_server("   "), None);
    }
}
