# OpenConnect GUI — Bridge API

**Version:** `1.1.0` &nbsp;•&nbsp; **Status:** stable &nbsp;•&nbsp; **Audience:** frontend developers

This document is the contract between **any** frontend and the OpenConnect
backend. It is complete enough for a junior developer to build an alternative UI
(web, CLI, mobile shell) without reading the Rust source.

---

## 1. Architecture

```
┌──────────────────────────────────────────────┐
│ Frontend  (JS today; web/CLI/mobile possible) │
│   invoke(command)  ───►                        │
│                    ◄───  events (6 channels)   │
└───────────────┬────────────────▲──────────────┘
                │ Tauri IPC       │ Tauri events
┌───────────────▼────────────────┴──────────────┐
│ commands.rs  — thin adapters + input validation│
├────────────────────────────────────────────────┤
│ bridge.rs    — UI-AGNOSTIC CONTRACT             │
│   • BridgeEvent  (what the frontend receives)   │
│   • EventSink    (how it's delivered)           │
│   • BridgeInfo   (version negotiation)          │
├────────────────────────────────────────────────┤
│ process.rs (child lifecycle) · parser.rs        │
│ config.rs · credentials.rs · logging.rs         │
│ killswitch.rs · netshield.rs                    │
│ process.rs                                      │
└────────────────────────────────────────────────┘
                │ spawn / stdin / stdout+stderr
                ▼
          openconnect.exe
```

The **bridge module** (`src-tauri/src/bridge.rs`) contains no Tauri types. To
port to a different frontend you implement one trait (`EventSink`) and reuse the
same command names and event payloads documented here.

- `EventSink` — delivers a `BridgeEvent` to your transport. The Tauri build uses
  `TauriEventSink` (in `commands.rs`); a web build would push over a WebSocket.
- `BridgeEvent` — the canonical backend → frontend message; each variant has a
  stable **channel name** and **JSON payload** (below).

---

## 2. Commands (frontend → backend)

All commands are invoked through Tauri's `invoke(name, args)`. Errors are
returned as human-readable strings (already sanitised — see §6).

| Command | Args | Returns | Purpose |
|---|---|---|---|
| `bridge_version` | — | `BridgeInfo` | Negotiate API compatibility at startup |
| `openconnect_version` | — | `string` | Version string of the bundled openconnect engine |
| `list_profiles` | — | `ConnectionProfile[]` | Load all saved profiles |
| `add_profile` | `{ profile }` | `void` | Create a profile |
| `update_profile` | `{ profile }` | `void` | Replace a profile by `id` |
| `delete_profile` | `{ id }` | `void` | Delete profile + its stored credential |
| `store_credential` | `{ profileId, username, password }` | `void` | Save password to OS credential store |
| `connect` | `{ profileId }` | `void` | Start a VPN connection |
| `submit_mfa` | `{ code }` | `void` | Provide password/MFA/TOTP code |
| `disconnect` | — | `void` | Tear down the current connection |
| `detect_country` | `{ server }` | `string \| null` | Resolve the server host's country via GeoIP; returns a lowercase ISO 3166-1 alpha-2 code (e.g. `"de"`) or `null` when it can't be determined. Used by the UI to pick the profile flag icon. |
| `get_connection_state` | — | `ConnectionState` | Read current state (for cold start) |
| `is_elevated` | — | `bool` | Whether the app is running elevated (admin); needed before kill-switch |
| `get_settings` | — | `AppSettings` | Read persisted global settings (tool toggles + preferences) |
| `set_settings` | `{ settings }` | `void` | Persist the full global settings object |
| `set_netshield` | `{ enabled }` | `AppSettings` | Toggle the NetShield master switch and persist it |
| `set_netshield_config` | `{ config }` | `AppSettings` | Update the NetShield sub-feature toggles (`block_malware` / `secure_connection` / `block_ads`) and persist them |
| `set_killswitch` | `{ enabled }` | `AppSettings` | Toggle the global kill-switch and persist it |
| `set_auto_retry` | `{ enabled }` | `AppSettings` | Toggle Auto Retry and persist it |

### Data types

```jsonc
// ConnectionProfile
{
  "id":          "550e8400-e29b-41d4-a716-446655440000", // UUID v4 (required)
  "name":        "Corp VPN",                              // 1–128 chars, no control chars
  "server":      "https://vpn.example.com",               // http(s)://, ≤2048, no CR/LF/NUL
  "username":    "alice",                                  // 1–256 chars, no control chars
  "server_cert": "pin-sha256:hV5X…=", // optional; omit if unset
  "kill_switch": false,               // optional (default false); block all
                                      // non-tunnel traffic while connected

  // ── OpenConnect option coverage (all optional; sent on add/update) ────────
  // Enums are validated server-side:
  //   protocol  : anyconnect | nc | gp | pulse | f5 | fortinet | array
  //   token_mode: rsa | totp | hotp | oidc
  //   os_override (--os): linux | linux-64 | win | mac-intel | android | apple-ios
  "protocol": "gp", "authgroup": "Employees", "usergroup": "/portal",
  "certificate": "C:/certs/c.pem", "sslkey": "C:/certs/c.key",
  "mca_certificate": null, "mca_key": null,
  "token_mode": "totp", "external_browser": "C:/…/chrome.exe",
  "no_external_auth": false,
  "proxy": "http://proxy:8080", "proxy_auth": "basic,ntlm", "no_proxy": false,
  "resolve": "vpn.example.com:203.0.113.5", "sni": "front.example.com",
  "cafile": "C:/certs/ca.pem", "no_system_trust": false,
  "allow_insecure_crypto": false, "dtls_ciphers": null,
  "base_mtu": 1400, "no_dtls": false, "pfs": false,
  "dtls_local_port": 4443, "force_dpd": 30, "passtos": false,
  "queue_len": 10, "disable_ipv6": false, "deflate": false,
  "useragent": null, "version_string": null, "os_override": "win",
  "local_hostname": null

  // ── Secret fields (INPUT ONLY): sent on add/update, immediately moved to
  //    Windows Credential Manager and NEVER written to profiles.json or
  //    returned by list_profiles. Fetched from Credential Manager at connect:
  //      totp_secret      -> openconnect-gui/<id>/totp
  //      token_secret     -> openconnect-gui/<id>/token-secret
  //      key_password     -> openconnect-gui/<id>/key-password
  //      mca_key_password -> openconnect-gui/<id>/mca-key-password
}
```

```jsonc
// ConnectionState — either a bare string or a tagged object:
"Disconnected" | "Connecting" | "Connected" | "Disconnecting"
{ "Failed": "human readable reason" }
```

```jsonc
// BridgeInfo (from bridge_version)
{
  "version": "1.1.0",
  "channels": [
    "openconnect://state",
    "openconnect://event",
    "openconnect://events",
    "openconnect://server-cert",
    "openconnect://mfa-required",
    "openconnect://tunnel-info"
  ]
}
```

---

## 3. Events (backend → frontend)

Subscribe with Tauri's `listen(channel, handler)`. `event.payload` shapes:

| Channel | Payload | Meaning |
|---|---|---|
| `openconnect://state` | `ConnectionState` | Lifecycle transition |
| `openconnect://event` | `{ timestamp, level, message }` | One parsed log line (`level`: `INFO`/`WARN`/`ERROR`/`DEBUG`) — single-event contract |
| `openconnect://events` | `[{ timestamp, level, message }, …]` | A **batch** of parsed log lines coalesced into one event (runtime emitter uses this to avoid one IPC event per line during log storms) |
| `openconnect://server-cert` | `string` (`pin-sha256:…`) | Server certificate pin detected — offer the user to save it |
| `openconnect://mfa-required` | `string` (profile id) | Prompt the user for a password/MFA/TOTP code, then call `submit_mfa` |
| `openconnect://tunnel-info` | `TunnelInfo` (`{ "ip": string, "gateway": string \| null }`) | Tunnel's assigned local address (and optional gateway) once the connection comes up — consumed by NetShield (locate tunnel adapter for DNS) |

**Ordering guarantee:** state changes are always emitted *after* the log line
that triggered them, and a terminal `Disconnected`/`Failed` is always the last
state event of a session. Consecutive identical states are coalesced.

---

## 4. Sequence diagrams

### Connect (stored credential + TOTP)
```
UI            connect(profileId)
  │  ── invoke ─────────────────────────►  backend
  │                                          load profile, read credential
  │                                          generate TOTP (if secret)
  │  ◄── event state: Connecting ──────────  spawn openconnect, write code→stdin
  │  ◄── event: "SSL negotiation…" ────────
  │  ◄── event state: Connecting ──────────
  │  ◄── event: "Connected as 10.0.0.5" ───
  │  ◄── event state: Connected ───────────  tunnel up
```

### Connect (no stored credential → MFA prompt)
```
UI            connect(profileId)
  │  ── invoke ────────────────────────►  backend  (credential missing)
  │  ◄── event mfa-required: profileId ──   pending connection stored
  │  show code entry
  │  ── submit_mfa(code) ──────────────►  backend  (stores cred, spawns proc)
  │  ◄── event state: Connecting ────────
  │  ◄── event state: Connected ─────────
```

### Disconnect
```
UI            disconnect()
  │  ── invoke ────────────────────────►  backend
  │  ◄── event state: Disconnecting ─────   kill process tree
  │  ◄── event state: Disconnected ──────   (always delivered — no stuck UI)
```

### Trust-on-first-use (unpinned server)
```
UI            connect(profileId)         (server_cert = null)
  │  ◄── event state: Connecting ────────  openconnect runs with --non-inter
  │  ◄── event: "…use --servercert pin-sha256:…"   (cert NOT auto-trusted)
  │  ◄── event server-cert: pin-sha256:… ─  UI offers "save this pin"
  │  ◄── event state: Failed(cert) ──────
  │  user saves pin (update_profile) → reconnect → fully validated
```

---

## 5. Build a new frontend in <2 hours

1. Call `bridge_version`; verify the major version matches `1`.
2. `listen()` to all six channels from `BridgeInfo.channels`.
3. On startup call `get_connection_state` to render the initial state.
4. Render profiles from `list_profiles`; wire `add/update/delete_profile`.
5. Buttons: `connect({profileId})`, `disconnect()`.
6. On `openconnect://mfa-required`, show a code field and call
   `submit_mfa({code})`.
7. On `openconnect://server-cert`, offer to persist the pin via `update_profile`.
8. For the profile icon, call `detect_country({server})` and render
   `flags/4x3/<country_code>.svg` (fall back to `flags/4x3/xx.svg` when the code
   is missing/unknown). The lipis/flag-icons SVG set ships under `src/flags/`
   (`4x3` and `1x1` ratios). Store the returned code in `profile.country_code`.

The reference implementation is `src/app.js` (~300 lines).

---

## 6. Security notes for frontend authors

- **Never** put passwords/TOTP codes in logs, the DOM, or the command line —
  they travel over `store_credential`/`submit_mfa` and are written to the child
  via stdin only.
- Certificate verification is **never disabled**. Unpinned servers surface a
  `server-cert` event for explicit user consent (trust-on-first-use).
- Backend error strings are sanitised: hostnames, file paths, and OS codes are
  stripped before reaching the frontend. Do not attempt to parse them.
- Passwords are stored in the OS credential store, not in `profiles.json`.

---

## 7. Versioning policy

`BRIDGE_API_VERSION` is semver.

- **Patch** — docs/impl fixes, no contract change.
- **Minor** — new optional event or command; existing ones unchanged.
- **Major** — any channel rename or payload-shape change.

Frontends should check the major version at startup and refuse to run against an
incompatible backend.
