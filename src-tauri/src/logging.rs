//! Lightweight, dependency-free structured logging.
//!
//! Verbosity is controlled by the `OPENCONNECT_GUI_LOG` environment variable,
//! read once on first use:
//!
//! | Value              | Emits            |
//! |--------------------|------------------|
//! | `off`              | nothing          |
//! | `error`            | ERROR            |
//! | `warn`             | ERROR, WARN      |
//! | `info` *(default)* | ERROR, WARN, INFO|
//! | `debug`            | everything       |
//!
//! Records are written to **stderr** (never stdout, which is reserved for the
//! openconnect child pipe) in the form `LEVEL [target] message`.
//!
//! # Security
//!
//! Log call sites must never pass secrets (passwords, TOTP codes, full
//! credentials). This module performs no redaction of its own; callers are
//! responsible for logging only non-sensitive data.

use std::sync::atomic::{AtomicU8, Ordering};

/// Log severity levels in ascending verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// No output.
    Off = 0,
    /// Unrecoverable or user-visible failures.
    Error = 1,
    /// Recoverable problems and suspicious conditions.
    Warn = 2,
    /// High-level lifecycle information.
    Info = 3,
    /// Verbose diagnostic detail.
    Debug = 4,
}

impl Level {
    /// Parse a case-insensitive level name; unknown values fall back to `Info`.
    pub fn from_str_or_default(s: &str) -> Level {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "silent" => Level::Off,
            "error" => Level::Error,
            "warn" | "warning" => Level::Warn,
            "info" => Level::Info,
            "debug" | "trace" | "verbose" => Level::Debug,
            _ => Level::Info,
        }
    }

    /// The uppercase label used in log output.
    pub fn label(self) -> &'static str {
        match self {
            Level::Off => "OFF",
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
        }
    }
}

/// Sentinel meaning "verbosity not yet resolved from the environment".
const UNINIT: u8 = u8::MAX;
static CURRENT: AtomicU8 = AtomicU8::new(UNINIT);

/// Environment variable that configures verbosity.
pub const ENV_VAR: &str = "OPENCONNECT_GUI_LOG";

/// Return the active maximum level, resolving it from the environment on first
/// call. Subsequent calls are a single relaxed atomic load.
pub fn current_level() -> Level {
    let raw = CURRENT.load(Ordering::Relaxed);
    if raw != UNINIT {
        return level_from_u8(raw);
    }
    let resolved = std::env::var(ENV_VAR)
        .map(|v| Level::from_str_or_default(&v))
        .unwrap_or(Level::Info);
    CURRENT.store(resolved as u8, Ordering::Relaxed);
    resolved
}

/// Override the active level at runtime (used by tests and by an optional
/// runtime setting). Takes precedence over the environment.
pub fn set_level(level: Level) {
    CURRENT.store(level as u8, Ordering::Relaxed);
}

fn level_from_u8(v: u8) -> Level {
    match v {
        0 => Level::Off,
        1 => Level::Error,
        2 => Level::Warn,
        3 => Level::Info,
        _ => Level::Debug,
    }
}

/// Whether a message at `level` would currently be emitted.
pub fn enabled(level: Level) -> bool {
    level != Level::Off && level <= current_level()
}

/// Write a single record to stderr if `level` is enabled. Prefer the
/// [`log_error!`], [`log_warn!`], [`log_info!`], and [`log_debug!`] macros.
pub fn log(level: Level, target: &str, message: &str) {
    if enabled(level) {
        eprintln!("{} [{}] {}", level.label(), target, message);
    }
}

/// Log at ERROR level: `log_error!(target, "fmt", args...)`.
#[macro_export]
macro_rules! log_error {
    ($target:expr, $($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Error, $target, &format!($($arg)*))
    };
}

/// Log at WARN level.
#[macro_export]
macro_rules! log_warn {
    ($target:expr, $($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Warn, $target, &format!($($arg)*))
    };
}

/// Log at INFO level.
#[macro_export]
macro_rules! log_info {
    ($target:expr, $($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Info, $target, &format!($($arg)*))
    };
}

/// Log at DEBUG level.
#[macro_export]
macro_rules! log_debug {
    ($target:expr, $($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Debug, $target, &format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_levels() {
        assert_eq!(Level::from_str_or_default("off"), Level::Off);
        assert_eq!(Level::from_str_or_default("ERROR"), Level::Error);
        assert_eq!(Level::from_str_or_default("Warn"), Level::Warn);
        assert_eq!(Level::from_str_or_default("info"), Level::Info);
        assert_eq!(Level::from_str_or_default("debug"), Level::Debug);
    }

    #[test]
    fn parse_unknown_defaults_to_info() {
        assert_eq!(Level::from_str_or_default("bogus"), Level::Info);
        assert_eq!(Level::from_str_or_default(""), Level::Info);
    }

    #[test]
    fn level_ordering_is_ascending() {
        assert!(Level::Off < Level::Error);
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
    }

    #[test]
    fn enabled_respects_threshold() {
        set_level(Level::Warn);
        assert!(enabled(Level::Error));
        assert!(enabled(Level::Warn));
        assert!(!enabled(Level::Info));
        assert!(!enabled(Level::Debug));
    }

    #[test]
    fn off_disables_everything() {
        set_level(Level::Off);
        assert!(!enabled(Level::Error));
        assert!(!enabled(Level::Debug));
        // Restore a sane default so later tests are not affected.
        set_level(Level::Info);
    }

    #[test]
    fn labels_are_uppercase() {
        assert_eq!(Level::Error.label(), "ERROR");
        assert_eq!(Level::Debug.label(), "DEBUG");
    }

    #[test]
    fn set_and_get_roundtrip() {
        set_level(Level::Debug);
        assert_eq!(current_level(), Level::Debug);
        set_level(Level::Info);
        assert_eq!(current_level(), Level::Info);
    }
}
