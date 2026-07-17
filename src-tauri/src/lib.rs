#![deny(unsafe_code)]
#![warn(missing_docs)]

//! OpenConnect GUI library crate.
//!
//! This crate root re-exports all backend modules used by the Tauri application.

pub mod bridge;
pub mod commands;
pub mod config;
pub mod credentials;
pub mod geoip;
pub mod killswitch;
pub mod logging;
pub mod netshield;
pub mod parser;
pub mod process;
pub mod settings;
/// Shared data types used across all backend modules.
pub mod types;
/// Auto-update commands backed by `tauri-plugin-updater`.
pub mod updater;
