@echo off
set RUSTUP_HOME=%~dp0.toolchain\rustup
set CARGO_HOME=%~dp0.toolchain\cargo
set PATH=%~dp0.toolchain\cargo\bin;%PATH%
cd /d "%~dp0"
cargo-tauri.exe dev
