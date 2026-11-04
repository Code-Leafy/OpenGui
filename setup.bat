@echo off
setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "TOOLCHAIN_DIR=%SCRIPT_DIR%.toolchain"
set "RUSTUP_HOME=%TOOLCHAIN_DIR%\rustup"
set "CARGO_HOME=%TOOLCHAIN_DIR%\cargo"
set "OPENCONNECT_DIR=%TOOLCHAIN_DIR%\openconnect"
set "RUSTUP_INIT=%TOOLCHAIN_DIR%\rustup-init.exe"
set "CARGO_BIN=%TOOLCHAIN_DIR%\cargo\bin\cargo.exe"
set "TAURI_BIN=%TOOLCHAIN_DIR%\cargo\bin\cargo-tauri.exe"

echo.
echo ============================================================
echo  OpenConnect GUI - Portable Toolchain Setup
echo ============================================================
echo.

echo [1/4] Creating .toolchain directories...
if not exist "%TOOLCHAIN_DIR%"       mkdir "%TOOLCHAIN_DIR%"
if not exist "%RUSTUP_HOME%"         mkdir "%RUSTUP_HOME%"
if not exist "%CARGO_HOME%"          mkdir "%CARGO_HOME%"
if not exist "%OPENCONNECT_DIR%"     mkdir "%OPENCONNECT_DIR%"
echo       Done.
echo.

echo [2/4] Downloading rustup-init.exe...
if exist "%RUSTUP_INIT%" (
    echo       rustup-init.exe already present, skipping download.
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile '%RUSTUP_INIT%' -UseBasicParsing"
    if !ERRORLEVEL! neq 0 (
        echo ERROR: Failed to download rustup-init.exe.
        exit /b 1
    )
    echo       Download complete.
)
echo.

echo [3/4] Installing Rust stable toolchain...
if exist "%CARGO_BIN%" (
    echo       Rust toolchain already installed, skipping.
) else (
    "%RUSTUP_INIT%" --default-toolchain stable-x86_64-pc-windows-msvc --default-host x86_64-pc-windows-msvc --no-modify-path -y
    if !ERRORLEVEL! neq 0 (
        echo ERROR: rustup-init.exe failed.
        exit /b 1
    )
    echo       Rust toolchain installed successfully.
)
echo.

echo [4/4] Installing tauri-cli (latest v2)...
if not exist "%CARGO_BIN%" (
    echo ERROR: cargo.exe not found. Rust installation may have failed.
    exit /b 1
)
if exist "%TAURI_BIN%" (
    echo       tauri-cli already installed, skipping.
) else (
    "%CARGO_BIN%" install tauri-cli
    if !ERRORLEVEL! neq 0 (
        echo ERROR: cargo install tauri-cli failed.
        exit /b 1
    )
    echo       tauri-cli installed successfully.
)
echo.

echo ============================================================
echo  MANUAL STEP REQUIRED
echo ============================================================
echo.
echo  Place openconnect.exe at:
echo    %OPENCONNECT_DIR%\openconnect.exe
echo.
echo  Then build with:
echo    .toolchain\cargo\bin\cargo.exe tauri build
echo ============================================================

endlocal
exit /b 0