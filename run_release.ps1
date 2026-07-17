$env:RUSTUP_HOME = "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\.toolchain\rustup"
$env:CARGO_HOME  = "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\.toolchain\cargo"
$env:Path = "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\.toolchain\cargo\bin;" + $env:Path
Set-Location "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\src-tauri"

Write-Host "=== cargo build --release ===" -ForegroundColor Cyan
cargo build --release 2>&1
Write-Host "RELEASE_EXIT:$LASTEXITCODE"
