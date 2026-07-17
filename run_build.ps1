$env:RUSTUP_HOME = "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\.toolchain\rustup"
$env:CARGO_HOME  = "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\.toolchain\cargo"
$env:Path = "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\.toolchain\cargo\bin;" + $env:Path
Set-Location "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\src-tauri"

Write-Host "=== cargo build ===" -ForegroundColor Cyan
cargo build
$buildExit = $LASTEXITCODE
Write-Host "cargo build exit: $buildExit"

Write-Host "`n=== cargo clippy ===" -ForegroundColor Cyan
cargo clippy -- -D warnings
$clippyExit = $LASTEXITCODE
Write-Host "cargo clippy exit: $clippyExit"

Write-Host "`n=== cargo test ===" -ForegroundColor Cyan
cargo test
$testExit = $LASTEXITCODE
Write-Host "cargo test exit: $testExit"

exit ($buildExit + $clippyExit + $testExit)
