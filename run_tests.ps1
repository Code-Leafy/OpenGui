$env:RUSTUP_HOME = "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\.toolchain\rustup"
$env:CARGO_HOME  = "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\.toolchain\cargo"
$env:Path = "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\.toolchain\cargo\bin;" + $env:Path
Set-Location "C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\src-tauri"

# The test binaries link Tauri/WebView2 and load WebView2Loader.dll at startup.
# cargo runs them from target\debug\deps, so the loader must sit next to them or
# the process aborts with STATUS_ENTRYPOINT_NOT_FOUND before any test runs.
Write-Host "=== building test binaries ===" -ForegroundColor Cyan
cargo test --no-run 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "TEST_EXIT:$LASTEXITCODE"; exit $LASTEXITCODE }

$deps = "target\debug\deps"
$loader = Get-ChildItem "target\debug\build\webview2-com-sys-*\out\x64\WebView2Loader.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($loader) {
    Copy-Item $loader.FullName (Join-Path $deps "WebView2Loader.dll") -Force
    Write-Host "Copied WebView2Loader.dll into $deps"
} else {
    Write-Host "WARNING: WebView2Loader.dll not found; tests may fail to start" -ForegroundColor Yellow
}

Write-Host "=== cargo test ===" -ForegroundColor Cyan
# The `openconnect-gui` binary embeds a Windows manifest requesting
# administrator elevation (for the firewall kill-switch). cargo cannot launch
# that test binary unelevated (OS error 740), and it contains no tests anyway,
# so we run the library tests and the integration tests explicitly and skip the
# elevated bin. --lib covers all unit tests in src/*.rs; --test runs each
# integration test crate.
cargo test --lib 2>&1
$libExit = $LASTEXITCODE
cargo test --test bridge_integration 2>&1
$itExit = $LASTEXITCODE
$exit = if ($libExit -ne 0) { $libExit } elseif ($itExit -ne 0) { $itExit } else { 0 }
Write-Host "TEST_EXIT:$exit"
