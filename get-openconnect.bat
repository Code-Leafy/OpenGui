@echo off
setlocal

set MSYS2_BASH=C:\msys64\usr\bin\bash.exe
set SRC_DIR=C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\openconnect-master
set OUT_DIR=%~dp0.toolchain\openconnect
set MINGW_BIN=C:\msys64\mingw64\bin
set VPNC_SCRIPT_URL=https://gitlab.com/openconnect/vpnc-scripts/raw/master/vpnc-script-win.js
set VPNC_SCRIPT_DIR=C:\msys64\usr\share\vpnc-scripts
set VPNC_SCRIPT=%VPNC_SCRIPT_DIR%\vpnc-script-win.js

if not exist "%MSYS2_BASH%" ( echo ERROR: MSYS2 not found at C:\msys64 & exit /b 1 )

echo [0/4] Ensuring openconnect source is present...
if not exist "%SRC_DIR%\configure.ac" (
    echo       Cloning openconnect source into openconnect-master...
    git clone --depth 1 https://gitlab.com/openconnect/openconnect.git "%SRC_DIR%"
    if errorlevel 1 ( echo ERROR: git clone failed. Install git or clone https://gitlab.com/openconnect/openconnect.git into openconnect-master manually. & exit /b 1 )
) else (
    echo       Source already present, skipping.
)

echo [1/4] Downloading vpnc-script-win.js...
if not exist "%VPNC_SCRIPT_DIR%" mkdir "%VPNC_SCRIPT_DIR%"
if not exist "%VPNC_SCRIPT%" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri '%VPNC_SCRIPT_URL%' -OutFile '%VPNC_SCRIPT%' -UseBasicParsing"
    if errorlevel 1 ( echo ERROR: Failed to download vpnc-script-win.js & exit /b 1 )
    echo       Done.
) else (
    echo       Already present, skipping.
)

echo [2/4] Installing build dependencies...
"%MSYS2_BASH%" -lc "pacman -Sy --noconfirm autoconf automake libtool pkg-config make jq mingw-w64-x86_64-gcc mingw-w64-x86_64-gnutls mingw-w64-x86_64-libxml2 mingw-w64-x86_64-zlib mingw-w64-x86_64-stoken"
if errorlevel 1 ( echo ERROR: pacman failed & exit /b 1 )

echo [3/4] Building openconnect from source...
"%MSYS2_BASH%" -lc "export PATH=/mingw64/bin:/usr/bin && export PKG_CONFIG_PATH=/mingw64/lib/pkgconfig && cd /c/Users/artin/OneDrive/Documents/Projects/OpenConnect/openconnect-master && autoreconf -iv && ./configure --host=x86_64-w64-mingw32 --with-gnutls --without-openssl --without-oath --without-stoken --disable-nls --with-vpnc-script=/usr/share/vpnc-scripts/vpnc-script-win.js && make -j4 openconnect.exe"
if errorlevel 1 ( echo ERROR: Build failed & exit /b 1 )

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

set OC_EXE=
if exist "%SRC_DIR%\.libs\openconnect.exe" set OC_EXE=%SRC_DIR%\.libs\openconnect.exe
if exist "%SRC_DIR%\openconnect.exe" set OC_EXE=%SRC_DIR%\openconnect.exe
if "%OC_EXE%"=="" ( echo ERROR: openconnect.exe not found after build & exit /b 1 )

echo [4/4] Copying openconnect.exe and DLLs...
copy /y "%OC_EXE%" "%OUT_DIR%\openconnect.exe"
if errorlevel 1 ( echo ERROR: Copy failed & exit /b 1 )

for %%D in (
    libgnutls-*.dll
    libhogweed-*.dll
    libnettle-*.dll
    libgmp-*.dll
    libp11-kit-*.dll
    libtasn1-*.dll
    libunistring-*.dll
    libffi-*.dll
    libxml2-*.dll
    libgcc_s_seh-*.dll
    libwinpthread-*.dll
    libstdc++-*.dll
    zlib1.dll
    libintl-*.dll
    libiconv-*.dll
    libbrotlicommon.dll
    libbrotlidec.dll
    libbrotlienc.dll
    libidn2-0.dll
    libzstd.dll
) do (
    if exist "%MINGW_BIN%\%%D" copy /y "%MINGW_BIN%\%%D" "%OUT_DIR%\" >nul
)

:: Copy libopenconnect-5.dll from the build output
if exist "%SRC_DIR%\.libs\libopenconnect-5.dll" copy /y "%SRC_DIR%\.libs\libopenconnect-5.dll" "%OUT_DIR%\" >nul

:: Copy wintun.dll (download separately from https://www.wintun.net/)
:: The build script does not download wintun automatically.
if not exist "%OUT_DIR%\wintun.dll" (
    echo WARNING: wintun.dll not found in %OUT_DIR%. Download from https://www.wintun.net/
)

echo.
echo Done. Testing openconnect.exe...
"%OUT_DIR%\openconnect.exe" --version
endlocal