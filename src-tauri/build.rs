fn main() {
    // Embed a custom Windows application manifest that requests administrator
    // elevation at launch (needed for the firewall kill-switch) and declares
    // per-monitor DPI awareness. Must be configured before tauri_build::build().
    #[cfg(target_os = "windows")]
    {
        let manifest = std::fs::read_to_string("windows-app-manifest.xml")
            .expect("failed to read windows-app-manifest.xml");
        let attrs = tauri_build::WindowsAttributes::new().app_manifest(manifest);
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(attrs))
            .expect("failed to run tauri_build with custom manifest");
        println!("cargo:rerun-if-changed=windows-app-manifest.xml");
    }

    // Required by Tauri v2 — must be called before any other build logic.
    #[cfg(not(target_os = "windows"))]
    tauri_build::build();

    let path = std::path::Path::new("..\\.toolchain\\openconnect\\openconnect.exe");
    if !path.exists() {
        panic!(
            "openconnect.exe not found at .toolchain\\openconnect\\openconnect.exe. \
             Follow the MANUAL STEP in setup.bat output."
        );
    }
    println!("cargo:rerun-if-changed=../.toolchain/openconnect/openconnect.exe");
}
