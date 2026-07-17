#![deny(unsafe_code)]
#![warn(missing_docs)]
#![windows_subsystem = "windows"]

//! OpenConnect GUI — application entry point.
//!
//! Initialises the Tauri application, registers all backend commands,
//! sets up system-tray behaviour, and ensures the openconnect child
//! process is killed on exit.

use std::sync::Arc;
use openconnect_gui_lib::process::ProcessManager;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, RunEvent, WindowEvent,
};

/// Restore and focus the main window from the tray (handles the hidden and
/// minimised cases). `unminimize` is required before `show`/`set_focus`,
/// otherwise a window hidden while minimised comes back invisible.
fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn main() {
    // Resolve log verbosity from OPENCONNECT_GUI_LOG once at startup.
    let level = openconnect_gui_lib::logging::current_level();
    openconnect_gui_lib::log_info!("main", "starting OpenConnect GUI (log level {})", level.label());

    // Self-heal: clear any kill-switch firewall rules a previous crash may have
    // left behind, so the user is never stranded without internet on launch.
    openconnect_gui_lib::killswitch::disable();

    let app = tauri::Builder::default()
        // Single-instance guard: if the app is launched again, focus the
        // existing window instead of spawning a second process (which would
        // create a second tray icon). Must be registered before other plugins.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main_window(app);
        }))
        .plugin(
            tauri_plugin_window_state::Builder::default()
                // Let tauri.conf.json own the window size, and always spawn the
                // window centered — so only maximize state is persisted.
                .with_state_flags(tauri_plugin_window_state::StateFlags::MAXIMIZED)
                .build(),
        )
        // Auto-updater: checks the GitHub Releases `latest.json`, verifies the
        // update signature against the embedded public key, and installs it.
        .plugin(tauri_plugin_updater::Builder::new().build())
        // Enables relaunching the app after an update is installed.
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            // ── Managed state ─────────────────────────────────────────────
            let manager = Arc::new(ProcessManager::new());
            app.manage(manager);

            // Ensure the window opens centered on the current monitor.
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.center();
            }

            // ── System tray ───────────────────────────────────────────────
            let show_item = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

            let mut builder = TrayIconBuilder::new()
                .tooltip("OpenGui")
                .menu(&menu)
                // Left-click should restore the window, not pop the menu.
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => show_main_window(app),
                    "quit" => {
                        if let Some(mgr) = app.try_state::<Arc<ProcessManager>>() {
                            mgr.kill_if_running();
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                });

            if let Some(icon) = app.default_window_icon().cloned() {
                builder = builder.icon(icon);
            }

            builder.build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| match event {
            // Close-to-tray: hide the window instead of quitting, so the VPN
            // connection keeps running in the background. Use "Quit" from the
            // tray menu to actually exit.
            WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                let _ = window.hide();
            }
            // Minimise-to-tray: hide the window when it is minimised (Windows
            // sends a Resized event with a zero-area size when minimising;
            // is_minimized() confirms it).
            WindowEvent::Resized(_) if window.is_minimized().unwrap_or(false) => {
                let _ = window.hide();
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            openconnect_gui_lib::commands::list_profiles,
            openconnect_gui_lib::commands::add_profile,
            openconnect_gui_lib::commands::update_profile,
            openconnect_gui_lib::commands::delete_profile,
            openconnect_gui_lib::commands::store_credential,
            openconnect_gui_lib::commands::detect_country,
            openconnect_gui_lib::commands::connect,
            openconnect_gui_lib::commands::disconnect,
            openconnect_gui_lib::commands::get_connection_state,
            openconnect_gui_lib::commands::submit_mfa,
            openconnect_gui_lib::commands::bridge_version,
            openconnect_gui_lib::commands::openconnect_version,
            openconnect_gui_lib::commands::is_elevated,
            openconnect_gui_lib::commands::get_settings,
            openconnect_gui_lib::commands::set_settings,
            openconnect_gui_lib::commands::set_netshield,
            openconnect_gui_lib::commands::set_netshield_config,
            openconnect_gui_lib::commands::set_killswitch,
            openconnect_gui_lib::commands::set_auto_retry,
            openconnect_gui_lib::updater::check_for_update,
            openconnect_gui_lib::updater::install_update,
        ])
        .build(tauri::generate_context!())
        .expect("error building Tauri application");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            if let Some(mgr) = app_handle.try_state::<Arc<ProcessManager>>() {
                mgr.kill_if_running();
            }
        }
    });
}
