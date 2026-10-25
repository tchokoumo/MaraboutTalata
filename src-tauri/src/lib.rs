mod agent_watcher;
mod monitor;

#[tauri::command]
fn get_system_snapshot(
    state: tauri::State<'_, monitor::MonitorState>,
) -> Result<monitor::SystemSnapshot, String> {
    state.snapshot()
}

#[tauri::command]
fn get_process_command(
    pid: usize,
    state: tauri::State<'_, monitor::MonitorState>,
) -> Result<Option<monitor::ProcessCommand>, String> {
    state.process_command(pid)
}

#[tauri::command]
fn set_agent_watch_config(
    config: agent_watcher::AgentWatchConfig,
    state: tauri::State<'_, monitor::MonitorState>,
) -> Result<agent_watcher::AgentWatchConfig, String> {
    state.set_agent_watch_config(config)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(monitor::MonitorState::new())
        .invoke_handler(tauri::generate_handler![
            get_system_snapshot,
            get_process_command,
            set_agent_watch_config
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
