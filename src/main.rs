pub mod models;
pub mod api;
pub mod config;
pub mod app;
pub mod ui;

use crate::app::{App, ActiveView};
use crate::config::ConfigManager;
use crate::api::WazuhApi;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // App state
    let mut app = App::new();
    let (tx, mut rx) = mpsc::channel(100);
    
    // Try to load config and init API
    match ConfigManager::load() {
        Ok(config) => {
            let api = WazuhApi::new(config);
            app.set_api(api.clone());
            app.active_view = ActiveView::Dashboard;
        }
        Err(_) => {
            app.is_config_wizard_active = true;
            app.error_message = Some("Configuration not found. Please complete the wizard.".to_string());
        }
    }

    let tick_rate = Duration::from_millis(250);
    let mut last_tick = Instant::now();

    // Initial data load
    if let Some(api) = app.api.clone() {
        app.set_loading("Fetching initial dashboard data...");
        let tx = tx.clone();
        tokio::spawn(async move {
            // Initial agent load
            if let Ok(agents_res) = api.list_agents(None, 0, 500).await {
                let _ = tx.send(crate::app::DataUpdate::Agents(agents_res.data.affected_items)).await;
            }

            // Initial logs load for stats (default 24h for dashboard)
            if let Ok(logs_res) = api.get_logs(None, 1440, 0, 1000, None).await {
                if let Some(hits) = logs_res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                    let mut stats = crate::app::ThreatStats::default();
                    let mut buckets = std::collections::BTreeMap::new();
                    let mut agent_counts = std::collections::HashMap::new();

                    for hit in hits {
                        if let Some(source) = hit.get("_source") {
                            if let Some(level) = source.get("rule").and_then(|r| r.get("level")).and_then(|l| l.as_u64()) {
                                match level {
                                    15..=u64::MAX => stats.critical += 1,
                                    12..=14 => stats.high += 1,
                                    7..=11 => stats.medium += 1,
                                    _ => stats.low += 1,
                                }
                            }
                            if let Some(agent_name) = source.get("agent").and_then(|a| a.get("name")).and_then(|n| n.as_str()) {
                                *agent_counts.entry(agent_name.to_string()).or_insert(0u64) += 1;
                            }
                            if let Some(ts) = source.get("@timestamp").and_then(|t| t.as_str()) {
                                if ts.len() >= 16 {
                                    let minute = &ts[11..16];
                                    *buckets.entry(minute.to_string()).or_insert(0u64) += 1;
                                }
                            }
                        }
                    }
                    let _ = tx.send(crate::app::DataUpdate::ThreatStats(stats)).await;
                    let hist: Vec<(String, u64)> = buckets.into_iter().collect();
                    let _ = tx.send(crate::app::DataUpdate::AlertHistory(hist)).await;
                    let mut top: Vec<(String, u64)> = agent_counts.into_iter().collect();
                    top.sort_by(|a, b| b.1.cmp(&a.1));
                    top.truncate(5);
                    let _ = tx.send(crate::app::DataUpdate::TopAgents(top)).await;
                }
            }
        });
        app.stop_loading();
    }

    loop {
        // Handle async updates
        while let Ok(update) = rx.try_recv() {
            match update {
                crate::app::DataUpdate::Agents(agents) => {
                    app.agents = agents;
                    app.sort_agents();
                }
                crate::app::DataUpdate::Groups(groups) => app.groups = groups,
                crate::app::DataUpdate::GroupAgents(agents) => {
                     app.agents = agents;
                     app.sort_agents();
                }
                crate::app::DataUpdate::SecurityEvents(logs) => app.logs = logs,
                crate::app::DataUpdate::VulnSummary(summary) => app.vuln_summary = summary,
                crate::app::DataUpdate::ThreatStats(stats) => app.threat_stats = stats,
                crate::app::DataUpdate::AgentHardware(hw) => app.hardware = Some(hw),
                crate::app::DataUpdate::AgentProcesses(procs) => app.processes = procs,
                crate::app::DataUpdate::AgentPrograms(progs) => app.programs = progs,
                crate::app::DataUpdate::AgentVulnerabilities(vulns) => app.vulnerabilities = vulns,
                crate::app::DataUpdate::AgentLogs(logs) => app.agent_logs = logs,
                crate::app::DataUpdate::AgentConfig(config) => app.agent_config = Some(config),
                crate::app::DataUpdate::AlertHistory(hist) => app.alert_buckets = hist,
                crate::app::DataUpdate::TopAgents(top) => app.top_agents = top,
                crate::app::DataUpdate::Notification(msg, level) => app.notify(&msg, level),
                crate::app::DataUpdate::Error(msg) => app.error_message = Some(msg),
                crate::app::DataUpdate::ErrorPopup { title, message } => app.show_error(&title, &message),
            }
        }

        // Draw UI
        terminal.draw(|f| {
            crate::ui::draw(f, &mut app);
        })?;

            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    
                    // Handle input for text fields
                    if app.is_config_wizard_active {
                        match key.code {
                            KeyCode::Char(c) => {
                                match app.config_step {
                                    crate::app::ConfigStep::Url => app.config_url.push(c),
                                    crate::app::ConfigStep::OsUrl => app.config_os_url.push(c),
                                    crate::app::ConfigStep::Username => app.config_username.push(c),
                                    crate::app::ConfigStep::Password => app.config_password.push(c),
                                    _ => {}
                                }
                            },
                            _ => {}
                        }
                    } else if app.show_interval_popup {
                        if let KeyCode::Char(c) = key.code {
                            app.interval_input.push(c);
                        }
                    } else if matches!(app.popup_mode, crate::app::PopupMode::SeverityFilter) {
                        // Advanced filter popup input handling
                        if let KeyCode::Char(c) = key.code {
                            // Handle special keys first
                            match c {
                                '1' if app.filter_popup_tab == crate::app::FilterPopupTab::Severity => {
                                    // Critical preset: level >= 15
                                    app.log_filter.mode = crate::app::SeverityFilterMode::Min;
                                    app.log_filter.val1 = 15;
                                    app.filter_input_1 = "15".to_string();
                                }
                                '2' if app.filter_popup_tab == crate::app::FilterPopupTab::Severity => {
                                    // High preset: 12-14
                                    app.log_filter.mode = crate::app::SeverityFilterMode::Range;
                                    app.log_filter.val1 = 12;
                                    app.log_filter.val2 = 14;
                                    app.filter_input_1 = "12".to_string();
                                    app.filter_input_2 = "14".to_string();
                                }
                                '3' if app.filter_popup_tab == crate::app::FilterPopupTab::Severity => {
                                    // Medium preset: 7-11
                                    app.log_filter.mode = crate::app::SeverityFilterMode::Range;
                                    app.log_filter.val1 = 7;
                                    app.log_filter.val2 = 11;
                                    app.filter_input_1 = "7".to_string();
                                    app.filter_input_2 = "11".to_string();
                                }
                                '4' if app.filter_popup_tab == crate::app::FilterPopupTab::Severity => {
                                    // Low preset: 0-6
                                    app.log_filter.mode = crate::app::SeverityFilterMode::Range;
                                    app.log_filter.val1 = 0;
                                    app.log_filter.val2 = 6;
                                    app.filter_input_1 = "0".to_string();
                                    app.filter_input_2 = "6".to_string();
                                }
                                'a' if app.filter_popup_tab == crate::app::FilterPopupTab::Severity => {
                                    // All levels: 0-15
                                    app.log_filter.mode = crate::app::SeverityFilterMode::Range;
                                    app.log_filter.val1 = 0;
                                    app.log_filter.val2 = 20;
                                    app.filter_input_1 = "0".to_string();
                                    app.filter_input_2 = "20".to_string();
                                }
                                'm' if app.filter_popup_tab == crate::app::FilterPopupTab::Severity => {
                                    // Cycle filter mode
                                    app.log_filter.mode = match app.log_filter.mode {
                                        crate::app::SeverityFilterMode::Min => crate::app::SeverityFilterMode::Max,
                                        crate::app::SeverityFilterMode::Max => crate::app::SeverityFilterMode::Exact,
                                        crate::app::SeverityFilterMode::Exact => crate::app::SeverityFilterMode::Range,
                                        crate::app::SeverityFilterMode::Range => crate::app::SeverityFilterMode::Min,
                                    };
                                }
                                'c' => {
                                    // Clear all filters
                                    app.log_filter = crate::app::LogFilter::default();
                                    app.filter_input_1 = "0".to_string();
                                    app.filter_input_2 = "15".to_string();
                                }
                                ' ' if app.filter_popup_tab == crate::app::FilterPopupTab::Columns => {
                                    // Toggle column visibility
                                    let all_columns = crate::app::LogColumn::all();
                                    if let Some(col) = all_columns.get(app.column_selection_index) {
                                        if let Some(pos) = app.visible_log_columns.iter().position(|c| c == col) {
                                            app.visible_log_columns.remove(pos);
                                        } else {
                                            app.visible_log_columns.push(*col);
                                        }
                                    }
                                }
                                _ => {
                                    // Regular text input
                                    match app.filter_popup_tab {
                                        crate::app::FilterPopupTab::Severity => {
                                            // Numeric input for severity levels
                                            if c.is_digit(10) {
                                                if app.filter_active_input == 0 {
                                                    app.filter_input_1.push(c);
                                                } else {
                                                    app.filter_input_2.push(c);
                                                }
                                            }
                                        }
                                        crate::app::FilterPopupTab::Agent => {
                                            app.log_filter.agent_filter.push(c);
                                        }
                                        crate::app::FilterPopupTab::Rule => {
                                            if app.filter_active_input == 0 {
                                                app.log_filter.rule_id_filter.push(c);
                                            } else {
                                                app.log_filter.mitre_filter.push(c);
                                            }
                                        }
                                        crate::app::FilterPopupTab::Text => {
                                            app.log_filter.description_filter.push(c);
                                        }
                                        crate::app::FilterPopupTab::Columns => {
                                            // No text input in columns tab (handled by Space above)
                                        }
                                    }
                                }
                            }
                        }
                    } else if matches!(app.popup_mode, crate::app::PopupMode::SshUsername { .. }) {
                        if let KeyCode::Char(c) = key.code {
                            app.input_buffer.push(c);
                        }
                    } else if app.is_searching {
                         if let KeyCode::Char(c) = key.code {
                            app.search_query.push(c);
                            app.agent_filter = crate::app::filter::AgentFilter::parse(&app.search_query);
                        }
                    } else if matches!(app.popup_mode, crate::app::PopupMode::CommandPalette) {
                         if let KeyCode::Char(c) = key.code {
                            app.command_palette_input.push(c);
                            app.command_palette_index = 0; // Reset selection on input
                        }
                    } else if matches!(app.popup_mode, crate::app::PopupMode::AgentJump) {
                         if let KeyCode::Char(c) = key.code {
                            app.jump_input.push(c);
                            app.jump_index = 0; // Reset selection on input
                        }
                    } 
                    
                    // Main key handling
                    match key.code {
                         KeyCode::Char('p') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                            // Command Palette Trigger
                            app.popup_mode = crate::app::PopupMode::CommandPalette;
                            app.command_palette_input.clear();
                            app.command_palette_index = 0;
                        }
                        KeyCode::Char(c) if !app.is_config_wizard_active && !app.is_searching && !app.show_interval_popup && app.popup_mode == crate::app::PopupMode::None => {
                            if c == 'k' {
                                if app.active_view == ActiveView::AgentInspector {
                                    app.scroll_up(1);
                                } else if app.selected_log.is_some() {
                                    app.log_scroll_offset = app.log_scroll_offset.saturating_sub(1);
                                } else if app.active_view != ActiveView::Dashboard {
                                    app.previous_item();
                                }
                            } else if c == 'j' {
                                if app.active_view == ActiveView::AgentInspector {
                                    app.scroll_down(1);
                                } else if app.selected_log.is_some() {
                                    app.log_scroll_offset = app.log_scroll_offset.saturating_add(1);
                                } else if app.active_view != ActiveView::Dashboard {
                                    app.next_item();
                                }
                            } else if c == ' ' {
                                app.toggle_selection();
                            } else if c == '/' {
                                app.is_searching = true;
                                app.search_query.clear();
                            } else if c == 'i' {
                                app.show_interval_popup = true;
                                app.interval_input = format!("{}m", app.log_interval_mins);
                            } else if c == 'G' {
                                if let Some(agent) = app.get_selected_agent() {
                                    let agent_id = agent.id.clone();
                                    // If multiple selected, pass special "MULTI" id or handle logic
                                    let target_id = if app.selected_agents.len() > 1 { "MULTI".to_string() } else { agent_id };
                                    app.popup_mode = crate::app::PopupMode::GroupAssignment { agent_id: target_id };
                                }
                            } else if c == 'v' {
                                if app.active_view == ActiveView::SecurityEvents {
                                    app.log_view_mode = match app.log_view_mode {
                                        crate::app::LogViewMode::Table => crate::app::LogViewMode::Raw,
                                        crate::app::LogViewMode::Raw => crate::app::LogViewMode::Table,
                                    };
                                }
                            } else if c == 'e' {
                                if app.active_view == ActiveView::AgentInspector && app.inspector_tab == crate::app::InspectorTab::Config {
                                    if let (Some(api), Some(agent), Some(config)) = (&app.api, app.get_selected_agent(), &app.agent_config) {
                                        let api = api.clone();
                                        let agent_id = agent.id.clone();
                                        let component = app.agent_config_component.clone();
                                        let config = config.clone();
                                        let tx = tx.clone();
                                        
                                        app.notify(&format!("Pushing config update to {}...", agent_id), crate::app::NotificationLevel::Info);
                                        tokio::spawn(async move {
                                            match api.update_agent_config(&agent_id, &component, config).await {
                                                Ok(_) => { let _ = tx.send(crate::app::DataUpdate::Notification("Configuration updated successfully".to_string(), crate::app::NotificationLevel::Success)).await; },
                                                Err(e) => { let _ = tx.send(crate::app::DataUpdate::Notification(format!("Update failed: {}", e), crate::app::NotificationLevel::Error)).await; },
                                            }
                                        });
                                    }
                                } else if app.active_view == ActiveView::SecurityEvents || (app.active_view == ActiveView::AgentInspector && app.inspector_tab == crate::app::InspectorTab::Logs) {
                                    // Handle log export here
                                    match app.export_logs() {
                                        Ok(filename) => app.notify(&format!("Logs exported to {}", filename), crate::app::NotificationLevel::Success),
                                        Err(e) => app.notify(&e, crate::app::NotificationLevel::Error),
                                    }
                                }
                            } else if c == 'h' {
                                if let Some(agent) = app.get_selected_agent() {
                                    let agent_id = agent.id.clone();
                                    let agent_ip = agent.ip.clone().unwrap_or_default();
                                    app.popup_mode = crate::app::PopupMode::SshUsername { agent_id, agent_ip };
                                    app.input_buffer.clear();
                                }
                            } else if c == 'f' {
                                 if app.active_view == ActiveView::SecurityEvents || (app.active_view == ActiveView::AgentInspector && app.inspector_tab == crate::app::InspectorTab::Logs) {
                                     app.popup_mode = crate::app::PopupMode::SeverityFilter;
                                     app.filter_input_1 = app.log_filter.val1.to_string();
                                     app.filter_input_2 = app.log_filter.val2.to_string();
                                 }
                            } else if c == 'o' {
                                if let (Some(api), Some(agent)) = (&app.api, app.get_selected_agent()) {
                                    if let Ok(u) = reqwest::Url::parse(&api.config.url) {
                                        let browser_url = format!("{}://{}/app/endpoints-summary#/agents?tab=welcome&agent={}&tabView=panels", 
                                            u.scheme(), u.host_str().unwrap_or(""), agent.id);
                                        
                                        let _ = std::process::Command::new("xdg-open")
                                            .arg(browser_url)
                                            .stdin(std::process::Stdio::null())
                                            .stdout(std::process::Stdio::null())
                                            .stderr(std::process::Stdio::null())
                                            .spawn();
                                    }
                                }
                            } else if c == '+' {
                                app.log_interval_mins = (app.log_interval_mins + 15).min(1440);
                            } else if c == '-' {
                                app.log_interval_mins = app.log_interval_mins.saturating_sub(15).max(5);
                            } else if c == 'U' {
                                if let Some(api) = app.api.as_ref() {
                                    let api = api.clone();
                                    let tx = tx.clone();
                                    
                                    let agent_ids: Vec<String> = if !app.selected_agents.is_empty() {
                                        app.selected_agents.iter().cloned().collect()
                                    } else if let Some(agent) = app.get_selected_agent() {
                                        vec![agent.id.clone()]
                                    } else {
                                        Vec::new()
                                    };

                                    if !agent_ids.is_empty() {
                                        let count = agent_ids.len();
                                        app.notify(&format!("Starting upgrade for {} agents...", count), crate::app::NotificationLevel::Info);
                                        tokio::spawn(async move {
                                            let ids: Vec<&str> = agent_ids.iter().map(|s| s.as_str()).collect();
                                            match api.upgrade_agents(&ids).await {
                                                Ok(_) => { let _ = tx.send(crate::app::DataUpdate::Notification(format!("Upgrade started for {} agents", count), crate::app::NotificationLevel::Success)).await; },
                                                Err(e) => { let _ = tx.send(crate::app::DataUpdate::Notification(format!("Upgrade failed: {}", e), crate::app::NotificationLevel::Error)).await; },
                                            }
                                        });
                                    }
                                }
                            } else if c == 'R' {
                                if let Some(api) = app.api.as_ref() {
                                    let api = api.clone();
                                    let tx = tx.clone();
                                    
                                    let agent_ids: Vec<String> = if !app.selected_agents.is_empty() {
                                        app.selected_agents.iter().cloned().collect()
                                    } else if let Some(agent) = app.get_selected_agent() {
                                        vec![agent.id.clone()]
                                    } else {
                                        Vec::new()
                                    };

                                    if !agent_ids.is_empty() {
                                        let count = agent_ids.len();
                                        app.notify(&format!("Restarting {} agents...", count), crate::app::NotificationLevel::Info);
                                        tokio::spawn(async move {
                                            let ids: Vec<&str> = agent_ids.iter().map(|s| s.as_str()).collect();
                                            match api.restart_agents(&ids).await {
                                                Ok(_) => { let _ = tx.send(crate::app::DataUpdate::Notification(format!("Restart signal sent to {} agents", count), crate::app::NotificationLevel::Success)).await; },
                                                Err(e) => { let _ = tx.send(crate::app::DataUpdate::Notification(format!("Restart failed: {}", e), crate::app::NotificationLevel::Error)).await; },
                                            }
                                        });
                                    }
                                }
                            } else if c == 's' {
                                if app.active_view == ActiveView::AgentList {
                                    app.cycle_sort();
                                }
                        } else if c == '1' {
                                if app.active_view == ActiveView::Dashboard {
                                    app.log_filter.mode = crate::app::SeverityFilterMode::Min;
                                    app.log_filter.val1 = 15;
                                    app.log_filter.val2 = 15;
                                    app.active_view = ActiveView::SecurityEvents;
                                    
                                    // Trigger data load with new filter
                                    if let Some(api) = app.api.clone() {
                                        app.set_loading("Fetching critical alerts...");
                                        let tx = tx.clone();
                                        let interval = app.log_interval_mins;
                                        let filter = Some(app.log_filter.clone());
                                        tokio::spawn(async move {
                                            if let Ok(res) = api.get_logs(None, interval, 0, 50, filter.as_ref()).await {
                                                if let Some(hits) = res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                    let _ = tx.send(crate::app::DataUpdate::SecurityEvents(hits.clone())).await;
                                                }
                                            }
                                        });
                                        app.stop_loading();
                                    }
                                }
                            } else if c == '2' {
                                if app.active_view == ActiveView::Dashboard {
                                    app.log_filter.mode = crate::app::SeverityFilterMode::Range;
                                    app.log_filter.val1 = 12;
                                    app.log_filter.val2 = 14;
                                    app.active_view = ActiveView::SecurityEvents;
                                    
                                    if let Some(api) = app.api.clone() {
                                        app.set_loading("Fetching high severity alerts...");
                                        let tx = tx.clone();
                                        let interval = app.log_interval_mins;
                                        let filter = Some(app.log_filter.clone());
                                        tokio::spawn(async move {
                                            if let Ok(res) = api.get_logs(None, interval, 0, 50, filter.as_ref()).await {
                                                if let Some(hits) = res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                    let _ = tx.send(crate::app::DataUpdate::SecurityEvents(hits.clone())).await;
                                                }
                                            }
                                        });
                                        app.stop_loading();
                                    }
                                }
                            } else if c == '3' {
                                if app.active_view == ActiveView::Dashboard {
                                    app.log_filter.mode = crate::app::SeverityFilterMode::Range;
                                    app.log_filter.val1 = 7;
                                    app.log_filter.val2 = 11;
                                    app.active_view = ActiveView::SecurityEvents;
                                    
                                    if let Some(api) = app.api.clone() {
                                        app.set_loading("Fetching medium severity alerts...");
                                        let tx = tx.clone();
                                        let interval = app.log_interval_mins;
                                        let filter = Some(app.log_filter.clone());
                                        tokio::spawn(async move {
                                            if let Ok(res) = api.get_logs(None, interval, 0, 50, filter.as_ref()).await {
                                                if let Some(hits) = res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                    let _ = tx.send(crate::app::DataUpdate::SecurityEvents(hits.clone())).await;
                                                }
                                            }
                                        });
                                        app.stop_loading();
                                    }
                                }
                            } else if c == '4' {
                                if app.active_view == ActiveView::Dashboard {
                                    app.log_filter.mode = crate::app::SeverityFilterMode::Range;
                                    app.log_filter.val1 = 0;
                                    app.log_filter.val2 = 6;
                                    app.active_view = ActiveView::SecurityEvents;
                                    
                                    if let Some(api) = app.api.clone() {
                                        app.set_loading("Fetching low severity alerts...");
                                        let tx = tx.clone();
                                        let interval = app.log_interval_mins;
                                        let filter = Some(app.log_filter.clone());
                                        tokio::spawn(async move {
                                            if let Ok(res) = api.get_logs(None, interval, 0, 50, filter.as_ref()).await {
                                                if let Some(hits) = res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                    let _ = tx.send(crate::app::DataUpdate::SecurityEvents(hits.clone())).await;
                                                }
                                            }
                                        });
                                        app.stop_loading();
                                    }
                                }
                            } else if c == 'r' {
                                if let Some(api) = app.api.clone() {
                                    app.set_loading("Refreshing...");
                                    let tx = tx.clone();
                                    let active_view = app.active_view.clone();
                                    let agent_id = app.get_selected_agent().map(|a| a.id.clone());
                                    let interval = app.log_interval_mins;
                                    let config_component = app.agent_config_component.clone();
                                    
                                    tokio::spawn(async move {
                                        match active_view {
                                            ActiveView::Dashboard | ActiveView::AgentList | ActiveView::GroupManagement => {
                                                if let Ok(agents_res) = api.list_agents(None, 0, 500).await {
                                                    let _ = tx.send(crate::app::DataUpdate::Agents(agents_res.data.affected_items)).await;
                                                }
                                                if let Ok(groups_res) = api.get_groups().await {
                                                    let _ = tx.send(crate::app::DataUpdate::Groups(groups_res.data.affected_items)).await;
                                                }

                                            // Fetch logs for dashboard threat summary
                                            if let Ok(logs_res) = api.get_logs(None, interval, 0, 100, None).await {
                                                if let Some(hits) = logs_res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                    let mut stats = crate::app::ThreatStats::default();
                                                    let mut buckets = std::collections::BTreeMap::new();
                                                    let mut agent_counts = std::collections::HashMap::new();

                                                    for hit in hits {
                                                        if let Some(source) = hit.get("_source") {
                                                            if let Some(level) = source.get("rule").and_then(|r| r.get("level")).and_then(|l| l.as_u64()) {
                                                                match level {
                                                                    15..=u64::MAX => stats.critical += 1,
                                                                    12..=14 => stats.high += 1,
                                                                    7..=11 => stats.medium += 1,
                                                                    _ => stats.low += 1,
                                                                }
                                                            }
                                                            
                                                            if let Some(agent_name) = source.get("agent").and_then(|a| a.get("name")).and_then(|n| n.as_str()) {
                                                                *agent_counts.entry(agent_name.to_string()).or_insert(0u64) += 1;
                                                            }

                                                            if let Some(ts) = source.get("@timestamp").and_then(|t| t.as_str()) {
                                                                // Group by minute: 2023-10-27T10:15:30.000Z -> 10:15
                                                                if ts.len() >= 16 {
                                                                    let minute = &ts[11..16];
                                                                    *buckets.entry(minute.to_string()).or_insert(0u64) += 1;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    let _ = tx.send(crate::app::DataUpdate::ThreatStats(stats)).await;
                                                    let hist: Vec<(String, u64)> = buckets.into_iter().collect();
                                                    let _ = tx.send(crate::app::DataUpdate::AlertHistory(hist)).await;

                                                    let mut top: Vec<(String, u64)> = agent_counts.into_iter().collect();
                                                    top.sort_by(|a, b| b.1.cmp(&a.1));
                                                    top.truncate(5);
                                                    let _ = tx.send(crate::app::DataUpdate::TopAgents(top)).await;
                                                }
                                            }
                                        }
                                        ActiveView::AgentInspector => {
                                             if let Some(id) = agent_id {
                                                if let Ok(hw_res) = api.get_hardware_info(&id).await {
                                                    if let Some(hw) = hw_res.data.affected_items.into_iter().next() {
                                                        let _ = tx.send(crate::app::DataUpdate::AgentHardware(hw)).await;
                                                    }
                                                }
                                                if let Ok(proc_res) = api.get_processes(&id).await {
                                                    let _ = tx.send(crate::app::DataUpdate::AgentProcesses(proc_res.data.affected_items)).await;
                                                }
                                            if let Ok(prog_res) = api.get_programs(&id).await {
                                                let _ = tx.send(crate::app::DataUpdate::AgentPrograms(prog_res.data.affected_items)).await;
                                            }
                                            match api.get_vulnerabilities(&id).await {
                                                Ok(vuln_res) => {
                                                    let _ = tx.send(crate::app::DataUpdate::AgentVulnerabilities(vuln_res.data.affected_items)).await;
                                                }
                                                Err(e) => {
                                                    let _ = tx.send(crate::app::DataUpdate::ErrorPopup { 
                                                        title: "Vulnerabilities Error".to_string(), 
                                                        message: format!("Failed to load vulnerabilities: {}", e) 
                                                    }).await;
                                                }
                                            }
                                            if let Ok(logs_res) = api.get_logs(Some(&id), interval, 0, 100, None).await {
                                                    if let Some(hits) = logs_res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                        let _ = tx.send(crate::app::DataUpdate::AgentLogs(hits.clone())).await;
                                                    }
                                                }
                                                match api.get_agent_config(&id, &config_component).await {
                                                    Ok(config_res) => {
                                                        let _ = tx.send(crate::app::DataUpdate::AgentConfig(config_res)).await;
                                                    }
                                                    Err(e) => {
                                                        let _ = tx.send(crate::app::DataUpdate::ErrorPopup { 
                                                            title: "Config Error".to_string(), 
                                                            message: format!("Failed to load config: {}", e) 
                                                        }).await;
                                                    }
                                                }
                                            }
                                        }
                                        ActiveView::SecurityEvents => {
                                            if let Ok(logs_res) = api.get_logs(None, interval, 0, 50, None).await {
                                                if let Some(hits) = logs_res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                    let _ = tx.send(crate::app::DataUpdate::SecurityEvents(hits.clone())).await;
                                                }
                                            }
                                        }
                                    }
                                    let _ = tx.send(crate::app::DataUpdate::Notification("Data refreshed".to_string(), crate::app::NotificationLevel::Success)).await;
                                });
                                app.stop_loading();
                            }
                        } else if c == '?' {
                            // Toggle help popup
                            if app.popup_mode == crate::app::PopupMode::Help {
                                app.popup_mode = crate::app::PopupMode::None;
                            } else {
                                app.popup_mode = crate::app::PopupMode::Help;
                            }
                        } else if c == 'J' && app.active_view == ActiveView::Dashboard {
                            // Quick jump to agent from dashboard (moved from 'j' to 'J')
                            app.popup_mode = crate::app::PopupMode::AgentJump;
                            app.jump_input.clear();
                            app.jump_index = 0;
                        } else if c == 'q' {
                            if app.active_view == ActiveView::AgentInspector {
                                app.active_view = ActiveView::AgentList;
                            } else {
                                app.should_quit = true;
                            }
                        }
                    }
                    KeyCode::Esc => {
                        if matches!(app.popup_mode, crate::app::PopupMode::AgentJump) {
                            app.popup_mode = crate::app::PopupMode::None;
                        } else if matches!(app.popup_mode, crate::app::PopupMode::CommandPalette) {
                            app.popup_mode = crate::app::PopupMode::None;
                        } else if app.is_searching {
                            app.is_searching = false;
                        } else if app.popup_mode != crate::app::PopupMode::None {
                            app.popup_mode = crate::app::PopupMode::None;
                        } else if app.show_interval_popup {
                            app.show_interval_popup = false;
                        } else if app.selected_log.is_some() {
                            app.selected_log = None;
                            app.log_scroll_offset = 0;
                        } else if app.severity_filter.is_some() {
                            app.severity_filter = None;
                        } else if app.active_view == ActiveView::AgentInspector {
                            app.active_view = ActiveView::AgentList;
                        }
                    }
                    KeyCode::PageUp => {
                        if app.active_view == ActiveView::SecurityEvents {
                            app.log_offset = app.log_offset.saturating_sub(app.log_limit);
                            let api = app.api.as_ref().unwrap().clone();
                            let tx = tx.clone();
                            let interval = app.log_interval_mins;
                            let offset = app.log_offset;
                            let limit = app.log_limit;
                            let filter = Some(app.log_filter.clone());
                            tokio::spawn(async move {
                                if let Ok(res) = api.get_logs(None, interval, offset, limit, filter.as_ref()).await {
                                    if let Some(hits) = res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                        let _ = tx.send(crate::app::DataUpdate::SecurityEvents(hits.clone())).await;
                                    }
                                }
                            });
                        } else {
                            app.scroll_up(15);
                        }
                    }
                    KeyCode::PageDown => {
                        if app.active_view == ActiveView::SecurityEvents {
                            app.log_offset += app.log_limit;
                            let api = app.api.as_ref().unwrap().clone();
                            let tx = tx.clone();
                            let interval = app.log_interval_mins;
                            let offset = app.log_offset;
                            let limit = app.log_limit;
                            let filter = Some(app.log_filter.clone());
                            tokio::spawn(async move {
                                if let Ok(res) = api.get_logs(None, interval, offset, limit, filter.as_ref()).await {
                                    if let Some(hits) = res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                        let _ = tx.send(crate::app::DataUpdate::SecurityEvents(hits.clone())).await;
                                    }
                                }
                            });
                        } else {
                            app.scroll_down(15);
                        }
                    }
                    KeyCode::Backspace => {
                        if matches!(app.popup_mode, crate::app::PopupMode::AgentJump) {
                            app.jump_input.pop();
                            app.jump_index = 0;
                        } else if matches!(app.popup_mode, crate::app::PopupMode::CommandPalette) {
                            app.command_palette_input.pop();
                            app.command_palette_index = 0;
                        } else if app.is_searching {
                            app.search_query.pop();
                            app.agent_filter = crate::app::filter::AgentFilter::parse(&app.search_query);
                        } else if matches!(app.popup_mode, crate::app::PopupMode::SshUsername { .. }) {
                            app.input_buffer.pop();
                        } else if matches!(app.popup_mode, crate::app::PopupMode::SeverityFilter) {
                            match app.filter_popup_tab {
                                crate::app::FilterPopupTab::Severity => {
                                    if app.filter_active_input == 0 {
                                        app.filter_input_1.pop();
                                    } else {
                                        app.filter_input_2.pop();
                                    }
                                }
                                crate::app::FilterPopupTab::Agent => {
                                    app.log_filter.agent_filter.pop();
                                }
                                crate::app::FilterPopupTab::Rule => {
                                    if app.filter_active_input == 0 {
                                        app.log_filter.rule_id_filter.pop();
                                    } else {
                                        app.log_filter.mitre_filter.pop();
                                    }
                                }
                                crate::app::FilterPopupTab::Text => {
                                    app.log_filter.description_filter.pop();
                                }
                                crate::app::FilterPopupTab::Columns => {
                                    // No backspace in columns tab
                                }
                            }
                        } else if app.show_interval_popup {
                            app.interval_input.pop();
                        } else if app.is_config_wizard_active {
                            match app.config_step {
                                crate::app::ConfigStep::Url => { app.config_url.pop(); }
                                crate::app::ConfigStep::OsUrl => { app.config_os_url.pop(); }
                                crate::app::ConfigStep::Username => { app.config_username.pop(); }
                                crate::app::ConfigStep::Password => { app.config_password.pop(); }
                                crate::app::ConfigStep::Confirm => { app.config_step = crate::app::ConfigStep::Password; }
                            }
                        }
                    }
                    KeyCode::Tab => {
                        if matches!(app.popup_mode, crate::app::PopupMode::SeverityFilter) {
                            // Tab switches between filter popup tabs
                            app.filter_popup_tab = app.filter_popup_tab.next();
                            app.filter_active_input = 0; // Reset input focus when switching tabs
                        } else if app.active_view == ActiveView::AgentInspector {
                            app.next_tab();
                        } else {
                            app.active_view = match app.active_view {
                                ActiveView::Dashboard => ActiveView::AgentList,
                                ActiveView::AgentList => ActiveView::SecurityEvents,
                                ActiveView::SecurityEvents => ActiveView::GroupManagement,
                                ActiveView::GroupManagement => ActiveView::Dashboard,
                                ActiveView::AgentInspector => ActiveView::AgentList,
                            };
                            
                            if let Some(api) = app.api.clone() {
                                app.set_loading("Fetching data...");
                                app.error_message = None;
                                let tx = tx.clone();
                                let interval = app.log_interval_mins;
                                let active_view = app.active_view.clone();
                                
                                tokio::spawn(async move {
                                    match active_view {
                                        ActiveView::SecurityEvents => {
                                            match api.get_logs(None, interval, 0, 50, None).await {
                                                Ok(logs_res) => {
                                                    if let Some(hits) = logs_res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                        let _ = tx.send(crate::app::DataUpdate::SecurityEvents(hits.clone())).await;
                                                    }
                                                }
                                                Err(e) => { let _ = tx.send(crate::app::DataUpdate::Error(format!("Failed to load logs: {}", e))).await; }
                                            }
                                        }
                                        ActiveView::Dashboard | ActiveView::AgentList | ActiveView::GroupManagement => {
                                            match api.list_agents(None, 0, 500).await {
                                                Ok(agents_res) => { let _ = tx.send(crate::app::DataUpdate::Agents(agents_res.data.affected_items)).await; }
                                                Err(e) => { let _ = tx.send(crate::app::DataUpdate::Error(format!("Failed to load agents: {}", e))).await; }
                                            }
                                            match api.get_groups().await {
                                                Ok(groups_res) => { let _ = tx.send(crate::app::DataUpdate::Groups(groups_res.data.affected_items)).await; }
                                                Err(e) => { let _ = tx.send(crate::app::DataUpdate::Error(format!("Failed to load groups: {}", e))).await; }
                                            }
                                        }
                                        _ => {}
                                    }
                                });
                                app.stop_loading();
                            }
                        }
                    }
                    KeyCode::Enter => {
                        if app.popup_mode != crate::app::PopupMode::None {
                             match &app.popup_mode {
                                  crate::app::PopupMode::CommandPalette => {
                                      let matches = app.get_command_palette_matches();
                                      if let Some((name, _)) = matches.get(app.command_palette_index) {
                                          match *name {
                                              "Jump to Agent" => {
                                                  app.popup_mode = crate::app::PopupMode::AgentJump;
                                                  app.jump_input.clear();
                                                  app.jump_index = 0;
                                              },
                                              "Filter Logs" => {
                                                  app.popup_mode = crate::app::PopupMode::SeverityFilter;
                                                  app.filter_input_1 = app.log_filter.val1.to_string();
                                                  app.filter_input_2 = app.log_filter.val2.to_string();
                                              },
                                              "Search" => {
                                                  app.popup_mode = crate::app::PopupMode::None;
                                                  app.is_searching = true;
                                                  app.search_query.clear();
                                              },
                                              "Refresh" => {
                                                  app.popup_mode = crate::app::PopupMode::None;
                                                  // Trigger refresh logic (copied from 'r' key handler)
                                                  if let Some(api) = app.api.clone() {
                                                      app.set_loading("Refreshing...");
                                                      let tx = tx.clone();
                                                      let active_view = app.active_view.clone();
                                                      let agent_id = app.get_selected_agent().map(|a| a.id.clone());
                                                      let interval = app.log_interval_mins;
                                                      let config_component = app.agent_config_component.clone();
                                                      
                                                      tokio::spawn(async move {
                                                          match active_view {
                                                                  ActiveView::Dashboard | ActiveView::AgentList | ActiveView::GroupManagement => {
                                                                      if let Ok(agents_res) = api.list_agents(None, 0, 500).await {
                                                                          let _ = tx.send(crate::app::DataUpdate::Agents(agents_res.data.affected_items)).await;
                                                                      }
                                                                      if let Ok(groups_res) = api.get_groups().await {
                                                                          let _ = tx.send(crate::app::DataUpdate::Groups(groups_res.data.affected_items)).await;
                                                                      }

                                                                  if let Ok(logs_res) = api.get_logs(None, interval, 0, 100, None).await {
                                                                      if let Some(hits) = logs_res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                                          let mut stats = crate::app::ThreatStats::default();
                                                                          let mut buckets = std::collections::BTreeMap::new();
                                                                          let mut agent_counts = std::collections::HashMap::new();

                                                                          for hit in hits {
                                                                              if let Some(source) = hit.get("_source") {
                                                                                  if let Some(level) = source.get("rule").and_then(|r| r.get("level")).and_then(|l| l.as_u64()) {
                                                                                      match level {
                                                                                          15..=u64::MAX => stats.critical += 1,
                                                                                          12..=14 => stats.high += 1,
                                                                                          7..=11 => stats.medium += 1,
                                                                                          _ => stats.low += 1,
                                                                                      }
                                                                                  }
                                                                                  
                                                                                  if let Some(agent_name) = source.get("agent").and_then(|a| a.get("name")).and_then(|n| n.as_str()) {
                                                                                      *agent_counts.entry(agent_name.to_string()).or_insert(0u64) += 1;
                                                                                  }

                                                                                  if let Some(ts) = source.get("@timestamp").and_then(|t| t.as_str()) {
                                                                                      if ts.len() >= 16 {
                                                                                          let minute = &ts[11..16];
                                                                                          *buckets.entry(minute.to_string()).or_insert(0u64) += 1;
                                                                                      }
                                                                                  }
                                                                              }
                                                                          }
                                                                          let _ = tx.send(crate::app::DataUpdate::ThreatStats(stats)).await;
                                                                          let hist: Vec<(String, u64)> = buckets.into_iter().collect();
                                                                          let _ = tx.send(crate::app::DataUpdate::AlertHistory(hist)).await;

                                                                          let mut top: Vec<(String, u64)> = agent_counts.into_iter().collect();
                                                                          top.sort_by(|a, b| b.1.cmp(&a.1));
                                                                          top.truncate(5);
                                                                          let _ = tx.send(crate::app::DataUpdate::TopAgents(top)).await;
                                                                      }
                                                                  }
                                                              }
                                                              ActiveView::AgentInspector => {
                                                                   if let Some(id) = agent_id {
                                                                      if let Ok(hw_res) = api.get_hardware_info(&id).await {
                                                                          if let Some(hw) = hw_res.data.affected_items.into_iter().next() {
                                                                              let _ = tx.send(crate::app::DataUpdate::AgentHardware(hw)).await;
                                                                          }
                                                                      }
                                                                      if let Ok(proc_res) = api.get_processes(&id).await {
                                                                          let _ = tx.send(crate::app::DataUpdate::AgentProcesses(proc_res.data.affected_items)).await;
                                                                      }
                                                                  if let Ok(prog_res) = api.get_programs(&id).await {
                                                                      let _ = tx.send(crate::app::DataUpdate::AgentPrograms(prog_res.data.affected_items)).await;
                                                                  }
                                                                  match api.get_vulnerabilities(&id).await {
                                                                      Ok(vuln_res) => {
                                                                          let _ = tx.send(crate::app::DataUpdate::AgentVulnerabilities(vuln_res.data.affected_items)).await;
                                                                      }
                                                                      Err(e) => {
                                                                          let _ = tx.send(crate::app::DataUpdate::ErrorPopup { 
                                                                              title: "Vulnerabilities Error".to_string(), 
                                                                              message: format!("Failed to load vulnerabilities: {}", e) 
                                                                          }).await;
                                                                      }
                                                                  }
                                                                  if let Ok(logs_res) = api.get_logs(Some(&id), interval, 0, 100, None).await {
                                                                          if let Some(hits) = logs_res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                                              let _ = tx.send(crate::app::DataUpdate::AgentLogs(hits.clone())).await;
                                                                          }
                                                                      }
                                                                      match api.get_agent_config(&id, &config_component).await {
                                                                          Ok(config_res) => {
                                                                              let _ = tx.send(crate::app::DataUpdate::AgentConfig(config_res)).await;
                                                                          }
                                                                          Err(e) => {
                                                                              let _ = tx.send(crate::app::DataUpdate::ErrorPopup { 
                                                                                  title: "Config Error".to_string(), 
                                                                                  message: format!("Failed to load config: {}", e) 
                                                                              }).await;
                                                                          }
                                                                      }
                                                                  }
                                                              }
                                                              ActiveView::SecurityEvents => {
                                                                  if let Ok(logs_res) = api.get_logs(None, interval, 0, 50, None).await {
                                                                      if let Some(hits) = logs_res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                                          let _ = tx.send(crate::app::DataUpdate::SecurityEvents(hits.clone())).await;
                                                                      }
                                                                  }
                                                              }
                                                          }
                                                          let _ = tx.send(crate::app::DataUpdate::Notification("Data refreshed".to_string(), crate::app::NotificationLevel::Success)).await;
                                                      });
                                                      app.stop_loading();
                                                  }
                                              },
                                              "Help" => {
                                                  app.popup_mode = crate::app::PopupMode::Help;
                                              },
                                              "Quit" => {
                                                  app.should_quit = true;
                                              },
                                              "Dashboard" => {
                                                  app.active_view = ActiveView::Dashboard;
                                                  app.popup_mode = crate::app::PopupMode::None;
                                              },
                                              "Agent List" => {
                                                  app.active_view = ActiveView::AgentList;
                                                  app.popup_mode = crate::app::PopupMode::None;
                                              },
                                              "Security Events" => {
                                                  app.active_view = ActiveView::SecurityEvents;
                                                  app.popup_mode = crate::app::PopupMode::None;
                                              },
                                              "Group Management" => {
                                                  app.active_view = ActiveView::GroupManagement;
                                                  app.popup_mode = crate::app::PopupMode::None;
                                              },
                                              _ => {}
                                          }
                                      }
                                  }
                                  crate::app::PopupMode::AgentJump => {
                                    let matches = app.get_jump_matches();
                                    if let Some(agent) = matches.get(app.jump_index) {
                                        let agent_id = agent.id.clone();
                                        if let Some(pos) = app.agents.iter().position(|a| a.id == agent_id) {
                                            app.selected_agent_index = pos;
                                            app.active_view = ActiveView::AgentInspector;
                                            
                                            // Trigger data load for the inspector
                                            app.set_loading("Loading agent details...");
                                            if let Some(api) = &app.api {
                                                let api = api.clone();
                                                let tx = tx.clone();
                                                let interval = app.log_interval_mins;
                                                let config_component = app.agent_config_component.clone();
                                                
                                                tokio::spawn(async move {
                                                    if let Ok(hw_res) = api.get_hardware_info(&agent_id).await {
                                                        if let Some(hw) = hw_res.data.affected_items.into_iter().next() {
                                                            let _ = tx.send(crate::app::DataUpdate::AgentHardware(hw)).await;
                                                        }
                                                    }
                                                    if let Ok(proc_res) = api.get_processes(&agent_id).await {
                                                        let _ = tx.send(crate::app::DataUpdate::AgentProcesses(proc_res.data.affected_items)).await;
                                                    }
                                                    if let Ok(prog_res) = api.get_programs(&agent_id).await {
                                                        let _ = tx.send(crate::app::DataUpdate::AgentPrograms(prog_res.data.affected_items)).await;
                                                    }
                                                    if let Ok(vuln_res) = api.get_vulnerabilities(&agent_id).await {
                                                        let _ = tx.send(crate::app::DataUpdate::AgentVulnerabilities(vuln_res.data.affected_items)).await;
                                                    }
                                                    if let Ok(logs_res) = api.get_logs(Some(&agent_id), interval, 0, 100, None).await {
                                                        if let Some(hits) = logs_res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                            let _ = tx.send(crate::app::DataUpdate::AgentLogs(hits.clone())).await;
                                                        }
                                                    }
                                                    match api.get_agent_config(&agent_id, &config_component).await {
                                                        Ok(config_res) => {
                                                            let _ = tx.send(crate::app::DataUpdate::AgentConfig(config_res)).await;
                                                        }
                                                        Err(e) => {
                                                            let _ = tx.send(crate::app::DataUpdate::Error(format!("Failed to load config: {}", e))).await;
                                                        }
                                                    }
                                                });
                                            }
                                            app.stop_loading();
                                        }
                                    }
                                    app.popup_mode = crate::app::PopupMode::None;
                                }
                                crate::app::PopupMode::GroupAssignment { agent_id } => {
                                    if let Some(group) = app.get_selected_group() {
                                        let api = app.api.as_ref().unwrap().clone();
                                        let tx = tx.clone();
                                        let group_id = group.name.clone();
                                        
                                        let agent_ids: Vec<String> = if agent_id == "MULTI" {
                                            app.selected_agents.iter().cloned().collect()
                                        } else {
                                            vec![agent_id.clone()]
                                        };

                                        tokio::spawn(async move {
                                            let ids: Vec<&str> = agent_ids.iter().map(|s| s.as_str()).collect();
                                            match api.assign_agents_to_group(&group_id, &ids).await {
                                                Ok(_) => { let _ = tx.send(crate::app::DataUpdate::Notification(format!("{} agents assigned to {}", ids.len(), group_id), crate::app::NotificationLevel::Success)).await; },
                                                Err(e) => { let _ = tx.send(crate::app::DataUpdate::Notification(format!("Assignment failed: {}", e), crate::app::NotificationLevel::Error)).await; },
                                            }
                                        });
                                    }
                                    app.selected_agents.clear();
                                    app.popup_mode = crate::app::PopupMode::None;
                                }

                                crate::app::PopupMode::SeverityFilter => {
                                    app.log_filter.val1 = app.filter_input_1.parse().unwrap_or(0);
                                    app.log_filter.val2 = app.filter_input_2.parse().unwrap_or(15);
                                    
                                    if let Some(api) = app.api.clone() {
                                        app.set_loading("Refreshing with filters...");
                                        let tx = tx.clone();
                                        let active_view = app.active_view.clone();
                                        let agent_id = app.get_selected_agent().map(|a| a.id.clone());
                                        let interval = app.log_interval_mins;
                                        let filter = Some(app.log_filter.clone());
                                        
                                        tokio::spawn(async move {
                                            match active_view {
                                                ActiveView::SecurityEvents => {
                                                    if let Ok(res) = api.get_logs(None, interval, 0, 50, filter.as_ref()).await {
                                                        if let Some(hits) = res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                            let _ = tx.send(crate::app::DataUpdate::SecurityEvents(hits.clone())).await;
                                                        }
                                                    }
                                                }
                                                ActiveView::AgentInspector => {
                                                    if let Some(id) = agent_id {
                                                        if let Ok(res) = api.get_logs(Some(&id), interval, 0, 100, filter.as_ref()).await {
                                                            if let Some(hits) = res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                                let _ = tx.send(crate::app::DataUpdate::AgentLogs(hits.clone())).await;
                                                            }
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                        });
                                        app.stop_loading();
                                    }
                                    app.popup_mode = crate::app::PopupMode::None;
                                }
                                crate::app::PopupMode::SshUsername { agent_id: _, agent_ip } => {
                                    let username = app.input_buffer.clone();
                                    if !username.is_empty() && !agent_ip.is_empty() {
                                        let ssh_cmd = format!("ssh {}@{}", username, agent_ip);
                                        // Try common terminal emulators
                                        let terminals = [
                                            ("xdg-terminal", vec![ssh_cmd.clone()]),
                                            ("gnome-terminal", vec!["--".to_string(), "bash".to_string(), "-c".to_string(), format!("{}; exec bash", ssh_cmd)]),
                                            ("konsole", vec!["-e".to_string(), ssh_cmd.clone()]),
                                            ("wezterm", vec!["start".to_string(), "--".to_string(), "bash".to_string(), "-c".to_string(), format!("{}; exec bash", ssh_cmd)]),
                                            ("alacritty", vec!["-e".to_string(), "bash".to_string(), "-c".to_string(), format!("{}; exec bash", ssh_cmd)]),
                                            ("kitty", vec!["bash".to_string(), "-c".to_string(), format!("{}; exec bash", ssh_cmd)]),
                                            ("foot", vec!["bash".to_string(), "-c".to_string(), format!("{}; exec bash", ssh_cmd)]),
                                            ("xterm", vec!["-e".to_string(), ssh_cmd.clone()]),
                                        ];
                                        
                                        let mut spawned = false;
                                        let mut last_error = String::new();

                                        for (t, args) in terminals {
                                            match std::process::Command::new(t)
                                                .args(&args)
                                                .stdin(std::process::Stdio::null())
                                                .stdout(std::process::Stdio::null())
                                                .stderr(std::process::Stdio::null())
                                                .spawn() 
                                            {
                                                Ok(_) => {
                                                    spawned = true;
                                                    app.notify(&format!("SSH session started in {}", t), crate::app::NotificationLevel::Success);
                                                    break;
                                                }
                                                Err(e) => {
                                                    last_error = e.to_string();
                                                }
                                            }
                                        }
                                        if !spawned {
                                            app.notify(&format!("Failed to launch SSH: {}", last_error), crate::app::NotificationLevel::Error);
                                        }
                                    }
                                    app.popup_mode = crate::app::PopupMode::None;
                                }
                                crate::app::PopupMode::Error { .. } => {
                                    // Just close the error popup
                                    app.popup_mode = crate::app::PopupMode::None;
                                }
                                _ => {}
                            }
                        } else if app.show_interval_popup {
                            if let Err(e) = app.parse_and_set_interval() {
                                app.error_message = Some(e);
                            } else {
                                if let Some(api) = app.api.clone() {
                                    app.set_loading("Refreshing with new interval...");
                                    let tx = tx.clone();
                                    let active_view = app.active_view.clone();
                                    let agent_id = app.get_selected_agent().map(|a| a.id.clone());
                                    let interval = app.log_interval_mins;
                                    
                                    tokio::spawn(async move {
                                        match active_view {
                                            ActiveView::SecurityEvents => {
                                                if let Ok(res) = api.get_logs(None, interval, app.log_offset, app.log_limit, None).await {
                                                    if let Some(hits) = res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                        let _ = tx.send(crate::app::DataUpdate::SecurityEvents(hits.clone())).await;
                                                    }
                                                }
                                            }
                                            ActiveView::AgentInspector => {
                                                if let Some(id) = agent_id {
                                                    match api.get_vulnerabilities(&id).await {
                                                        Ok(vuln_res) => {
                                                            let _ = tx.send(crate::app::DataUpdate::AgentVulnerabilities(vuln_res.data.affected_items)).await;
                                                        }
                                                        Err(e) => {
                                                            let _ = tx.send(crate::app::DataUpdate::Error(format!("Failed to load vulnerabilities: {}", e))).await;
                                                        }
                                                    }
                                                    if let Ok(res) = api.get_logs(Some(&id), interval, 0, 100, None).await {
                                                        if let Some(hits) = res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                            let _ = tx.send(crate::app::DataUpdate::AgentLogs(hits.clone())).await;
                                                        }
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    });
                                    app.stop_loading();
                                }
                            }
                        } else if app.is_config_wizard_active {
                            match app.config_step {
                                crate::app::ConfigStep::Url => {
                                    if !app.config_url.is_empty() {
                                        if app.config_os_url.is_empty() {
                                             if let Ok(u) = reqwest::Url::parse(&app.config_url) {
                                                app.config_os_url = format!("{}://{}:9200", u.scheme(), u.host_str().unwrap_or(""));
                                             }
                                        }
                                        app.config_step = crate::app::ConfigStep::OsUrl;
                                    }
                                }
                                crate::app::ConfigStep::OsUrl => { app.config_step = crate::app::ConfigStep::Username; }
                                crate::app::ConfigStep::Username => { app.config_step = crate::app::ConfigStep::Password; }
                                crate::app::ConfigStep::Password => { app.config_step = crate::app::ConfigStep::Confirm; }
                                crate::app::ConfigStep::Confirm => {
                                    let config = crate::models::Config {
                                        url: app.config_url.clone(),
                                        username: app.config_username.clone(),
                                        password: app.config_password.clone(),
                                        os_url: Some(app.config_os_url.clone()),
                                        os_username: Some(app.config_username.clone()),
                                        os_password: Some(app.config_username.clone()),
                                    };
                                    if let Ok(_) = ConfigManager::save(&config) {
                                        let api = WazuhApi::new(config);
                                        app.set_api(api);
                                        app.is_config_wizard_active = false;
                                        app.active_view = ActiveView::Dashboard;
                                        app.set_loading("Fetching agents...");
                                        if let Some(api) = &app.api {
                                            if let Ok(res) = api.list_agents(None, 0, 500).await {
                                                app.agents = res.data.affected_items;
                                                app.sort_agents();
                                            }
                                        }
                                        app.stop_loading();
                                    }
                                }
                            }
                        } else if app.active_view == ActiveView::GroupManagement {
                             if let Some(group) = app.get_selected_group() {
                                 let api = app.api.as_ref().unwrap().clone();
                                 let tx = tx.clone();
                                 let group_name = group.name.clone();
                                 tokio::spawn(async move {
                                     if let Ok(res) = api.list_agents(Some(&group_name), 0, 500).await {
                                         let _ = tx.send(crate::app::DataUpdate::Agents(res.data.affected_items)).await;
                                     }
                                 });
                             }
                        } else if app.active_view == ActiveView::AgentList {
                            if let Some(agent) = app.get_selected_agent() {
                                let agent_id = agent.id.clone();
                                app.active_view = ActiveView::AgentInspector;
                                app.set_loading("Loading agent details...");
                                app.error_message = None;
                                if let Some(api) = &app.api {
                                    let api = api.clone();
                                    let tx = tx.clone();
                                    let interval = app.log_interval_mins;
                                    let config_component = app.agent_config_component.clone();
                                    
                                    tokio::spawn(async move {
                                        if let Ok(hw_res) = api.get_hardware_info(&agent_id).await {
                                            if let Some(hw) = hw_res.data.affected_items.into_iter().next() {
                                                let _ = tx.send(crate::app::DataUpdate::AgentHardware(hw)).await;
                                            }
                                        }
                                        if let Ok(proc_res) = api.get_processes(&agent_id).await {
                                            let _ = tx.send(crate::app::DataUpdate::AgentProcesses(proc_res.data.affected_items)).await;
                                        }
                                        if let Ok(prog_res) = api.get_programs(&agent_id).await {
                                            let _ = tx.send(crate::app::DataUpdate::AgentPrograms(prog_res.data.affected_items)).await;
                                        }
                                        match api.get_vulnerabilities(&agent_id).await {
                                            Ok(vuln_res) => {
                                                let _ = tx.send(crate::app::DataUpdate::AgentVulnerabilities(vuln_res.data.affected_items)).await;
                                            }
                                            Err(e) => {
                                                let _ = tx.send(crate::app::DataUpdate::Error(format!("Failed to load vulnerabilities: {}", e))).await;
                                            }
                                        }
                                        if let Ok(logs_res) = api.get_logs(Some(&agent_id), interval, 0, 100, None).await {
                                            if let Some(hits) = logs_res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                                let _ = tx.send(crate::app::DataUpdate::AgentLogs(hits.clone())).await;
                                            }
                                        }
                                        match api.get_agent_config(&agent_id, &config_component).await {
                                            Ok(config_res) => {
                                                let _ = tx.send(crate::app::DataUpdate::AgentConfig(config_res)).await;
                                            }
                                            Err(e) => {
                                                let _ = tx.send(crate::app::DataUpdate::Error(format!("Failed to load config: {}", e))).await;
                                            }
                                        }
                                    });
                                }
                                app.stop_loading();
                            }
                        } else if app.active_view == ActiveView::AgentInspector && app.inspector_tab == crate::app::InspectorTab::Config {
                            // Cycle through config components
                            let current_idx = app.available_config_components.iter().position(|c| c == &app.agent_config_component).unwrap_or(0);
                            let next_idx = (current_idx + 1) % app.available_config_components.len();
                            app.agent_config_component = app.available_config_components[next_idx].clone();
                            
                            if let (Some(api), Some(agent)) = (&app.api, app.get_selected_agent()) {
                                let api = api.clone();
                                let tx = tx.clone();
                                let agent_id = agent.id.clone();
                                let component = app.agent_config_component.clone();
                                app.agent_config = None; // Reset to show loading
                                tokio::spawn(async move {
                                    match api.get_agent_config(&agent_id, &component).await {
                                        Ok(config_res) => {
                                            let _ = tx.send(crate::app::DataUpdate::AgentConfig(config_res)).await;
                                        }
                                        Err(e) => {
                                            let _ = tx.send(crate::app::DataUpdate::Error(format!("Failed to load config: {}", e))).await;
                                        }
                                    }
                                });
                            }
                        } else if app.active_view == ActiveView::AgentInspector || app.active_view == ActiveView::SecurityEvents {
                            if app.selected_log.is_some() {
                                app.show_log_json = !app.show_log_json;
                            } else {
                                let log = match app.active_view {
                                    ActiveView::AgentInspector if app.inspector_tab == crate::app::InspectorTab::Logs => {
                                        let idx = app.inspector_table_state.selected().unwrap_or(0);
                                        app.agent_logs.get(idx).cloned()
                                    }
                                    ActiveView::SecurityEvents => {
                                        let idx = app.table_state.selected().unwrap_or(0);
                                        app.logs.get(idx).cloned()
                                    }
                                    _ => None,
                                };

                                if let Some(l) = log {
                                    app.selected_log = Some(l);
                                    app.log_scroll_offset = 0; // Reset scroll for new log
                                }
                            }
                        }
                    }
                    KeyCode::Down => {
                         if app.selected_log.is_some() {
                             // Scroll down in log detail view
                             app.log_scroll_offset = app.log_scroll_offset.saturating_add(1);
                         } else if matches!(app.popup_mode, crate::app::PopupMode::SeverityFilter) {
                             match app.filter_popup_tab {
                                 crate::app::FilterPopupTab::Severity => {
                                     // Down decreases severity value
                                     if app.filter_active_input == 0 {
                                         let val = app.filter_input_1.parse::<u32>().unwrap_or(0);
                                         app.filter_input_1 = val.saturating_sub(1).to_string();
                                     } else {
                                         let val = app.filter_input_2.parse::<u32>().unwrap_or(0);
                                         app.filter_input_2 = val.saturating_sub(1).to_string();
                                     }
                                 }
                                 crate::app::FilterPopupTab::Rule => {
                                     // Switch between rule_id and mitre fields
                                     app.filter_active_input = (app.filter_active_input + 1) % 2;
                                 }
                                 crate::app::FilterPopupTab::Columns => {
                                     // Navigate column list
                                     let len = crate::app::LogColumn::all().len();
                                     if len > 0 {
                                         app.column_selection_index = (app.column_selection_index + 1) % len;
                                     }
                                 }
                                 _ => {}
                             }
                         } else if matches!(app.popup_mode, crate::app::PopupMode::CommandPalette) {
                              let matches_len = app.get_command_palette_matches().len();
                              if matches_len > 0 {
                                  app.command_palette_index = (app.command_palette_index + 1) % matches_len;
                              }
                         } else if matches!(app.popup_mode, crate::app::PopupMode::AgentJump) {
                              let matches_len = app.get_jump_matches().len();
                              if matches_len > 0 {
                                  app.jump_index = (app.jump_index + 1) % matches_len;
                              }
                         } else if app.active_view == ActiveView::AgentInspector {
                              app.scroll_down(1);
                         } else if app.active_view == ActiveView::Dashboard {
                              // No table selection in dashboard
                         } else {
                              app.next_item();
                         }
                    }
                    KeyCode::Up => {
                         if app.selected_log.is_some() {
                             // Scroll up in log detail view
                             app.log_scroll_offset = app.log_scroll_offset.saturating_sub(1);
                         } else if matches!(app.popup_mode, crate::app::PopupMode::SeverityFilter) {
                             match app.filter_popup_tab {
                                 crate::app::FilterPopupTab::Severity => {
                                     // Up increases severity value
                                     if app.filter_active_input == 0 {
                                         let val = app.filter_input_1.parse::<u32>().unwrap_or(0);
                                         app.filter_input_1 = val.saturating_add(1).min(20).to_string();
                                     } else {
                                         let val = app.filter_input_2.parse::<u32>().unwrap_or(0);
                                         app.filter_input_2 = val.saturating_add(1).min(20).to_string();
                                     }
                                 }
                                 crate::app::FilterPopupTab::Rule => {
                                     // Switch between rule_id and mitre fields
                                     if app.filter_active_input == 0 {
                                         app.filter_active_input = 1;
                                     } else {
                                         app.filter_active_input = 0;
                                     }
                                 }
                                 crate::app::FilterPopupTab::Columns => {
                                     // Navigate column list
                                     let len = crate::app::LogColumn::all().len();
                                     if len > 0 {
                                         if app.column_selection_index == 0 {
                                             app.column_selection_index = len - 1;
                                         } else {
                                             app.column_selection_index -= 1;
                                         }
                                     }
                                 }
                                 _ => {}
                             }
                         } else if matches!(app.popup_mode, crate::app::PopupMode::CommandPalette) {
                              let matches_len = app.get_command_palette_matches().len();
                              if matches_len > 0 {
                                  if app.command_palette_index == 0 {
                                      app.command_palette_index = matches_len - 1;
                                  } else {
                                      app.command_palette_index -= 1;
                                  }
                              }
                         } else if matches!(app.popup_mode, crate::app::PopupMode::AgentJump) {
                              let matches_len = app.get_jump_matches().len();
                              if matches_len > 0 {
                                  if app.jump_index == 0 {
                                      app.jump_index = matches_len - 1;
                                  } else {
                                      app.jump_index -= 1;
                                  }
                              }
                         } else if app.active_view == ActiveView::AgentInspector {
                              app.scroll_up(1);
                         } else if app.active_view == ActiveView::Dashboard {
                              // No table selection in dashboard
                         } else {
                              app.previous_item();
                         }
                    }
                    KeyCode::Left => {
                        if matches!(app.popup_mode, crate::app::PopupMode::SeverityFilter) {
                            match app.filter_popup_tab {
                                crate::app::FilterPopupTab::Severity => {
                                    if app.log_filter.mode == crate::app::SeverityFilterMode::Range {
                                        app.filter_active_input = 0; // Focus on min field
                                    }
                                }
                                crate::app::FilterPopupTab::Rule => {
                                    app.filter_active_input = 0; // Focus on rule_id field
                                }
                                _ => {}
                            }
                        }
                    }
                    KeyCode::Right => {
                        if matches!(app.popup_mode, crate::app::PopupMode::SeverityFilter) {
                            match app.filter_popup_tab {
                                crate::app::FilterPopupTab::Severity => {
                                    if app.log_filter.mode == crate::app::SeverityFilterMode::Range {
                                        app.filter_active_input = 1; // Focus on max field
                                    }
                                }
                                crate::app::FilterPopupTab::Rule => {
                                    app.filter_active_input = 1; // Focus on mitre field
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.clear_old_notifications();
            if app.is_loading {
                app.spinner_index = app.spinner_index.wrapping_add(1);
            }
            last_tick = Instant::now();
        }

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    Ok(())
}
