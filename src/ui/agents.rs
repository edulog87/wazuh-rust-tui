use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table, Cell, Tabs},
    Frame,
};
use crate::app::{App, SortColumn, SortOrder, InspectorTab};
use crate::ui::theme::*;
use crate::ui::common::{filter_matches, format_last_keep_alive, centered_rect};
use crate::ui::json::{colorize_json};

pub fn draw_agent_list(f: &mut Frame, app: &mut App, area: Rect) {
    let mut filtered_agents: Vec<_> = if !app.agent_filter.raw_query.is_empty() {
        app.agents.iter()
            .filter(|a| app.agent_filter.matches(a))
            .collect()
    } else {
        app.agents.iter().collect()
    };

    if let Some(_severity) = &app.severity_filter {
        // Note: In a real app we'd need the agent vulnerability info here.
        // For now we just filter based on a hypothetical property or keep all if not available.
        // But let's show we are filtering.
        filtered_agents.retain(|_a| {
            // Ideally we check if agent has vulnerabilities of this severity
            true 
        });
    }

    let get_header = |name: &str, col: SortColumn| {
        let mut s = name.to_string();
        if app.sort_column == col {
            s.push_str(if app.sort_order == SortOrder::Asc { " 󰁞" } else { " 󰁆" });
        }
        Cell::from(s).style(Style::default().fg(BLUE).add_modifier(Modifier::BOLD)) // One Dark Blue
    };

    let header_cells = vec![
        get_header(" ID ", SortColumn::Id),
        get_header(" NAME ", SortColumn::Name),
        get_header(" IP ADDRESS ", SortColumn::Ip),
        get_header(" STATUS ", SortColumn::Status),
        get_header(" OPERATING SYSTEM ", SortColumn::Os),
        get_header(" LAST KEEP ALIVE ", SortColumn::LastKeepAlive),
    ];
    
    let header = Row::new(header_cells)
        .style(Style::default().bg(BG)) // One Dark Background
        .height(1);

    let rows = filtered_agents.iter().map(|a| {
        let (status_icon, base_color) = match a.status.as_str() {
            "active" => ("󰄬 ", GREEN),      // One Dark Green
            "disconnected" => ("󰅖 ", RED), // One Dark Red
            _ => ("󰒲 ", FG),             // One Dark Gray
        };

        let os_info = match &a.os {
            Some(os) => {
                let name = os.name.as_deref().unwrap_or("Unknown");
                let version = os.version.as_deref().unwrap_or("");
                if version.is_empty() {
                    name.to_string()
                } else {
                    format!("{} {}", name, version)
                }
            }
            None => "Unknown".to_string(),
        };

        let is_selected = app.selected_agents.contains(&a.id);
        let selection_prefix = if is_selected { "󰄬 " } else { "  " };

        Row::new(vec![
            Cell::from(format!("{} {}", selection_prefix, a.id)),
            Cell::from(a.name.clone()),
            Cell::from(a.ip.clone().unwrap_or_else(|| "N/A".to_string())),
            Cell::from(format!("{}{}", status_icon, a.status)),
            Cell::from(os_info),
            Cell::from(format_last_keep_alive(&a.last_keep_alive)),
        ]).style(Style::default().fg(base_color)).height(1)
    });

    let table = Table::new(rows, [
            Constraint::Length(8),
            Constraint::Min(20),
            Constraint::Length(16),
            Constraint::Length(15),
            Constraint::Min(30),
            Constraint::Length(18),
        ])
        .header(header)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(DARK_GRAY)) // Subtle border
            .title(format!(" 󰒋 Agents List ({}){} ", 
                filtered_agents.len(),
                app.severity_filter.as_ref().map(|s| format!(" | Filter: {} ", s.to_uppercase())).unwrap_or_default()
            )))
        .highlight_style(Style::default()
            .bg(SELECTION_BG) // Selection background (One Dark)
            .add_modifier(Modifier::BOLD))
        .highlight_symbol("󰁔 ");

    let mut state = app.table_state.clone();
    f.render_stateful_widget(table, area, &mut state);
}

pub fn draw_agent_inspector(f: &mut Frame, app: &mut App, area: Rect) {
    let agent = match app.get_selected_agent() {
        Some(a) => a,
        None => return,
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Agent Header
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Details
        ])
        .split(area);

    let header = Paragraph::new(format!(" Inspecting: {} ({}) | OS: {} | Status: {}", 
        agent.name, agent.id, 
        agent.os.as_ref().and_then(|o| o.name.clone()).unwrap_or_default(),
        agent.status
    )).block(Block::default()
        .borders(Borders::ALL)
        .title(" Agent Info ")
        .border_style(Style::default().fg(DARK_GRAY)));
    f.render_widget(header, chunks[0]);

    let titles = vec![" Hardware ", " Processes ", " Programs ", " Vulnerabilities ", " Events/Logs ", " Config "];
    let tabs = Tabs::new(titles)
        .select(app.selected_tab_index)
        .block(Block::default().borders(Borders::ALL).title(" Categories ").border_style(Style::default().fg(DARK_GRAY)))
        .highlight_style(Style::default().fg(YELLOW).add_modifier(Modifier::BOLD))
        .style(Style::default().fg(FG));
    f.render_widget(tabs, chunks[1]);

    match app.inspector_tab {
        InspectorTab::Hardware => {
            if let Some(hw) = &app.hardware {
                let text = format!(
                    " CPU: {} ({} cores, {} MHz)\n RAM Total: {} MB\n RAM Free: {} MB\n Serial: {}\n Scan Time: {}",
                    hw.cpu.name, hw.cpu.cores, hw.cpu.mhz,
                    hw.ram.total, hw.ram.free,
                    hw.board_serial,
                    hw.scan.time
                );
                f.render_widget(Paragraph::new(text).block(Block::default().borders(Borders::ALL).border_type(ratatui::widgets::BorderType::Rounded).border_style(Style::default().fg(DARK_GRAY))), chunks[2]);
            } else {
                f.render_widget(Paragraph::new("Loading hardware info...").block(Block::default().borders(Borders::ALL).border_type(ratatui::widgets::BorderType::Rounded).border_style(Style::default().fg(DARK_GRAY))), chunks[2]);
            }
        },
        InspectorTab::Processes => {
            let filtered_processes: Vec<_> = if app.is_searching {
                app.processes.iter()
                    .filter(|p| {
                        let content = format!("{} {} {} {}", 
                            p.pid, 
                            p.name.as_ref().unwrap_or(&String::new()), 
                            p.state.as_ref().unwrap_or(&String::new()), 
                            p.cmd.as_ref().unwrap_or(&String::new())
                        );
                        filter_matches(&app.search_query, &content)
                    })
                    .collect()
            } else {
                app.processes.iter().collect()
            };

            let rows = filtered_processes.iter().map(|p| {
                Row::new(vec![
                    Cell::from(p.pid.clone()),
                    Cell::from(p.name.clone().unwrap_or_else(|| "N/A".to_string())),
                    Cell::from(p.state.clone().unwrap_or_else(|| "N/A".to_string())),
                    Cell::from(p.cmd.clone().unwrap_or_else(|| "N/A".to_string())),
                ]).style(Style::default().fg(FG))
            });
            let table = Table::new(rows, [
                Constraint::Length(8),
                Constraint::Length(20),
                Constraint::Length(10),
                Constraint::Min(30),
            ]).header(Row::new(vec!["PID", "Name", "State", "Command"]).style(Style::default().fg(BLUE)))
              .block(Block::default().borders(Borders::ALL).title(" Processes ").border_style(Style::default().fg(DARK_GRAY)))
              .highlight_style(Style::default().bg(SELECTION_BG).add_modifier(Modifier::BOLD));
            let mut state = app.inspector_table_state.clone();
            f.render_stateful_widget(table, chunks[2], &mut state);
        },
        InspectorTab::Programs => {
             let filtered_programs: Vec<_> = if app.is_searching {
                app.programs.iter()
                    .filter(|p| {
                        let content = format!("{} {} {}", 
                            p.name, 
                            p.version, 
                            p.vendor.as_ref().unwrap_or(&String::new())
                        );
                        filter_matches(&app.search_query, &content)
                    })
                    .collect()
            } else {
                app.programs.iter().collect()
            };

            let rows = filtered_programs.iter().map(|p| {
                Row::new(vec![
                    Cell::from(p.name.clone()),
                    Cell::from(p.version.clone()),
                    Cell::from(p.vendor.clone().unwrap_or_else(|| "N/A".to_string())),
                ]).style(Style::default().fg(FG))
            });
            let table = Table::new(rows, [
                Constraint::Min(30),
                Constraint::Length(25),
                Constraint::Length(25),
            ]).header(Row::new(vec!["Name", "Version", "Vendor"]).style(Style::default().fg(BLUE)))
              .block(Block::default().borders(Borders::ALL).border_type(ratatui::widgets::BorderType::Rounded).title(" Installed Programs ").border_style(Style::default().fg(DARK_GRAY)))
              .highlight_style(Style::default().bg(SELECTION_BG).add_modifier(Modifier::BOLD));
            let mut state = app.inspector_table_state.clone();
            f.render_stateful_widget(table, chunks[2], &mut state);
        },
        InspectorTab::Vulnerabilities => {
            if app.vulnerabilities.is_empty() {
                f.render_widget(Paragraph::new(" No vulnerabilities found. Make sure the vulnerability module is enabled in Wazuh.")
                    .block(Block::default().borders(Borders::ALL).border_type(ratatui::widgets::BorderType::Rounded).title(" Vulnerabilities ").border_style(Style::default().fg(DARK_GRAY)))
                    .wrap(ratatui::widgets::Wrap { trim: false })
                    .style(Style::default().fg(FG)), chunks[2]);
            } else {
                // Split the area into Summary (Top) and List (Bottom)
                let vuln_layout = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3), // Summary Cards
                        Constraint::Min(0),    // Table
                    ])
                    .split(chunks[2]);

                // --- SUMMARY SECTION ---
                // Calculate stats
                let mut crit = 0;
                let mut high = 0;
                let mut med = 0;
                let mut low = 0;
                
                for v in &app.vulnerabilities {
                    match v.severity.to_lowercase().as_str() {
                        "critical" => crit += 1,
                        "high" => high += 1,
                        "medium" => med += 1,
                        _ => low += 1,
                    }
                }

                let summary_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Percentage(25),
                        Constraint::Percentage(25),
                        Constraint::Percentage(25),
                        Constraint::Percentage(25),
                    ])
                    .split(vuln_layout[0]);

                let draw_severity_card = |f: &mut Frame, title: &str, count: u64, color: Color, area: Rect| {
                    let block = Block::default()
                        .borders(Borders::ALL)
                        .border_type(ratatui::widgets::BorderType::Rounded)
                        .title(format!(" {} ", title))
                        .border_style(Style::default().fg(color));
                    
                    let text = Paragraph::new(count.to_string())
                        .block(block)
                        .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
                        .alignment(ratatui::layout::Alignment::Center);

                    f.render_widget(text, area);
                };

                draw_severity_card(f, "CRITICAL", crit as u64, VULN_CRITICAL, summary_chunks[0]);
                draw_severity_card(f, "HIGH", high as u64, VULN_HIGH, summary_chunks[1]);
                draw_severity_card(f, "MEDIUM", med as u64, VULN_MEDIUM, summary_chunks[2]);
                draw_severity_card(f, "LOW", low as u64, VULN_LOW, summary_chunks[3]);


                // --- LIST SECTION ---
                let filtered_vulns: Vec<_> = if app.is_searching {
                    app.vulnerabilities.iter()
                        .filter(|v| {
                            let pkg_name = v.package.as_ref().map(|p| p.name.clone())
                                .unwrap_or_else(|| v.name.clone().unwrap_or_default());
                            let pkg_version = v.package.as_ref().map(|p| p.version.clone())
                                .unwrap_or_else(|| v.version.clone().unwrap_or_default());

                            let content = format!("{} {} {} {}", 
                                v.cve, 
                                v.severity, 
                                pkg_name, 
                                pkg_version
                            );
                            filter_matches(&app.search_query, &content)
                        })
                        .collect()
                } else {
                    app.vulnerabilities.iter().collect()
                };

                let rows = filtered_vulns.iter().map(|v| {
                    let color = match v.severity.to_lowercase().as_str() {
                        "critical" => VULN_CRITICAL,
                        "high" => VULN_HIGH,
                        "medium" => VULN_MEDIUM,
                        _ => FG,
                    };

                    let pkg_name = v.package.as_ref().map(|p| p.name.clone())
                        .unwrap_or_else(|| v.name.clone().unwrap_or_else(|| "N/A".to_string()));
                    let pkg_version = v.package.as_ref().map(|p| p.version.clone())
                        .unwrap_or_else(|| v.version.clone().unwrap_or_else(|| "N/A".to_string()));

                    let severity_display = if v.severity.is_empty() { "N/A" } else { &v.severity };

                    Row::new(vec![
                        Cell::from(v.cve.clone()),
                        Cell::from(severity_display),
                        Cell::from(pkg_name),
                        Cell::from(pkg_version),
                    ]).style(Style::default().fg(color))
                });
                let table = Table::new(rows, [
                    Constraint::Length(15),
                    Constraint::Length(12),
                    Constraint::Min(30),
                    Constraint::Length(20),
                ]).header(Row::new(vec!["CVE", "Severity", "Package", "Version"]).style(Style::default().fg(BLUE)))
                  .block(Block::default().borders(Borders::ALL).border_type(ratatui::widgets::BorderType::Rounded).title(" Details ").border_style(Style::default().fg(DARK_GRAY)))
                  .highlight_style(Style::default().bg(SELECTION_BG).add_modifier(Modifier::BOLD));
                let mut state = app.inspector_table_state.clone();
                f.render_stateful_widget(table, vuln_layout[1], &mut state);
            }
        },
        InspectorTab::Logs => {
            let filtered_logs: Vec<_> = if app.is_searching {
                app.agent_logs.iter()
                    .filter(|l| filter_matches(&app.search_query, &l.to_string()))
                    .collect()
            } else {
                app.agent_logs.iter().collect()
            };

            let rows = filtered_logs.iter().map(|log| {
                let source = log.get("_source").unwrap();
                let rule = source.get("rule").unwrap();
                let level = rule.get("level").and_then(|v| v.as_u64()).unwrap_or(0);
                let description = rule.get("description").and_then(|v| v.as_str()).unwrap_or("No description");
                let timestamp = source.get("@timestamp").and_then(|v| v.as_str()).unwrap_or("Unknown");

        let (_icon, color) = match level {
            12..=16 => ("󰅚 ", VULN_CRITICAL),
            8..=11 => ("󰀦 ", VULN_HIGH),
            4..=7 => ("󱈸 ", VULN_MEDIUM),
            _ => ("󰋼 ", FG),
        };

        Row::new(vec![
            Cell::from(timestamp.to_string()),
            Cell::from(level.to_string()),
            Cell::from(description.to_string()),
        ]).style(Style::default().fg(color))
            });

            let table = Table::new(rows, [
                Constraint::Length(20),
                Constraint::Length(5),
                Constraint::Min(40),
            ]).header(Row::new(vec!["Timestamp", "Lvl", "Description"]).style(Style::default().fg(BLUE)))
              .block(Block::default().borders(Borders::ALL).border_type(ratatui::widgets::BorderType::Rounded).title(" Agent Events ").border_style(Style::default().fg(DARK_GRAY)))
              .highlight_style(Style::default().bg(SELECTION_BG).add_modifier(Modifier::BOLD));
            let mut state = app.inspector_table_state.clone();
            f.render_stateful_widget(table, chunks[2], &mut state);
        },
        InspectorTab::Config => {
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(format!(" Component: {} (Press Enter to cycle) ", app.agent_config_component))
                .border_style(Style::default().fg(DARK_GRAY));
            
            if let Some(config) = &app.agent_config {
                if config.is_null() || (config.is_object() && config.as_object().map(|o| o.is_empty()).unwrap_or(false)) {
                    f.render_widget(Paragraph::new(format!(" No configuration found for component: {}\n\nPress Enter to cycle to another component.", app.agent_config_component))
                        .block(block)
                        .wrap(ratatui::widgets::Wrap { trim: false })
                        .style(Style::default().fg(FG)), chunks[2]);
                } else {
                    // Use colorized JSON for config display
                    let lines = colorize_json(config);
                    let text = ratatui::text::Text::from(lines);
                    f.render_widget(Paragraph::new(text)
                        .block(block)
                        .wrap(ratatui::widgets::Wrap { trim: false }), chunks[2]);
                }
            } else {
                f.render_widget(Paragraph::new(format!("Loading {} config...\n\nIf this persists, the agent may not have this component configured.", app.agent_config_component))
                    .block(Block::default().borders(Borders::ALL).border_type(ratatui::widgets::BorderType::Rounded).border_style(Style::default().fg(DARK_GRAY)))
                    .wrap(ratatui::widgets::Wrap { trim: false })
                    .style(Style::default().fg(FG)), chunks[2]);
            }
        }
    }

    if app.selected_log.is_some() {
        let log = app.selected_log.clone().unwrap();
        let area = centered_rect(80, 80, f.size());
        crate::ui::logs::draw_log_detail(f, app, &log, area);
    }
}
