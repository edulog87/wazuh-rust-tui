use ratatui::{
    layout::{Constraint, Direction, Layout, Rect, Alignment},
    style::{Modifier, Style},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap, Tabs},
    text::{Span, Line},
    Frame,
};
use crate::app::{App, PopupMode, SeverityFilterMode, FilterPopupTab, LogColumn};
use crate::ui::theme::*;
use crate::ui::common::centered_rect;

fn draw_popup_shell<'a>(f: &mut Frame, title: &str, percent_x: u16, percent_y: u16, border_style: Style) -> (Rect, Block<'a>) {
    let area = centered_rect(percent_x, percent_y, f.size());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(border_style)
        .title(format!(" {} ", title));
    (area, block)
}

fn get_severity_style(level: u64) -> Style {
    let color = match level {
        15..=u64::MAX => VULN_CRITICAL,
        12..=14 => VULN_HIGH,
        7..=11 => VULN_MEDIUM,
        _ => VULN_LOW,
    };
    Style::default().fg(color)
}

fn get_severity_label(level: u64) -> &'static str {
    match level {
        15..=u64::MAX => "Critical",
        12..=14 => "High",
        7..=11 => "Medium",
        _ => "Low",
    }
}

pub fn draw_popup(f: &mut Frame, app: &mut App) {
    match &app.popup_mode {
        PopupMode::GroupAssignment { agent_id: _ } => {
            let (area, block) = draw_popup_shell(f, "Assign Agent to Groups", 40, 50, Style::default().fg(BLUE));
            
            let list_items: Vec<_> = app.groups.iter().map(|g| {
                ListItem::new(Line::from(vec![
                    Span::styled(format!(" 󰒲 {} ", g.name), Style::default().fg(FG)),
                ]))
            }).collect();
            
            let list = List::new(list_items)
                .block(block)
                .highlight_style(Style::default().bg(SELECTION_BG).add_modifier(Modifier::BOLD))
                .highlight_symbol("󰁔 ");
            
            let mut state = ListState::default();
            state.select(app.groups_table_state.selected());
            f.render_stateful_widget(list, area, &mut state);
        },
        PopupMode::SeverityFilter => {
            draw_advanced_filter_popup(f, app);
        },
        PopupMode::SshUsername { agent_id, agent_ip } => {
            let (area, block) = draw_popup_shell(f, &format!("SSH to {} ({})", agent_id, agent_ip), 40, 20, Style::default().fg(YELLOW));
            
            let p = Paragraph::new(format!(" Enter SSH Username:\n\n {}█\n\n [Enter] Launch SSH  [Esc] Cancel ", app.input_buffer))
                .block(block)
                .alignment(Alignment::Center)
                .style(Style::default().fg(FG));
            f.render_widget(p, area);
        },
        PopupMode::AgentJump => {
            let (area, block) = draw_popup_shell(f, "Quick Agent Jump (Autocomplete)", 50, 40, Style::default().fg(YELLOW).add_modifier(Modifier::BOLD));
            f.render_widget(block, area);
            
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(0),
                ])
                .margin(1)
                .split(area);

            let input = Paragraph::new(format!(" 󰍉 Query: {}█ ", app.jump_input))
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(DARK_GRAY)));
            f.render_widget(input, chunks[0]);

            let matches = app.get_jump_matches();
            let items: Vec<_> = matches.iter().enumerate().map(|(i, a)| {
                let style = if i == app.jump_index {
                    Style::default().fg(BLUE).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(FG)
                };
                let status_color = match a.status.as_str() {
                    "active" => GREEN,
                    "disconnected" => RED,
                    _ => DARK_GRAY,
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!(" {:<8} ", a.id), Style::default().fg(DARK_GRAY)),
                    Span::styled(format!(" {:<20} ", a.name), style),
                    Span::styled(format!(" {} ", a.status), Style::default().fg(status_color)),
                ]))
            }).collect();

            let list = List::new(items)
                .block(Block::default().borders(Borders::NONE))
                .highlight_style(Style::default().bg(SELECTION_BG))
                .highlight_symbol("󰁔 ");
            f.render_widget(list, chunks[1]);
        },
        PopupMode::CommandPalette => {
            let (area, block) = draw_popup_shell(f, "Command Palette", 50, 40, Style::default().fg(BLUE).add_modifier(Modifier::BOLD));
            f.render_widget(block, area);
            
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(0),
                ])
                .margin(1)
                .split(area);

            let input = Paragraph::new(format!(" > {}█ ", app.command_palette_input))
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(DARK_GRAY)));
            f.render_widget(input, chunks[0]);

            let matches = app.get_command_palette_matches();
            let items: Vec<_> = matches.iter().enumerate().map(|(i, (name, desc))| {
                let style = if i == app.command_palette_index {
                    Style::default().bg(SELECTION_BG).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(FG)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!(" {:<20} ", name), style),
                    Span::styled(format!(" {} ", desc), Style::default().fg(DARK_GRAY)),
                ]))
            }).collect();

            let list = List::new(items)
                .block(Block::default().borders(Borders::NONE))
                .highlight_symbol("󰁔 ");
            f.render_widget(list, chunks[1]);
        },
        PopupMode::Error { title, message } => {
            let (area, block) = draw_popup_shell(f, title, 60, 40, Style::default().fg(RED).add_modifier(Modifier::BOLD));
            
            let p = Paragraph::new(format!("\n{}\n\n\n [Enter/Esc] Close ", message))
                .block(block)
                .alignment(Alignment::Center)
                .style(Style::default().fg(FG))
                .wrap(Wrap { trim: true });
            f.render_widget(p, area);
        },
        PopupMode::Help => {
            draw_help_popup(f, app);
        },
        _ => {}
    }
}

pub fn draw_interval_popup(f: &mut Frame, app: &mut App) {
    if app.show_interval_popup {
        let (area, block) = draw_popup_shell(f, "Set Custom Interval", 40, 20, Style::default().fg(GREEN));
        
        let p = Paragraph::new(format!(" Value: {} \n\n Examples: 30m, 2h, 1d \n (Enter to apply, Esc to cancel) ", app.interval_input))
            .block(block)
            .alignment(Alignment::Center)
            .style(Style::default().fg(FG));
        f.render_widget(p, area);
    }
}

fn draw_help_popup(f: &mut Frame, app: &App) {
    let (area, block) = draw_popup_shell(f, "Keyboard Shortcuts", 70, 80, Style::default().fg(BLUE).add_modifier(Modifier::BOLD));
    
    // Build help content based on current view
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("  GLOBAL KEYS", Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ?       ", Style::default().fg(CYAN)),
            Span::styled("Toggle this help", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  q       ", Style::default().fg(CYAN)),
            Span::styled("Quit / Go back", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  Tab     ", Style::default().fg(CYAN)),
            Span::styled("Switch view", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  r       ", Style::default().fg(CYAN)),
            Span::styled("Refresh data", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  /       ", Style::default().fg(CYAN)),
            Span::styled("Start search/filter", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("          ", Style::default().fg(CYAN)),
            Span::styled("Syntax: ", Style::default().fg(DARK_GRAY)),
            Span::styled("n:name st:active ip:10 os:linux sev:high", Style::default().fg(BLUE)),
        ]),
        Line::from(vec![
            Span::styled("  Esc     ", Style::default().fg(CYAN)),
            Span::styled("Cancel / Close popup", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  i       ", Style::default().fg(CYAN)),
            Span::styled("Set time interval", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  +/-     ", Style::default().fg(CYAN)),
            Span::styled("Adjust interval (+/- 15m)", Style::default().fg(FG)),
        ]),
        Line::from(""),
    ];
    
    // Add view-specific help
    match app.active_view {
        crate::app::ActiveView::Dashboard => {
            lines.push(Line::from(vec![
                Span::styled("  DASHBOARD", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  j       ", Style::default().fg(CYAN)),
                Span::styled("Quick jump to agent", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  1-4     ", Style::default().fg(CYAN)),
                Span::styled("Filter by severity (1=Critical, 4=Low)", Style::default().fg(FG)),
            ]));
        }
        crate::app::ActiveView::AgentList => {
            lines.push(Line::from(vec![
                Span::styled("  AGENTS LIST", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  Enter   ", Style::default().fg(CYAN)),
                Span::styled("Inspect selected agent", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Space   ", Style::default().fg(CYAN)),
                Span::styled("Toggle selection (multi-select)", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  s       ", Style::default().fg(CYAN)),
                Span::styled("Cycle sort column/order", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  U       ", Style::default().fg(CYAN)),
                Span::styled("Upgrade selected agents", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  R       ", Style::default().fg(CYAN)),
                Span::styled("Restart selected agents", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  G       ", Style::default().fg(CYAN)),
                Span::styled("Assign to group", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  h       ", Style::default().fg(CYAN)),
                Span::styled("SSH to agent", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  o       ", Style::default().fg(CYAN)),
                Span::styled("Open in browser", Style::default().fg(FG)),
            ]));
        }
        crate::app::ActiveView::AgentInspector => {
            lines.push(Line::from(vec![
                Span::styled("  AGENT INSPECTOR", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  Tab     ", Style::default().fg(CYAN)),
                Span::styled("Switch category tab", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Enter   ", Style::default().fg(CYAN)),
                Span::styled("View log detail / Cycle config", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  f       ", Style::default().fg(CYAN)),
                Span::styled("Filter logs by severity", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  e       ", Style::default().fg(CYAN)),
                Span::styled("Export logs to JSON", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  G       ", Style::default().fg(CYAN)),
                Span::styled("Assign to group", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  h       ", Style::default().fg(CYAN)),
                Span::styled("SSH to agent", Style::default().fg(FG)),
            ]));
        }
        crate::app::ActiveView::SecurityEvents => {
            lines.push(Line::from(vec![
                Span::styled("  SECURITY EVENTS", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  Enter   ", Style::default().fg(CYAN)),
                Span::styled("View event detail", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  f       ", Style::default().fg(CYAN)),
                Span::styled("Filter by severity", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  e       ", Style::default().fg(CYAN)),
                Span::styled("Export to JSON", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  PgUp    ", Style::default().fg(CYAN)),
                Span::styled("Previous page", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  PgDn    ", Style::default().fg(CYAN)),
                Span::styled("Next page", Style::default().fg(FG)),
            ]));
        }
        crate::app::ActiveView::GroupManagement => {
            lines.push(Line::from(vec![
                Span::styled("  GROUPS (Read-Only)", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  Enter   ", Style::default().fg(CYAN)),
                Span::styled("View agents in group", Style::default().fg(FG)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  ↑/↓     ", Style::default().fg(CYAN)),
                Span::styled("Navigate groups", Style::default().fg(FG)),
            ]));
        }
    }
    
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Press ", Style::default().fg(DARK_GRAY)),
        Span::styled("?", Style::default().fg(YELLOW)),
        Span::styled(" or ", Style::default().fg(DARK_GRAY)),
        Span::styled("Esc", Style::default().fg(YELLOW)),
        Span::styled(" to close", Style::default().fg(DARK_GRAY)),
    ]));
    
    let p = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    
    f.render_widget(p, area);
}

fn draw_advanced_filter_popup(f: &mut Frame, app: &mut App) {
    let area = centered_rect(70, 80, f.size());
    f.render_widget(Clear, area);
    
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(PURPLE).add_modifier(Modifier::BOLD))
        .title(" 󰈲 Advanced Event Filter ");
    f.render_widget(block, area);
    
    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Tabs
            Constraint::Min(0),     // Content
            Constraint::Length(3),  // Footer/Actions
        ])
        .margin(1)
        .split(area);
    
    // Tab bar
    let tab_titles = vec![" Severity ", " Agent ", " Rule ", " Text ", " Columns "];
    let active_tab = match app.filter_popup_tab {
        FilterPopupTab::Severity => 0,
        FilterPopupTab::Agent => 1,
        FilterPopupTab::Rule => 2,
        FilterPopupTab::Text => 3,
        FilterPopupTab::Columns => 4,
    };
    
    let tabs = Tabs::new(tab_titles)
        .block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(DARK_GRAY)))
        .select(active_tab)
        .style(Style::default().fg(FG))
        .highlight_style(Style::default().fg(CYAN).add_modifier(Modifier::BOLD))
        .divider("│");
    f.render_widget(tabs, inner[0]);
    
    // Content based on active tab
    match app.filter_popup_tab {
        FilterPopupTab::Severity => draw_severity_tab(f, app, inner[1]),
        FilterPopupTab::Agent => draw_agent_filter_tab(f, app, inner[1]),
        FilterPopupTab::Rule => draw_rule_filter_tab(f, app, inner[1]),
        FilterPopupTab::Text => draw_text_filter_tab(f, app, inner[1]),
        FilterPopupTab::Columns => draw_columns_tab(f, app, inner[1]),
    }
    
    // Footer
    let footer_text = vec![
        Span::styled(" [Tab] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled("Switch Tab  ", Style::default().fg(FG)),
        Span::styled(" [Enter] ", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Span::styled("Apply  ", Style::default().fg(FG)),
        Span::styled(" [Esc] ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
        Span::styled("Cancel  ", Style::default().fg(FG)),
        Span::styled(" [c] ", Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
        Span::styled("Clear All", Style::default().fg(FG)),
    ];
    let footer = Paragraph::new(Line::from(footer_text))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(DARK_GRAY)));
    f.render_widget(footer, inner[2]);
}

fn draw_severity_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Quick presets
            Constraint::Length(1),  // Separator
            Constraint::Length(4),  // Mode selector
            Constraint::Min(0),     // Level input
        ])
        .margin(1)
        .split(area);
    
    // Quick presets
    let presets_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" Quick Presets ", Style::default().fg(BLUE)));
    
    let presets_content = vec![
        Line::from(vec![
            Span::styled("  [1] ", Style::default().fg(VULN_CRITICAL).add_modifier(Modifier::BOLD)),
            Span::styled("Critical (15+)    ", Style::default().fg(FG)),
            Span::styled("  [2] ", Style::default().fg(VULN_HIGH).add_modifier(Modifier::BOLD)),
            Span::styled("High (12-14)    ", Style::default().fg(FG)),
            Span::styled("  [3] ", Style::default().fg(VULN_MEDIUM).add_modifier(Modifier::BOLD)),
            Span::styled("Medium (7-11)    ", Style::default().fg(FG)),
            Span::styled("  [4] ", Style::default().fg(VULN_LOW).add_modifier(Modifier::BOLD)),
            Span::styled("Low (0-6)", Style::default().fg(FG)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [a] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled("All Levels (0-15)", Style::default().fg(FG)),
        ]),
    ];
    let presets_para = Paragraph::new(presets_content).block(presets_block);
    f.render_widget(presets_para, chunks[0]);
    
    // Mode selector
    let mode_text = match app.log_filter.mode {
        SeverityFilterMode::Min => "≥ Minimum Level",
        SeverityFilterMode::Max => "≤ Maximum Level", 
        SeverityFilterMode::Exact => "= Exact Level",
        SeverityFilterMode::Range => "Range (Min - Max)",
    };
    
    let mode_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" Filter Mode [m] to cycle ", Style::default().fg(BLUE)));
    
    let mode_line = Line::from(vec![
        Span::styled("  < ", Style::default().fg(DARK_GRAY)),
        Span::styled(mode_text, Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
        Span::styled(" > ", Style::default().fg(DARK_GRAY)),
    ]);
    let mode_para = Paragraph::new(mode_line).block(mode_block).alignment(Alignment::Center);
    f.render_widget(mode_para, chunks[2]);
    
    // Level inputs
    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" Level Values ", Style::default().fg(BLUE)));
    
    let v1 = app.filter_input_1.parse::<u64>().unwrap_or(0);
    let v2 = app.filter_input_2.parse::<u64>().unwrap_or(15);
    let style1 = get_severity_style(v1);
    let style2 = get_severity_style(v2);
    
    let mut input_lines = vec![];
    
    if app.log_filter.mode == SeverityFilterMode::Range {
        input_lines.push(Line::from(vec![
            Span::styled("  Min: ", Style::default().fg(FG)),
            Span::styled(format!("{}", app.filter_input_1), style1.add_modifier(Modifier::BOLD)),
            if app.filter_active_input == 0 { Span::styled("█", Style::default().fg(YELLOW)) } else { Span::raw("") },
            Span::styled(format!(" ({})", get_severity_label(v1)), Style::default().fg(DARK_GRAY)),
            Span::styled("     Max: ", Style::default().fg(FG)),
            Span::styled(format!("{}", app.filter_input_2), style2.add_modifier(Modifier::BOLD)),
            if app.filter_active_input == 1 { Span::styled("█", Style::default().fg(YELLOW)) } else { Span::raw("") },
            Span::styled(format!(" ({})", get_severity_label(v2)), Style::default().fg(DARK_GRAY)),
        ]));
        input_lines.push(Line::from(""));
        input_lines.push(Line::from(vec![
            Span::styled("  [↑/↓] ", Style::default().fg(CYAN)),
            Span::styled("Change value   ", Style::default().fg(DARK_GRAY)),
            Span::styled("[←/→] ", Style::default().fg(CYAN)),
            Span::styled("Switch field", Style::default().fg(DARK_GRAY)),
        ]));
    } else {
        input_lines.push(Line::from(vec![
            Span::styled("  Level: ", Style::default().fg(FG)),
            Span::styled(format!("{}", app.filter_input_1), style1.add_modifier(Modifier::BOLD)),
            Span::styled("█", Style::default().fg(YELLOW)),
            Span::styled(format!("  ({})", get_severity_label(v1)), Style::default().fg(DARK_GRAY)),
        ]));
        input_lines.push(Line::from(""));
        input_lines.push(Line::from(vec![
            Span::styled("  [↑/↓] ", Style::default().fg(CYAN)),
            Span::styled("Change value   ", Style::default().fg(DARK_GRAY)),
            Span::styled("[0-9] ", Style::default().fg(CYAN)),
            Span::styled("Type directly", Style::default().fg(DARK_GRAY)),
        ]));
    }
    
    let input_para = Paragraph::new(input_lines).block(input_block);
    f.render_widget(input_para, chunks[3]);
}

fn draw_agent_filter_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .margin(1)
        .split(area);
    
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" Filter by Agent Name ", Style::default().fg(BLUE)));
    
    let content = vec![
        Line::from(vec![
            Span::styled("  Agent: ", Style::default().fg(FG)),
            Span::styled(format!("{}", app.log_filter.agent_filter), Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
            Span::styled("█", Style::default().fg(YELLOW)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Type agent name or partial match (case-insensitive)", Style::default().fg(DARK_GRAY)),
        ]),
    ];
    
    let para = Paragraph::new(content).block(block);
    f.render_widget(para, chunks[0]);
    
    // Show matching agents from the list
    if !app.log_filter.agent_filter.is_empty() {
        let matches: Vec<&str> = app.agents.iter()
            .filter(|a| a.name.to_lowercase().contains(&app.log_filter.agent_filter.to_lowercase()))
            .take(10)
            .map(|a| a.name.as_str())
            .collect();
        
        let match_block = Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(DARK_GRAY))
            .title(Span::styled(format!(" Matching Agents ({}) ", matches.len()), Style::default().fg(CYAN)));
        
        let items: Vec<ListItem> = matches.iter()
            .map(|name| ListItem::new(format!("  󰒋 {}", name)))
            .collect();
        
        let list = List::new(items)
            .block(match_block)
            .style(Style::default().fg(FG));
        
        f.render_widget(list, chunks[1]);
    }
}

fn draw_rule_filter_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .margin(1)
        .split(area);
    
    // Rule ID filter
    let rule_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" Filter by Rule ID ", Style::default().fg(BLUE)));
    
    let rule_content = vec![
        Line::from(vec![
            Span::styled("  Rule ID: ", Style::default().fg(FG)),
            Span::styled(format!("{}", app.log_filter.rule_id_filter), Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
            if app.filter_active_input == 0 { Span::styled("█", Style::default().fg(YELLOW)) } else { Span::raw("") },
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Examples: 5501, 550*, 5501,5502,5503", Style::default().fg(DARK_GRAY)),
        ]),
    ];
    
    let rule_para = Paragraph::new(rule_content).block(rule_block);
    f.render_widget(rule_para, chunks[0]);
    
    // MITRE filter
    let mitre_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" Filter by MITRE ATT&CK ", Style::default().fg(BLUE)));
    
    let mitre_content = vec![
        Line::from(vec![
            Span::styled("  MITRE ID/Tactic: ", Style::default().fg(FG)),
            Span::styled(format!("{}", app.log_filter.mitre_filter), Style::default().fg(PURPLE).add_modifier(Modifier::BOLD)),
            if app.filter_active_input == 1 { Span::styled("█", Style::default().fg(YELLOW)) } else { Span::raw("") },
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Examples: T1059, TA0001, lateral-movement", Style::default().fg(DARK_GRAY)),
        ]),
    ];
    
    let mitre_para = Paragraph::new(mitre_content).block(mitre_block);
    f.render_widget(mitre_para, chunks[1]);
    
    // Hint for switching fields
    let hint = Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  [↑/↓] ", Style::default().fg(CYAN)),
            Span::styled("Switch between Rule ID and MITRE fields", Style::default().fg(DARK_GRAY)),
        ]),
    ]);
    f.render_widget(hint, chunks[2]);
}

fn draw_text_filter_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .margin(1)
        .split(area);
    
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" Search in Description ", Style::default().fg(BLUE)));
    
    let content = vec![
        Line::from(vec![
            Span::styled("  Search: ", Style::default().fg(FG)),
            Span::styled(format!("{}", app.log_filter.description_filter), Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
            Span::styled("█", Style::default().fg(YELLOW)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Full-text search in alert descriptions (case-insensitive)", Style::default().fg(DARK_GRAY)),
        ]),
    ];
    
    let para = Paragraph::new(content).block(block);
    f.render_widget(para, chunks[0]);
    
    // Search tips
    let tips_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" Search Tips ", Style::default().fg(CYAN)));
    
    let tips = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  • ", Style::default().fg(YELLOW)),
            Span::styled("Use keywords: ", Style::default().fg(FG)),
            Span::styled("authentication failed, ssh, sudo", Style::default().fg(BLUE)),
        ]),
        Line::from(vec![
            Span::styled("  • ", Style::default().fg(YELLOW)),
            Span::styled("Multiple words are matched as AND", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  • ", Style::default().fg(YELLOW)),
            Span::styled("Leave empty to show all events", Style::default().fg(FG)),
        ]),
    ];
    
    let tips_para = Paragraph::new(tips).block(tips_block);
    f.render_widget(tips_para, chunks[1]);
}

fn draw_columns_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .margin(1)
        .split(area);
    
    // Available columns
    let available_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" Available Columns ", Style::default().fg(BLUE)));
    
    let all_columns = LogColumn::all();
    let items: Vec<ListItem> = all_columns.iter().enumerate().map(|(i, col)| {
        let is_visible = app.visible_log_columns.contains(col);
        let is_selected = i == app.column_selection_index;
        
        let checkbox = if is_visible { "[✓]" } else { "[ ]" };
        let style = if is_selected {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else if is_visible {
            Style::default().fg(GREEN)
        } else {
            Style::default().fg(FG)
        };
        
        ListItem::new(Line::from(vec![
            Span::styled(format!("  {} ", checkbox), style),
            Span::styled(col.label(), style),
        ]))
    }).collect();
    
    let list = List::new(items).block(available_block);
    f.render_widget(list, chunks[0]);
    
    // Current order / preview
    let preview_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" Visible (in order) ", Style::default().fg(GREEN)));
    
    let visible_items: Vec<ListItem> = app.visible_log_columns.iter().enumerate().map(|(i, col)| {
        ListItem::new(Line::from(vec![
            Span::styled(format!("  {}. ", i + 1), Style::default().fg(DARK_GRAY)),
            Span::styled(col.label(), Style::default().fg(FG)),
        ]))
    }).collect();
    
    let visible_list = List::new(visible_items).block(preview_block);
    f.render_widget(visible_list, chunks[1]);
}
