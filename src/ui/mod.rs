pub mod theme;
pub mod dashboard;
pub mod agents;
pub mod security;
pub mod groups;
pub mod popups;
pub mod common;
pub mod json;
pub mod logs;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Tabs, Clear},
    text::Span,
    Frame,
};
use crate::app::{App, ActiveView, InspectorTab, ConfigStep};
use crate::ui::theme::*;
use crate::ui::dashboard::draw_dashboard;
use crate::ui::agents::{draw_agent_list, draw_agent_inspector};
use crate::ui::security::draw_security_events;
use crate::ui::groups::draw_group_management;
use crate::ui::logs::draw_log_detail;
use crate::ui::popups::{draw_popup, draw_interval_popup};

pub fn draw(f: &mut Frame, app: &mut App) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(if app.is_searching || !app.search_query.is_empty() { 3 } else { 0 }), // Search Bar
            Constraint::Min(0),    // Main content
            Constraint::Length(2), // Status Bar
        ])
        .split(f.size());

    // --- NOTIFICATION TOASTS ---
    draw_notifications(f, app);

    // --- HEADER ---
    let titles = vec![
        " 󱂬 Dashboard ", 
        " 󰒋 Agents ", 
        " 󱖙 Security Events ", 
        " 󰒲 Groups ",
    ];
    let active_tab = match app.active_view {
        ActiveView::Dashboard => 0,
        ActiveView::AgentList | ActiveView::AgentInspector => 1,
        ActiveView::SecurityEvents => 2,
        ActiveView::GroupManagement => 3,
    };

    let (id_count, active_count) = match app.active_view {
        ActiveView::GroupManagement => {
            if let Some(g) = app.get_selected_group() {
                let agents_in_group: Vec<_> = app.agents.iter()
                    .filter(|a| a.group.as_ref().map(|groups| groups.contains(&g.name)).unwrap_or(false))
                    .collect();
                let active = agents_in_group.iter().filter(|a| a.status == "active").count();
                (agents_in_group.len(), active)
            } else {
                (0, 0)
            }
        },
        _ => (app.agents.len(), app.agents.iter().filter(|a| a.status == "active").count()),
    };

    let breadcrumb = match app.active_view {
        ActiveView::Dashboard => "Dashboard".to_string(),
        ActiveView::AgentList => "Agents".to_string(),
        ActiveView::AgentInspector => {
            if let Some(agent) = app.get_selected_agent() {
                format!("Agents > {} ({})", agent.name, agent.id)
            } else {
                "Agents > Unknown".to_string()
            }
        },
        ActiveView::SecurityEvents => "Security Events".to_string(),
        ActiveView::GroupManagement => {
            if let Some(group) = app.get_selected_group() {
                format!("Groups > {}", group.name)
            } else {
                "Groups".to_string()
            }
        },
    };

    let header_block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(format!(" 󰆍 WAZUH TUI v0.1.0 │ {} │ View: {}/{} Active ", 
            breadcrumb,
            active_count, id_count
        ));

    let tabs = Tabs::new(titles)
        .block(header_block)
        .select(active_tab)
        .style(Style::default().fg(FG))
        .highlight_style(
            Style::default()
                .fg(BLUE)
                .add_modifier(Modifier::BOLD)
        )
        .divider("│");
    f.render_widget(tabs, main_layout[0]);

    // --- SEARCH BAR ---
    if app.is_searching || !app.search_query.is_empty() {
        let search_block = Block::default()
            .borders(Borders::ALL)
            .border_style(if app.is_searching {
                Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(DARK_GRAY)
            })
            .title(format!(" 󰍉 FILTERING {} ", match app.active_view {
                ActiveView::AgentList => "AGENTS",
                ActiveView::SecurityEvents => "SECURITY EVENTS",
                ActiveView::AgentInspector => match app.inspector_tab {
                    InspectorTab::Processes => "PROCESSES",
                    InspectorTab::Programs => "PROGRAMS",
                    InspectorTab::Logs => "LOGS",
                    _ => "DETAILS",
                },
                _ => "CONTENT",
            }));
        
        let mut spans = Vec::new();
        let parts: Vec<&str> = app.search_query.split_inclusive(' ').collect();
        
        for part in parts {
            if part.contains(':') {
                if let Some((prefix, value)) = part.split_once(':') {
                    spans.push(Span::styled(format!("{}:", prefix), Style::default().fg(BLUE).add_modifier(Modifier::BOLD)));
                    spans.push(Span::styled(value.to_string(), Style::default().fg(GREEN)));
                }
            } else {
                spans.push(Span::styled(part.to_string(), Style::default().fg(FG)));
            }
        }

        if app.is_searching {
            spans.push(Span::styled("█", Style::default().fg(YELLOW))); // Cursor
        }
        
        let p = Paragraph::new(ratatui::text::Line::from(spans))
            .block(search_block)
            .style(Style::default().fg(if app.is_searching { Color::White } else { FG }));
        f.render_widget(p, main_layout[1]);
    }

    // --- MAIN CONTENT AREA ---
    let content_area = main_layout[2];

    if app.is_config_wizard_active {
        draw_config_wizard(f, app, content_area);
    } else {
        match app.active_view {
            ActiveView::Dashboard => draw_dashboard(f, app, content_area),
            ActiveView::AgentList => draw_agent_list(f, app, content_area),
            ActiveView::AgentInspector => draw_agent_inspector(f, app, content_area),
            ActiveView::SecurityEvents => draw_security_events(f, app, content_area),
            ActiveView::GroupManagement => draw_group_management(f, app, content_area),
        }
    }

    // --- LOG DETAIL OVERLAY (FULL SCREEN) ---
    if app.selected_log.is_some() {
        let log = app.selected_log.clone().unwrap();
        draw_log_detail(f, app, &log, f.size());
    }

    // --- POPUPS ---
    draw_popup(f, app);

    // --- INTERVAL POPUP ---
    draw_interval_popup(f, app);

    // --- FOOTER / STATUS BAR ---
    let mut footer_spans = vec![
        Span::styled(" [Ctrl+P] Cmd Palette ", Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
        Span::styled(" [?] Help ", Style::default().fg(PURPLE)),
        Span::styled(" [q] Quit ", Style::default().fg(BLUE)),
        Span::styled(" [Tab] View ", Style::default().fg(BLUE)),
        Span::styled(" [r] Refresh ", Style::default().fg(BLUE)),
    ];

    if app.active_view == ActiveView::AgentList {
        footer_spans.push(Span::styled(" [Space] Select ", Style::default().fg(YELLOW)));
        footer_spans.push(Span::styled(" [s] Sort ", Style::default().fg(YELLOW)));
        footer_spans.push(Span::styled(" [U] Upgrade ", Style::default().fg(YELLOW)));
        footer_spans.push(Span::styled(" [R] Restart ", Style::default().fg(YELLOW)));
        footer_spans.push(Span::styled(" [Enter] Inspect ", Style::default().fg(GREEN)));
    }

    if app.active_view == ActiveView::GroupManagement {
        footer_spans.push(Span::styled(" [Enter] View Agents ", Style::default().fg(GREEN)));
        footer_spans.push(Span::styled(" [/] Search ", Style::default().fg(YELLOW)));
    }

    if app.active_view == ActiveView::SecurityEvents || (app.active_view == ActiveView::AgentInspector && app.inspector_tab == InspectorTab::Logs) {
        footer_spans.push(Span::styled(" [f] Filter ", Style::default().fg(PURPLE)));
        if app.active_view == ActiveView::SecurityEvents {
             footer_spans.push(Span::styled(" [v] Toggle View ", Style::default().fg(YELLOW)));
        }
        footer_spans.push(Span::styled(" [e] Export JSON ", Style::default().fg(PURPLE)));
    }

    if app.active_view == ActiveView::AgentInspector && app.inspector_tab == InspectorTab::Config {
         footer_spans.push(Span::styled(" [e] Edit Config ", Style::default().fg(YELLOW)));
    }

    if app.active_view == ActiveView::AgentList || app.active_view == ActiveView::AgentInspector {
        footer_spans.push(Span::styled(" [G] Group ", Style::default().fg(YELLOW)));
        footer_spans.push(Span::styled(" [h] SSH ", Style::default().fg(YELLOW)));
        footer_spans.push(Span::styled(" [o] Browser ", Style::default().fg(YELLOW)));
    }
    
    footer_spans.push(Span::styled(format!(" [i] Interval: {} ", app.format_interval()), Style::default().fg(GREEN)));
    footer_spans.push(Span::styled(" [+/-] Quick Adj ", Style::default().fg(GREEN)));

    if app.is_searching {
        footer_spans.push(Span::styled(format!(" 󰍉 Filtering: {} ", app.search_query), Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)));
    }

    if app.is_loading {
        footer_spans.push(Span::styled(format!(" {} {} ", app.get_spinner_char(), app.loading_text), Style::default().fg(BLUE).add_modifier(Modifier::BOLD)));
    }

    if app.active_view == ActiveView::Dashboard {
        footer_spans.push(Span::styled(" [j] Jump to Agent ", Style::default().fg(YELLOW)));
        footer_spans.push(Span::styled(" [1-4] Severity Jumps ", Style::default().fg(PURPLE)));
    }

    if let Some(err) = &app.error_message {
        footer_spans.push(Span::styled(format!(" 󰅚 {} ", err), Style::default().fg(RED).add_modifier(Modifier::BOLD)));
    }

    let status_bar = Paragraph::new(ratatui::text::Line::from(footer_spans))
        .style(Style::default().bg(STATUS_BAR_BG))
        .block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(DARK_GRAY)));
    f.render_widget(status_bar, main_layout[3]);

    // --- NOTIFICATION TOASTS (Rendered last to be on top) ---
    draw_notifications(f, app);
}

fn draw_notifications(f: &mut Frame, app: &mut App) {
    if app.notifications.is_empty() {
        return;
    }

    let area = f.size();
    let notification_height = 3;
    let vertical_offset = 1;
    
    let notifications = app.notifications.clone();
    for (i, notification) in notifications.iter().enumerate() {
        let (icon, color) = match notification.level {
            crate::app::NotificationLevel::Info => ("󰋼 ", BLUE),
            crate::app::NotificationLevel::Success => ("󰄬 ", GREEN),
            crate::app::NotificationLevel::Warning => ("󰀦 ", YELLOW),
            crate::app::NotificationLevel::Error => ("󰅚 ", RED),
        };

        let notification_area = Rect::new(
            area.width.saturating_sub(42),
            vertical_offset + (i as u16 * (notification_height + 1)),
            40.min(area.width),
            notification_height,
        );

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(color))
            .title(format!(" {} Notification ", icon));

        let p = Paragraph::new(notification.message.as_str())
            .block(block)
            .style(Style::default().fg(FG));
        
        f.render_widget(Clear, notification_area);
        f.render_widget(p, notification_area);
    }
}

fn draw_config_wizard(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Welcome
            Constraint::Min(0),    // Inputs
        ])
        .split(area);

    let welcome = Paragraph::new(" Welcome to Wazuh TUI. Please configure your connection. \n Shared credentials will be used for both Wazuh and OpenSearch. ")
        .style(Style::default().fg(YELLOW)) // One Dark Yellow
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(DARK_GRAY)));
    f.render_widget(welcome, chunks[0]);

    let pass_mask = "*".repeat(app.config_password.len());
    let fields = vec![
        ("1. Wazuh API URL", &app.config_url, app.config_step == ConfigStep::Url),
        ("2. OpenSearch URL", &app.config_os_url, app.config_step == ConfigStep::OsUrl),
        ("3. Username", &app.config_username, app.config_step == ConfigStep::Username),
        ("4. Password", &pass_mask, app.config_step == ConfigStep::Password),
    ];

    let input_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(fields.iter().map(|_| Constraint::Length(3)).collect::<Vec<_>>())
        .split(chunks[1]);

    for (i, (label, value, is_active)) in fields.into_iter().enumerate() {
        let style = if is_active {
            Style::default().fg(BLUE).add_modifier(Modifier::BOLD) // One Dark Blue
        } else {
            Style::default().fg(FG) // One Dark Gray
        };
        
        let border_color = if is_active { GREEN } else { DARK_GRAY }; // Green if active, subtle gray if not
        
        let p = Paragraph::new(value.as_str())
            .block(Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(label)
                .border_style(Style::default().fg(border_color)))
            .style(style);
        f.render_widget(p, input_chunks[i]);
    }

    if app.config_step == ConfigStep::Confirm {
        let confirm = Paragraph::new(" Press Enter to Save and Connect | Backspace to Edit ")
            .alignment(ratatui::layout::Alignment::Center)
            .style(Style::default().fg(YELLOW).add_modifier(Modifier::SLOW_BLINK))
            .block(Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Final Step ")
                .border_style(Style::default().fg(BLUE)));
        
        let last_chunk = input_chunks.last().unwrap();
        let confirm_area = Rect::new(last_chunk.x, last_chunk.y + 3, last_chunk.width, 3);
        f.render_widget(confirm, confirm_area);
    }
}
