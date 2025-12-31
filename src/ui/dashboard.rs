use ratatui::{
    layout::{Constraint, Direction, Layout, Rect, Alignment},
    style::{Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table, Cell},
    text::{Line, Span},
    Frame,
};
use crate::app::App;
use crate::ui::theme::*;

pub fn draw_dashboard(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Agent Summary
            Constraint::Length(7),  // Threat Summary
            Constraint::Min(0),     // Bottom content
        ])
        .margin(1)
        .split(area);

    // ─────────────────────────────────────────────────────────────────────────
    // AGENT SUMMARY SECTION
    // ─────────────────────────────────────────────────────────────────────────
    let total = app.agents.len();
    let active = app.agents.iter().filter(|a| a.status == "active").count();
    let disconnected = app.agents.iter().filter(|a| a.status == "disconnected").count();
    let never_connected = app.agents.iter().filter(|a| a.status == "never_connected").count();
    let pending = app.agents.iter().filter(|a| a.status == "pending").count();

    let agent_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" 󰒋 AGENTS ", Style::default().fg(BLUE).add_modifier(Modifier::BOLD)));

    let health_pct = if total > 0 { (active * 100) / total } else { 0 };
    let health_bar_width = 20;
    let filled = (health_pct * health_bar_width) / 100;
    let empty = health_bar_width - filled;
    let bar_color = if health_pct > 80 { GREEN } else if health_pct > 50 { YELLOW } else { RED };

    let agent_content = vec![
        Line::from(vec![
            Span::styled("  Total: ", Style::default().fg(FG)),
            Span::styled(format!("{:<6}", total), Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("  Active: ", Style::default().fg(FG)),
            Span::styled(format!("{:<6}", active), Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
            Span::styled("  Disconnected: ", Style::default().fg(FG)),
            Span::styled(format!("{:<6}", disconnected), Style::default().fg(RED).add_modifier(Modifier::BOLD)),
            Span::styled("  Never Connected: ", Style::default().fg(FG)),
            Span::styled(format!("{:<6}", never_connected), Style::default().fg(DARK_GRAY)),
            Span::styled("  Pending: ", Style::default().fg(FG)),
            Span::styled(format!("{}", pending), Style::default().fg(YELLOW)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Health: ", Style::default().fg(FG)),
            Span::styled("▓".repeat(filled), Style::default().fg(bar_color)),
            Span::styled("░".repeat(empty), Style::default().fg(DARK_GRAY)),
            Span::styled(format!(" {}%", health_pct), Style::default().fg(bar_color).add_modifier(Modifier::BOLD)),
        ]),
    ];

    let agent_para = Paragraph::new(agent_content).block(agent_block);
    f.render_widget(agent_para, chunks[0]);

    // ─────────────────────────────────────────────────────────────────────────
    // THREAT SUMMARY SECTION
    // ─────────────────────────────────────────────────────────────────────────
    let interval_text = format!("Last {}", app.format_interval());

    let threat_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(
            format!(" 󱖙 SECURITY ALERTS ({}) ", interval_text),
            Style::default().fg(PURPLE).add_modifier(Modifier::BOLD)
        ));

    let threat_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .margin(1)
        .split(chunks[1]);

    f.render_widget(threat_block, chunks[1]);

    // Severity cards - minimal style
    let create_severity_card = |label: &'static str, count: u32, color: ratatui::style::Color, key: char| {
        let lines = vec![
            Line::from(Span::styled(
                format!("{}", count),
                Style::default().fg(color).add_modifier(Modifier::BOLD)
            )),
            Line::from(Span::styled(label, Style::default().fg(FG))),
            Line::from(Span::styled(
                format!("[{}]", key),
                Style::default().fg(DARK_GRAY)
            )),
        ];
        Paragraph::new(lines).alignment(Alignment::Center)
    };

    f.render_widget(create_severity_card("Critical", app.threat_stats.critical, VULN_CRITICAL, '1'), threat_layout[0]);
    f.render_widget(create_severity_card("High", app.threat_stats.high, VULN_HIGH, '2'), threat_layout[1]);
    f.render_widget(create_severity_card("Medium", app.threat_stats.medium, VULN_MEDIUM, '3'), threat_layout[2]);
    f.render_widget(create_severity_card("Low", app.threat_stats.low, VULN_LOW, '4'), threat_layout[3]);

    // ─────────────────────────────────────────────────────────────────────────
    // BOTTOM SECTION - Top Attacked Agents / Quick Actions
    // ─────────────────────────────────────────────────────────────────────────
    let bottom_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(chunks[2]);

    // Top Attacked Agents Table
    if !app.top_agents.is_empty() {
        let top_block = Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(DARK_GRAY))
            .title(Span::styled(" 󰀦 TOP ATTACKED AGENTS ", Style::default().fg(RED)));

        let rows = app.top_agents.iter().enumerate().map(|(i, (name, count))| {
            let rank_style = match i {
                0 => Style::default().fg(VULN_CRITICAL).add_modifier(Modifier::BOLD),
                1 => Style::default().fg(VULN_HIGH),
                2 => Style::default().fg(VULN_MEDIUM),
                _ => Style::default().fg(FG),
            };
            Row::new(vec![
                Cell::from(format!(" {}.", i + 1)).style(rank_style),
                Cell::from(name.clone()).style(Style::default().fg(FG)),
                Cell::from(format!("{}", count)).style(rank_style),
            ])
        });

        let table = Table::new(rows, [
            Constraint::Length(4),
            Constraint::Min(15),
            Constraint::Length(8),
        ])
        .header(
            Row::new(vec![" #", "Agent", "Alerts"])
                .style(Style::default().fg(BLUE).add_modifier(Modifier::BOLD))
        )
        .block(top_block);

        f.render_widget(table, bottom_layout[0]);
    } else {
        let empty_block = Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(DARK_GRAY))
            .title(Span::styled(" 󰀦 TOP ATTACKED AGENTS ", Style::default().fg(RED)));

        let empty_msg = Paragraph::new("\n\n  No alert data available.\n  Press [r] to refresh.")
            .style(Style::default().fg(DARK_GRAY))
            .block(empty_block);

        f.render_widget(empty_msg, bottom_layout[0]);
    }

    // Quick Actions / Help Panel
    let help_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(Span::styled(" 󰋗 QUICK ACTIONS ", Style::default().fg(CYAN)));

    let help_content = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  [Tab]     ", Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("Switch between views", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  [J]       ", Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("Jump to agent by name", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  [1-4]     ", Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("View alerts by severity", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  [r]       ", Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("Refresh data", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  [i]       ", Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("Set time interval", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  [Ctrl+P]  ", Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
            Span::styled("Command palette", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("  [?]       ", Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("Full help", Style::default().fg(FG)),
        ]),
    ];

    let help_para = Paragraph::new(help_content).block(help_block);
    f.render_widget(help_para, bottom_layout[1]);
}
