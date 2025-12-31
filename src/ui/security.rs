use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table, Cell},
    text::{Line, Span},
    Frame,
};
use crate::app::{App, LogViewMode, LogColumn};
use crate::ui::theme::*;

fn get_severity_info(level: u64) -> (&'static str, ratatui::style::Color) {
    match level {
        15..=u64::MAX => ("󰅚 ", VULN_CRITICAL),
        12..=14 => ("󰀦 ", VULN_HIGH),
        7..=11 => ("󱈸 ", VULN_MEDIUM),
        _ => ("󰋼 ", FG),
    }
}

fn extract_field(source: &serde_json::Value, column: &LogColumn) -> String {
    match column {
        LogColumn::Timestamp => {
            let ts = source.get("@timestamp").and_then(|v| v.as_str()).unwrap_or("Unknown");
            ts.split('.').next().unwrap_or(ts).replace('T', " ")
        }
        LogColumn::Level => {
            let level = source.get("rule").and_then(|r| r.get("level")).and_then(|l| l.as_u64()).unwrap_or(0);
            let (icon, _) = get_severity_info(level);
            format!("{}{:02}", icon, level)
        }
        LogColumn::Agent => {
            source.get("agent")
                .and_then(|a| a.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("Manager")
                .to_string()
        }
        LogColumn::Description => {
            source.get("rule")
                .and_then(|r| r.get("description"))
                .and_then(|d| d.as_str())
                .unwrap_or("No description")
                .to_string()
        }
        LogColumn::RuleId => {
            source.get("rule")
                .and_then(|r| r.get("id"))
                .and_then(|id| id.as_str())
                .unwrap_or("-")
                .to_string()
        }
        LogColumn::MitreId => {
            source.get("rule")
                .and_then(|r| r.get("mitre"))
                .and_then(|m| m.get("id"))
                .and_then(|ids| ids.as_array())
                .and_then(|arr| arr.first())
                .and_then(|id| id.as_str())
                .unwrap_or("-")
                .to_string()
        }
        LogColumn::MitreTactic => {
            source.get("rule")
                .and_then(|r| r.get("mitre"))
                .and_then(|m| m.get("tactic"))
                .and_then(|tactics| tactics.as_array())
                .and_then(|arr| arr.first())
                .and_then(|t| t.as_str())
                .unwrap_or("-")
                .to_string()
        }
        LogColumn::SrcIp => {
            source.get("data")
                .and_then(|d| d.get("srcip"))
                .and_then(|ip| ip.as_str())
                .or_else(|| source.get("data").and_then(|d| d.get("src_ip")).and_then(|ip| ip.as_str()))
                .unwrap_or("-")
                .to_string()
        }
        LogColumn::DstIp => {
            source.get("data")
                .and_then(|d| d.get("dstip"))
                .and_then(|ip| ip.as_str())
                .or_else(|| source.get("data").and_then(|d| d.get("dst_ip")).and_then(|ip| ip.as_str()))
                .unwrap_or("-")
                .to_string()
        }
        LogColumn::User => {
            source.get("data")
                .and_then(|d| d.get("srcuser"))
                .and_then(|u| u.as_str())
                .or_else(|| source.get("data").and_then(|d| d.get("dstuser")).and_then(|u| u.as_str()))
                .or_else(|| source.get("data").and_then(|d| d.get("user")).and_then(|u| u.as_str()))
                .unwrap_or("-")
                .to_string()
        }
        LogColumn::Groups => {
            source.get("rule")
                .and_then(|r| r.get("groups"))
                .and_then(|g| g.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_str())
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_else(|| "-".to_string())
        }
    }
}

fn get_column_width(column: &LogColumn) -> Constraint {
    match column {
        LogColumn::Timestamp => Constraint::Length(20),
        LogColumn::Level => Constraint::Length(8),
        LogColumn::Agent => Constraint::Length(25),
        LogColumn::Description => Constraint::Min(30),
        LogColumn::RuleId => Constraint::Length(8),
        LogColumn::MitreId => Constraint::Length(10),
        LogColumn::MitreTactic => Constraint::Length(18),
        LogColumn::SrcIp => Constraint::Length(16),
        LogColumn::DstIp => Constraint::Length(16),
        LogColumn::User => Constraint::Length(12),
        LogColumn::Groups => Constraint::Length(20),
    }
}

pub fn draw_security_events(f: &mut Frame, app: &mut App, area: Rect) {
    if app.log_view_mode == LogViewMode::Raw {
        draw_raw_view(f, app, area);
        return;
    }

    // Build dynamic header based on visible columns
    let header_cells: Vec<Cell> = app.visible_log_columns.iter()
        .map(|col| Cell::from(format!(" {} ", col.label()))
            .style(Style::default().fg(BLUE).add_modifier(Modifier::BOLD)))
        .collect();
    
    let header = Row::new(header_cells)
        .style(Style::default().bg(BG))
        .height(1);

    // Build rows with only visible columns
    let rows = app.logs.iter().map(|log| {
        let source = log.get("_source").unwrap_or(log);
        let level = source.get("rule")
            .and_then(|r| r.get("level"))
            .and_then(|l| l.as_u64())
            .unwrap_or(0);
        let (_, color) = get_severity_info(level);

        let cells: Vec<Cell> = app.visible_log_columns.iter()
            .map(|col| Cell::from(extract_field(source, col)))
            .collect();

        Row::new(cells).style(Style::default().fg(color)).height(1)
    });

    // Build column widths
    let widths: Vec<Constraint> = app.visible_log_columns.iter()
        .map(|col| get_column_width(col))
        .collect();

    // Build title with filter status
    let filter_status = build_filter_status(app);
    let title = format!(" 󱖙 Security Events {} ", filter_status);

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(DARK_GRAY))
            .title(Span::styled(title, Style::default().fg(PURPLE))))
        .highlight_style(Style::default()
            .bg(SELECTION_BG)
            .add_modifier(Modifier::BOLD))
        .highlight_symbol("󰁔 ");

    let mut state = app.table_state.clone();
    f.render_stateful_widget(table, area, &mut state);
}

fn build_filter_status(app: &App) -> String {
    let mut parts = vec![];
    
    // Time interval
    parts.push(format!("Last {}", app.format_interval()));
    
    // Severity filter
    match app.log_filter.mode {
        crate::app::SeverityFilterMode::Min => {
            if app.log_filter.val1 > 0 {
                parts.push(format!("Level ≥{}", app.log_filter.val1));
            }
        }
        crate::app::SeverityFilterMode::Max => {
            parts.push(format!("Level ≤{}", app.log_filter.val1));
        }
        crate::app::SeverityFilterMode::Exact => {
            parts.push(format!("Level ={}", app.log_filter.val1));
        }
        crate::app::SeverityFilterMode::Range => {
            parts.push(format!("Level {}-{}", app.log_filter.val1, app.log_filter.val2));
        }
    }
    
    // Agent filter
    if !app.log_filter.agent_filter.is_empty() {
        parts.push(format!("Agent:{}", app.log_filter.agent_filter));
    }
    
    // Rule filter
    if !app.log_filter.rule_id_filter.is_empty() {
        parts.push(format!("Rule:{}", app.log_filter.rule_id_filter));
    }
    
    // Text filter
    if !app.log_filter.description_filter.is_empty() {
        parts.push(format!("\"{}\"", app.log_filter.description_filter));
    }
    
    format!("[{}]", parts.join(" | "))
}

fn draw_raw_view(f: &mut Frame, app: &mut App, area: Rect) {
    let logs_text: Vec<Line> = app.logs.iter().map(|log| {
        let formatted = serde_json::to_string(log).unwrap_or_default();
        Line::from(Span::raw(formatted))
    }).collect();

    let p = Paragraph::new(logs_text)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(DARK_GRAY))
            .title(" Security Alerts (Raw JSON) "))
        .wrap(ratatui::widgets::Wrap { trim: true })
        .scroll((app.log_offset as u16, 0));
        
    f.render_widget(p, area);
}
