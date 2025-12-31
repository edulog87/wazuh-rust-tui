use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table, Cell},
    Frame,
};
use crate::app::App;
use crate::ui::theme::*;
use crate::ui::common::filter_matches;

pub fn draw_group_management(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30), // Groups List
            Constraint::Percentage(70), // Agents in Group
        ])
        .split(area);

    // Groups List
    let filtered_groups: Vec<_> = if app.is_searching {
        app.groups.iter()
            .filter(|g| filter_matches(&app.search_query, &g.name))
            .collect()
    } else {
        app.groups.iter().collect()
    };

    let rows = filtered_groups.iter().map(|g| {
        Row::new(vec![
            Cell::from(g.name.clone()),
            Cell::from(g.count.map(|c| c.to_string()).unwrap_or_else(|| "0".to_string())),
        ]).style(Style::default().fg(FG))
    });

    let table = Table::new(rows, [
        Constraint::Min(20),
        Constraint::Length(10),
    ])
    .header(Row::new(vec!["Group Name", "Agents"]).style(Style::default().fg(BLUE)))
    .block(Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(DARK_GRAY))
        .title(" Wazuh Groups "))
    .highlight_style(Style::default()
        .bg(SELECTION_BG)
        .add_modifier(Modifier::BOLD))
    .highlight_symbol("󰁔 ");

    let mut state = app.groups_table_state.clone();
    f.render_stateful_widget(table, chunks[0], &mut state);

    // Right side: Agents in selected group
    let selected_group = state.selected()
        .and_then(|idx| filtered_groups.get(idx));

    if let Some(group) = selected_group {
        let group_agents: Vec<_> = app.agents.iter()
            .filter(|a| a.group.as_ref().map(|g| g.contains(&group.name)).unwrap_or(false))
            .collect();

        let agent_rows = group_agents.iter().map(|a| {
            let (icon, color) = match a.status.as_str() {
                "active" => ("󰄬 ", GREEN),
                "disconnected" => ("󰅖 ", RED),
                _ => ("󰒲 ", FG),
            };
            Row::new(vec![
                Cell::from(a.id.clone()),
                Cell::from(a.name.clone()),
                Cell::from(format!("{}{}", icon, a.status)),
                Cell::from(a.ip.clone().unwrap_or_else(|| "N/A".to_string())),
            ]).style(Style::default().fg(color))
        });

        let agent_table = Table::new(agent_rows, [
            Constraint::Length(6),
            Constraint::Min(20),
            Constraint::Length(15),
            Constraint::Length(15),
        ])
        .header(Row::new(vec!["ID", "Name", "Status", "IP"]).style(Style::default().fg(BLUE)))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(DARK_GRAY))
            .title(format!(" Agents in Group: {} ", group.name)));
        
        f.render_widget(agent_table, chunks[1]);
    } else {
        let placeholder = Paragraph::new("\n\n Select a group from the list to view its members. ")
            .alignment(ratatui::layout::Alignment::Center)
            .style(Style::default().fg(GRAY))
            .block(Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(DARK_GRAY))
                .title(" Group Details "));
        f.render_widget(placeholder, chunks[1]);
    }
}
