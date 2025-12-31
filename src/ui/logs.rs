use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    widgets::{Block, Borders, Paragraph, Clear, Wrap},
    text::{Line, Span, Text},
    Frame,
};
use crate::app::App;
use crate::ui::theme::*;
use crate::ui::json::{colorize_json, colorize_flat_json};

pub fn draw_log_detail(f: &mut Frame, app: &mut App, log: &serde_json::Value, area: Rect) {
    f.render_widget(Clear, area);
    
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .title(" 󱖙 Event Detail ")
        .title_alignment(ratatui::layout::Alignment::Center)
        .border_style(Style::default().fg(BLUE).add_modifier(Modifier::BOLD));

    // Create inner area for content
    let inner_area = block.inner(area);
    f.render_widget(block, area);

    let lines: Vec<Line> = if app.show_log_json {
        // Raw JSON with syntax highlighting
        colorize_json(log)
    } else {
        // Flattened JSON with colored keys/values
        let mut result = vec![
            Line::from(vec![
                Span::styled(" --- LOG FIELDS ---", Style::default().fg(BLUE).add_modifier(Modifier::BOLD))
            ]),
            Line::from(""),
        ];
        
        if let Some(obj) = log.get("_source").and_then(|s| s.as_object()) {
            result.extend(colorize_flat_json(obj, ""));
        }
        result
    };

    let text = Text::from(lines);
    let p = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .scroll((app.log_scroll_offset as u16, 0));
    
    f.render_widget(p, inner_area);

    // Mini help at bottom
    let help = Paragraph::new(" [Enter] Toggle Raw JSON │ [Esc] Close Detail │ [↑/↓] Scroll ")
        .alignment(ratatui::layout::Alignment::Center)
        .style(Style::default().fg(BLUE).bg(STATUS_BAR_BG));
    let help_area = Rect::new(area.x, area.y + area.height - 1, area.width, 1);
    f.render_widget(help, help_area);
}
