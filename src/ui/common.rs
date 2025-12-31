use chrono;
use regex::RegexBuilder;
use ratatui::layout::{Constraint, Direction, Layout, Rect};

pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

pub fn filter_matches(query: &str, content: &str) -> bool {
    if let Ok(re) = RegexBuilder::new(query).case_insensitive(true).build() {
        re.is_match(content)
    } else {
        content.to_lowercase().contains(&query.to_lowercase())
    }
}

pub fn format_last_keep_alive(last_keep_alive: &Option<String>) -> String {
    if let Some(time_str) = last_keep_alive {
        // Try RFC3339 first (standard ISO8601)
        let dt = chrono::DateTime::parse_from_rfc3339(time_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .or_else(|_| {
                // Try format without offset if it fails (common in some Wazuh versions)
                chrono::NaiveDateTime::parse_from_str(time_str, "%Y-%m-%dT%H:%M:%S")
                    .map(|ndt| chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(ndt, chrono::Utc))
            });

        if let Ok(dt) = dt {
            let now = chrono::Utc::now();
            let duration = now.signed_duration_since(dt);
            
            if duration.num_seconds() < 0 {
                return "Just now".to_string();
            }
            if duration.num_seconds() < 60 {
                return format!("{}s ago", duration.num_seconds());
            }
            if duration.num_minutes() < 60 {
                return format!("{}m ago", duration.num_minutes());
            }
            if duration.num_hours() < 24 {
                return format!("{}h ago", duration.num_hours());
            }
            return format!("{}d ago", duration.num_days());
        }
    }
    "Never".to_string()
}
