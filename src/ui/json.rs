use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};
use crate::ui::theme::*;

/// Creates colored spans for a flattened JSON key-value pair
pub fn colorize_flat_line<'a>(key: &str, value: &serde_json::Value) -> Line<'a> {
    
    let value_span = match value {
        serde_json::Value::String(s) => Span::styled(format!("\"{}\"", s), Style::default().fg(JSON_STRING)),
        serde_json::Value::Number(n) => Span::styled(n.to_string(), Style::default().fg(JSON_NUMBER)),
        serde_json::Value::Bool(b) => Span::styled(b.to_string(), Style::default().fg(JSON_BOOL)),
        serde_json::Value::Null => Span::styled("null", Style::default().fg(JSON_NULL)),
        serde_json::Value::Array(arr) => Span::styled(format!("{:?}", arr), Style::default().fg(FG)),
        serde_json::Value::Object(_) => Span::styled("[object]", Style::default().fg(GRAY)),
    };
    
    Line::from(vec![
        Span::styled(format!("{}", key), Style::default().fg(JSON_KEY)),
        Span::styled(": ", Style::default().fg(JSON_COLON)),
        value_span,
    ])
}

/// Creates colored lines for flattened JSON display
pub fn colorize_flat_json(obj: &serde_json::Map<String, serde_json::Value>, prefix: &str) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    
    for (k, v) in obj {
        let key = if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) };
        match v {
            serde_json::Value::Object(inner) => {
                lines.extend(colorize_flat_json(inner, &key));
            }
            serde_json::Value::Array(arr) => {
                // For arrays, show each element or summarize
                if arr.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled(key, Style::default().fg(JSON_KEY)),
                        Span::styled(": ", Style::default().fg(JSON_COLON)),
                        Span::styled("[]", Style::default().fg(JSON_BRACKET)),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled(format!("{}", key), Style::default().fg(JSON_KEY)),
                        Span::styled(": ", Style::default().fg(JSON_COLON)),
                        Span::styled(format!("[{} items]", arr.len()), Style::default().fg(GRAY)),
                    ]));
                }
            }
            _ => {
                lines.push(colorize_flat_line(&key, v));
            }
        }
    }
    
    lines
}

/// Creates colored text for raw JSON display with syntax highlighting
pub fn colorize_json(json: &serde_json::Value) -> Vec<Line<'static>> {
    let formatted = serde_json::to_string_pretty(json).unwrap_or_default();
    let mut lines = Vec::new();
    
    for line in formatted.lines() {
        let spans = parse_json_line(line);
        lines.push(Line::from(spans));
    }
    
    lines
}

/// Parse a single line of formatted JSON and return colored spans
fn parse_json_line(line: &str) -> Vec<Span<'static>> {
    
    let mut spans = Vec::new();
    let mut chars = line.chars().peekable();
    let mut current = String::new();
    let mut in_string = false;
    let mut is_key = true;
    
    // Handle leading whitespace (indentation)
    let mut indent_str = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            indent_str.push(chars.next().unwrap());
        } else {
            break;
        }
    }
    if !indent_str.is_empty() {
        spans.push(Span::raw(indent_str));
    }
    
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_string {
                    // End of string
                    current.push(c);
                    let color = if is_key { JSON_KEY } else { JSON_STRING };
                    spans.push(Span::styled(current.clone(), Style::default().fg(color)));
                    current.clear();
                    in_string = false;
                } else {
                    // Start of string
                    if !current.is_empty() {
                        let color = get_value_color(&current);
                        spans.push(Span::styled(current.clone(), Style::default().fg(color)));
                        current.clear();
                    }
                    current.push(c);
                    in_string = true;
                }
            }
            ':' if !in_string => {
                if !current.is_empty() {
                    let color = get_value_color(&current);
                    spans.push(Span::styled(current.clone(), Style::default().fg(color)));
                    current.clear();
                }
                spans.push(Span::styled(": ", Style::default().fg(JSON_COLON)));
                is_key = false;
                // Skip the space after colon if present
                if chars.peek() == Some(&' ') {
                    chars.next();
                }
            }
            ',' if !in_string => {
                if !current.is_empty() {
                    let color = get_value_color(&current);
                    spans.push(Span::styled(current.clone(), Style::default().fg(color)));
                    current.clear();
                }
                spans.push(Span::styled(",", Style::default().fg(FG)));
                is_key = true;
            }
            '{' | '}' | '[' | ']' if !in_string => {
                if !current.is_empty() {
                    let color = get_value_color(&current);
                    spans.push(Span::styled(current.clone(), Style::default().fg(color)));
                    current.clear();
                }
                spans.push(Span::styled(c.to_string(), Style::default().fg(JSON_BRACKET)));
                if c == '{' || c == '[' {
                    is_key = true; // After { or [ we expect a key if it's an object
                }
            }
            '\\' if in_string => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            _ => {
                current.push(c);
            }
        }
    }
    
    // Handle remaining content
    if !current.is_empty() {
        let color = if in_string {
            if is_key { JSON_KEY } else { JSON_STRING }
        } else {
            get_value_color(&current)
        };
        spans.push(Span::styled(current, Style::default().fg(color)));
    }
    
    spans
}

/// Determine the color for a JSON value based on its content
fn get_value_color(value: &str) -> Color {
    let trimmed = value.trim();
    if trimmed == "true" || trimmed == "false" {
        JSON_BOOL
    } else if trimmed == "null" {
        JSON_NULL
    } else if trimmed.parse::<f64>().is_ok() {
        JSON_NUMBER
    } else {
        FG
    }
}
