use ratatui::style::Color;

pub const BG: Color = Color::Rgb(40, 44, 52);
pub const FG: Color = Color::Rgb(171, 178, 191);
pub const BLUE: Color = Color::Rgb(97, 175, 239);
pub const GREEN: Color = Color::Rgb(152, 195, 121);
pub const YELLOW: Color = Color::Rgb(229, 192, 123);
pub const RED: Color = Color::Rgb(224, 108, 117);
pub const PURPLE: Color = Color::Rgb(198, 120, 221);
pub const CYAN: Color = Color::Rgb(86, 182, 194);
pub const ORANGE: Color = Color::Rgb(209, 154, 102);
pub const GRAY: Color = Color::Rgb(92, 99, 112);
pub const DARK_GRAY: Color = Color::Rgb(75, 82, 99);
pub const SELECTION_BG: Color = Color::Rgb(62, 68, 81);
pub const STATUS_BAR_BG: Color = Color::Rgb(33, 37, 43);

pub const VULN_CRITICAL: Color = Color::Rgb(255, 50, 50);
pub const VULN_HIGH: Color = Color::Rgb(224, 108, 117);
pub const VULN_MEDIUM: Color = Color::Rgb(229, 192, 123);
pub const VULN_LOW: Color = Color::Rgb(171, 178, 191);
pub const VULN_UNTRIAGED: Color = Color::Rgb(92, 99, 112);

// JSON syntax highlighting colors (One Dark theme)
pub const JSON_KEY: Color = Color::Rgb(198, 120, 221);      // Purple - keys
pub const JSON_STRING: Color = Color::Rgb(152, 195, 121);   // Green - string values
pub const JSON_NUMBER: Color = Color::Rgb(209, 154, 102);   // Orange - numbers
pub const JSON_BOOL: Color = Color::Rgb(86, 182, 194);      // Cyan - true/false
pub const JSON_NULL: Color = Color::Rgb(92, 99, 112);       // Gray - null
pub const JSON_BRACKET: Color = Color::Rgb(171, 178, 191);  // FG - brackets {}, []
pub const JSON_COLON: Color = Color::Rgb(86, 182, 194);     // Cyan - colons
