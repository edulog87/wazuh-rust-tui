pub mod filter;

#[cfg(test)]
mod filter_tests;

use crate::models::{WazuhAgent, WazuhGroup, WazuhHardwareItem, WazuhProcessItem, WazuhProgramItem};
use crate::api::WazuhApi;
use crate::app::filter::AgentFilter;
use std::time::Instant;
use std::fs::File;
use std::io::Write;

#[derive(Debug, PartialEq, Clone)]
pub enum NotificationLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub message: String,
    pub level: NotificationLevel,
    pub timestamp: Instant,
}

#[derive(Debug, Default, Clone)]
pub struct ThreatStats {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

pub enum DataUpdate {
    Agents(Vec<WazuhAgent>),
    Groups(Vec<WazuhGroup>),
    GroupAgents(Vec<WazuhAgent>),
    SecurityEvents(Vec<serde_json::Value>),
    VulnSummary(crate::models::VulnerabilitySummary),
    ThreatStats(ThreatStats),
    AgentHardware(WazuhHardwareItem),
    AgentProcesses(Vec<WazuhProcessItem>),
    AgentPrograms(Vec<WazuhProgramItem>),
    AgentVulnerabilities(Vec<crate::models::WazuhVulnerabilityItem>),
    AgentLogs(Vec<serde_json::Value>),
    AgentConfig(serde_json::Value),
    AlertHistory(Vec<(String, u64)>),
    TopAgents(Vec<(String, u64)>),
    Notification(String, NotificationLevel),
    Error(String),
    ErrorPopup { title: String, message: String },
}

#[derive(Debug, PartialEq, Clone)]
pub enum ActiveView {
    Dashboard,
    AgentList,
    AgentInspector,
    SecurityEvents,
    GroupManagement,
}

#[derive(Debug, PartialEq, Clone)]
pub enum PopupMode {
    None,
    GroupAssignment { agent_id: String },
    SeverityFilter,
    SshUsername { agent_id: String, agent_ip: String },
    AgentJump,
    Error { title: String, message: String },
    Help,
    CommandPalette,
}

#[derive(Debug, PartialEq, Clone)]
pub enum SeverityFilterMode {
    Min,
    Max,
    Exact,
    Range,
}

#[derive(Debug, Clone)]
pub struct LogFilter {
    pub mode: SeverityFilterMode,
    pub val1: u32,
    pub val2: u32,
    pub agent_filter: String,
    pub rule_id_filter: String,
    pub description_filter: String,
    pub mitre_filter: String,
}

impl Default for LogFilter {
    fn default() -> Self {
        Self {
            mode: SeverityFilterMode::Min,
            val1: 0,
            val2: 15,
            agent_filter: String::new(),
            rule_id_filter: String::new(),
            description_filter: String::new(),
            mitre_filter: String::new(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum LogColumn {
    Timestamp,
    Level,
    Agent,
    Description,
    RuleId,
    MitreId,
    MitreTactic,
    SrcIp,
    DstIp,
    User,
    Groups,
}

impl LogColumn {
    pub fn label(&self) -> &'static str {
        match self {
            LogColumn::Timestamp => "Timestamp",
            LogColumn::Level => "Level",
            LogColumn::Agent => "Agent",
            LogColumn::Description => "Description",
            LogColumn::RuleId => "Rule ID",
            LogColumn::MitreId => "MITRE ID",
            LogColumn::MitreTactic => "Tactic",
            LogColumn::SrcIp => "Src IP",
            LogColumn::DstIp => "Dst IP",
            LogColumn::User => "User",
            LogColumn::Groups => "Groups",
        }
    }
    
    pub fn all() -> Vec<LogColumn> {
        vec![
            LogColumn::Timestamp,
            LogColumn::Level,
            LogColumn::Agent,
            LogColumn::Description,
            LogColumn::RuleId,
            LogColumn::MitreId,
            LogColumn::MitreTactic,
            LogColumn::SrcIp,
            LogColumn::DstIp,
            LogColumn::User,
            LogColumn::Groups,
        ]
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FilterPopupTab {
    Severity,
    Agent,
    Rule,
    Text,
    Columns,
}

impl FilterPopupTab {
    pub fn next(&self) -> Self {
        match self {
            FilterPopupTab::Severity => FilterPopupTab::Agent,
            FilterPopupTab::Agent => FilterPopupTab::Rule,
            FilterPopupTab::Rule => FilterPopupTab::Text,
            FilterPopupTab::Text => FilterPopupTab::Columns,
            FilterPopupTab::Columns => FilterPopupTab::Severity,
        }
    }
    
    pub fn prev(&self) -> Self {
        match self {
            FilterPopupTab::Severity => FilterPopupTab::Columns,
            FilterPopupTab::Agent => FilterPopupTab::Severity,
            FilterPopupTab::Rule => FilterPopupTab::Agent,
            FilterPopupTab::Text => FilterPopupTab::Rule,
            FilterPopupTab::Columns => FilterPopupTab::Text,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum LogViewMode {
    Table,
    Raw,
}

#[derive(Debug, PartialEq, Clone)]
pub enum SortColumn {
    Id,
    Name,
    Ip,
    Status,
    Os,
    LastKeepAlive,
}

impl SortColumn {
    pub fn next(&self) -> Self {
        match self {
            SortColumn::Id => SortColumn::Name,
            SortColumn::Name => SortColumn::Ip,
            SortColumn::Ip => SortColumn::Status,
            SortColumn::Status => SortColumn::Os,
            SortColumn::Os => SortColumn::LastKeepAlive,
            SortColumn::LastKeepAlive => SortColumn::Id,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum SortOrder {
    Asc,
    Desc,
}

#[derive(Debug, PartialEq, Clone)]
pub enum InspectorTab {
    Hardware,
    Processes,
    Programs,
    Vulnerabilities,
    Logs,
    Config,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ConfigStep {
    Url,
    OsUrl,
    Username,
    Password,
    Confirm,
}

pub struct App {
    pub active_view: ActiveView,
    pub inspector_tab: InspectorTab,
    
    // Sorting state
    pub sort_column: SortColumn,
    pub sort_order: SortOrder,
    
    // Config Wizard state
    pub is_config_wizard_active: bool,
    pub config_step: ConfigStep,
    pub config_url: String,
    pub config_os_url: String,
    pub config_username: String,
    pub config_password: String,
    
    // Interval Popup state
    pub show_interval_popup: bool,
    pub interval_input: String,
    
    // Popups
    pub popup_mode: PopupMode,
    pub input_buffer: String,
    
    pub agents: Vec<WazuhAgent>,
    pub groups: Vec<WazuhGroup>,
    pub selected_agent_index: usize,
    pub selected_tab_index: usize,
    
    // Scrolling state
    pub table_state: ratatui::widgets::TableState,
    pub inspector_table_state: ratatui::widgets::TableState,
    pub groups_table_state: ratatui::widgets::TableState,
    
    // Search state
    pub search_query: String,
    pub is_searching: bool,
    pub agent_filter: AgentFilter,
    
    // Inspector Details
    pub hardware: Option<WazuhHardwareItem>,
    pub processes: Vec<WazuhProcessItem>,
    pub programs: Vec<WazuhProgramItem>,
    pub vulnerabilities: Vec<crate::models::WazuhVulnerabilityItem>,
    pub agent_logs: Vec<serde_json::Value>,
    pub agent_config: Option<serde_json::Value>,
    pub agent_config_component: String,
    pub available_config_components: Vec<String>,
    
    // Selected Log Detail
    pub selected_log: Option<serde_json::Value>,
    pub show_log_json: bool,
    pub log_scroll_offset: usize,
    
    // Security Events
    pub logs: Vec<serde_json::Value>,
    pub log_view_mode: LogViewMode,
    pub log_interval_mins: u32,
    pub log_offset: u32,
    pub log_limit: u32,
    pub log_total: u64,
    
    // Dashboard Stats
    pub vuln_summary: crate::models::VulnerabilitySummary,
    pub threat_stats: ThreatStats,
    
    pub is_loading: bool,
    pub loading_text: String,
    pub spinner_index: usize,
    pub error_message: Option<String>,
    pub should_quit: bool,
    pub api: Option<WazuhApi>,
    pub notifications: Vec<Notification>,
    
    // Filtering
    pub severity_filter: Option<String>,
    pub log_filter: LogFilter,
    pub filter_input_1: String,
    pub filter_input_2: String,
    pub filter_active_input: usize, // 0 for val1, 1 for val2
    pub filter_popup_tab: FilterPopupTab,
    pub visible_log_columns: Vec<LogColumn>,
    pub column_selection_index: usize,

    // Agent Jump
    pub jump_input: String,
    pub jump_index: usize,

    // Command Palette
    pub command_palette_input: String,
    pub command_palette_index: usize,

    // Multi-select
    pub selected_agents: std::collections::HashSet<String>,

    // Chart Data
    pub alert_buckets: Vec<(String, u64)>,
    pub top_agents: Vec<(String, u64)>,
}

impl App {
    pub fn new() -> Self {
        let mut table_state = ratatui::widgets::TableState::default();
        table_state.select(Some(0));
        
        Self {
            active_view: ActiveView::Dashboard,
            inspector_tab: InspectorTab::Hardware,
            sort_column: SortColumn::Id,
            sort_order: SortOrder::Asc,
            is_config_wizard_active: false,
            config_step: ConfigStep::Url,
            config_url: String::new(),
            config_os_url: String::new(),
            config_username: String::new(),
            config_password: String::new(),
            show_interval_popup: false,
            interval_input: String::new(),
            popup_mode: PopupMode::None,
            input_buffer: String::new(),
            agents: Vec::new(),
            groups: Vec::new(),
            selected_agent_index: 0,
            selected_tab_index: 0,
            table_state,
            inspector_table_state: ratatui::widgets::TableState::default(),
            groups_table_state: ratatui::widgets::TableState::default(),
            search_query: String::new(),
            is_searching: false,
            agent_filter: AgentFilter::default(),
            hardware: None,
            processes: Vec::new(),
            programs: Vec::new(),
            vulnerabilities: Vec::new(),
            agent_logs: Vec::new(),
            agent_config: None,
            agent_config_component: "syscheck".to_string(),
            available_config_components: vec![
                "syscheck".to_string(),
                "logcollector".to_string(), 
                "wmodules".to_string(),
                "agent".to_string(),
                "auth".to_string()
            ],
            selected_log: None,
            show_log_json: false,
            log_scroll_offset: 0,
            logs: Vec::new(),
            log_view_mode: LogViewMode::Table,
            log_interval_mins: 15,
            log_offset: 0,
            log_limit: 50,
            log_total: 0,
            vuln_summary: crate::models::VulnerabilitySummary {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                untriaged: 0,
            },
            threat_stats: ThreatStats::default(),
            is_loading: false,
            loading_text: String::from("Fetching data..."),
            spinner_index: 0,
            error_message: None,
            should_quit: false,
            api: None,
            notifications: Vec::new(),
            severity_filter: None,
            log_filter: LogFilter::default(),
            filter_input_1: String::new(),
            filter_input_2: String::new(),
            filter_active_input: 0,
            filter_popup_tab: FilterPopupTab::Severity,
            visible_log_columns: vec![
                LogColumn::Timestamp,
                LogColumn::Level,
                LogColumn::Agent,
                LogColumn::Description,
            ],
            column_selection_index: 0,
            jump_input: String::new(),
            jump_index: 0,
            command_palette_input: String::new(),
            command_palette_index: 0,
            selected_agents: std::collections::HashSet::new(),
            alert_buckets: Vec::new(),
            top_agents: Vec::new(),
        }
    }

    pub fn notify(&mut self, message: &str, level: NotificationLevel) {
        self.notifications.push(Notification {
            message: message.to_string(),
            level,
            timestamp: Instant::now(),
        });
    }

    pub fn show_error(&mut self, title: &str, message: &str) {
        self.popup_mode = PopupMode::Error {
            title: title.to_string(),
            message: message.to_string(),
        };
    }

    pub fn clear_old_notifications(&mut self) {
        self.notifications.retain(|n| n.timestamp.elapsed().as_secs() < 5);
    }

    pub fn parse_and_set_interval(&mut self) -> Result<(), String> {
        let input = self.interval_input.trim().to_lowercase();
        if input.is_empty() { return Ok(()); }

        let (val_str, unit) = if input.ends_with('m') {
            (&input[..input.len()-1], 1)
        } else if input.ends_with('h') {
            (&input[..input.len()-1], 60)
        } else if input.ends_with('d') {
            (&input[..input.len()-1], 1440)
        } else {
            (input.as_str(), 1) // default minutes
        };

        match val_str.parse::<u32>() {
            Ok(val) => {
                self.log_interval_mins = val * unit;
                self.interval_input.clear();
                self.show_interval_popup = false;
                Ok(())
            }
            Err(_) => Err("Invalid number format".to_string())
        }
    }

    pub fn format_interval(&self) -> String {
        if self.log_interval_mins >= 1440 && self.log_interval_mins % 1440 == 0 {
            format!("{}d", self.log_interval_mins / 1440)
        } else if self.log_interval_mins >= 60 && self.log_interval_mins % 60 == 0 {
            format!("{}h", self.log_interval_mins / 60)
        } else {
            format!("{}m", self.log_interval_mins)
        }
    }

    pub fn get_spinner_char(&self) -> &str {
        let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        frames[self.spinner_index % frames.len()]
    }

    pub fn set_loading(&mut self, text: &str) {
        self.is_loading = true;
        self.loading_text = text.to_string();
    }

    pub fn stop_loading(&mut self) {
        self.is_loading = false;
    }

    pub fn get_jump_matches(&self) -> Vec<&crate::models::WazuhAgent> {
        if self.jump_input.is_empty() {
            return Vec::new();
        }
        self.agents.iter()
            .filter(|a| {
                a.name.to_lowercase().contains(&self.jump_input.to_lowercase()) ||
                a.id.to_lowercase().contains(&self.jump_input.to_lowercase())
            })
            .collect()
    }

    pub fn get_command_palette_matches(&self) -> Vec<(&str, &str)> {
        let commands = vec![
            ("Jump to Agent", "Open the jump to agent popup"),
            ("Filter Logs", "Open the log filter popup"),
            ("Search", "Start searching in the current view"),
            ("Refresh", "Refresh the current view"),
            ("Help", "Show help popup"),
            ("Quit", "Quit the application"),
            ("Dashboard", "Go to Dashboard"),
            ("Agent List", "Go to Agent List"),
            ("Security Events", "Go to Security Events"),
            ("Group Management", "Go to Group Management"),
        ];

        if self.command_palette_input.is_empty() {
            return commands;
        }

        let input = self.command_palette_input.to_lowercase();
        commands.into_iter()
            .filter(|(name, desc)| {
                name.to_lowercase().contains(&input) || desc.to_lowercase().contains(&input)
            })
            .collect()
    }

    pub fn set_api(&mut self, api: WazuhApi) {
        self.api = Some(api);
    }

    pub fn next_item(&mut self) {
        match self.active_view {
            ActiveView::Dashboard => {}
            ActiveView::AgentInspector => {}
            ActiveView::GroupManagement => {
                let len = if self.is_searching {
                    let query = self.search_query.clone();
                    self.groups.iter().filter(|g| g.name.to_lowercase().contains(&query.to_lowercase())).count()
                } else {
                    self.groups.len()
                };
                if len > 0 {
                    let current = self.groups_table_state.selected().unwrap_or(0);
                    let next = (current + 1) % len;
                    self.groups_table_state.select(Some(next));
                }
            }
            _ => {
                if !self.agents.is_empty() {
                    self.selected_agent_index = (self.selected_agent_index + 1) % self.agents.len();
                    self.table_state.select(Some(self.selected_agent_index));
                }
            }
        }
    }

    pub fn previous_item(&mut self) {
        match self.active_view {
            ActiveView::Dashboard => {}
            ActiveView::AgentInspector => {}
            ActiveView::GroupManagement => {
                let len = if self.is_searching {
                    let query = self.search_query.clone();
                    self.groups.iter().filter(|g| g.name.to_lowercase().contains(&query.to_lowercase())).count()
                } else {
                    self.groups.len()
                };
                if len > 0 {
                    let current = self.groups_table_state.selected().unwrap_or(0);
                    let next = if current > 0 { current - 1 } else { len - 1 };
                    self.groups_table_state.select(Some(next));
                }
            }
            _ => {
                if !self.agents.is_empty() {
                    if self.selected_agent_index > 0 {
                        self.selected_agent_index -= 1;
                    } else {
                        self.selected_agent_index = self.agents.len() - 1;
                    }
                    self.table_state.select(Some(self.selected_agent_index));
                }
            }
        }
    }

    pub fn scroll_down(&mut self, amount: usize) {
        match self.active_view {
            ActiveView::AgentList => {
                if !self.agents.is_empty() {
                    self.selected_agent_index = std::cmp::min(self.selected_agent_index + amount, self.agents.len() - 1);
                    self.table_state.select(Some(self.selected_agent_index));
                }
            }
            ActiveView::AgentInspector => {
                let len = match self.inspector_tab {
                    InspectorTab::Processes => self.processes.len(),
                    InspectorTab::Programs => self.programs.len(),
                    InspectorTab::Vulnerabilities => self.vulnerabilities.len(),
                    InspectorTab::Logs => self.agent_logs.len(),
                    _ => 0,
                };
                if len > 0 {
                    let current = self.inspector_table_state.selected().unwrap_or(0);
                    let next = std::cmp::min(current + amount, len - 1);
                    self.inspector_table_state.select(Some(next));
                }
            }
            ActiveView::SecurityEvents => {
                if !self.logs.is_empty() {
                    let current = self.table_state.selected().unwrap_or(0);
                    let next = std::cmp::min(current + amount, self.logs.len() - 1);
                    self.table_state.select(Some(next));
                }
            }
            _ => {}
        }
    }

    pub fn scroll_up(&mut self, amount: usize) {
        match self.active_view {
            ActiveView::AgentList => {
                if !self.agents.is_empty() {
                    self.selected_agent_index = self.selected_agent_index.saturating_sub(amount);
                    self.table_state.select(Some(self.selected_agent_index));
                }
            }
            ActiveView::AgentInspector => {
                let current = self.inspector_table_state.selected().unwrap_or(0);
                let next = current.saturating_sub(amount);
                self.inspector_table_state.select(Some(next));
            }
            ActiveView::SecurityEvents => {
                let current = self.table_state.selected().unwrap_or(0);
                let next = current.saturating_sub(amount);
                self.table_state.select(Some(next));
            }
            _ => {}
        }
    }

    pub fn next_tab(&mut self) {
        self.selected_tab_index = (self.selected_tab_index + 1) % 6;
        self.inspector_tab = match self.selected_tab_index {
            0 => InspectorTab::Hardware,
            1 => InspectorTab::Processes,
            2 => InspectorTab::Programs,
            3 => InspectorTab::Vulnerabilities,
            4 => InspectorTab::Logs,
            5 => InspectorTab::Config,
            _ => InspectorTab::Hardware,
        };
        self.inspector_table_state.select(Some(0));
    }

    pub fn get_selected_agent(&self) -> Option<&WazuhAgent> {
        self.agents.get(self.selected_agent_index)
    }

    pub fn toggle_sort(&mut self, column: SortColumn) {
        if self.sort_column == column {
            self.sort_order = match self.sort_order {
                SortOrder::Asc => SortOrder::Desc,
                SortOrder::Desc => SortOrder::Asc,
            };
        } else {
            self.sort_column = column;
            self.sort_order = SortOrder::Asc;
        }
        self.sort_agents();
    }

    pub fn cycle_sort(&mut self) {
        if self.sort_order == SortOrder::Asc {
            self.sort_order = SortOrder::Desc;
        } else {
            self.sort_column = self.sort_column.next();
            self.sort_order = SortOrder::Asc;
        }
        self.sort_agents();
    }

    pub fn toggle_selection(&mut self) {
        if let Some(agent) = self.get_selected_agent() {
            let id = agent.id.clone();
            if self.selected_agents.contains(&id) {
                self.selected_agents.remove(&id);
            } else {
                self.selected_agents.insert(id);
            }
        }
    }

    pub fn sort_agents(&mut self) {
        self.agents.sort_by(|a, b| {
            let res = match self.sort_column {
                SortColumn::Id => a.id.cmp(&b.id),
                SortColumn::Name => a.name.cmp(&b.name),
                SortColumn::Ip => a.ip.cmp(&b.ip),
                SortColumn::Status => a.status.cmp(&b.status),
                SortColumn::Os => {
                    let os_a = a.os.as_ref().map(|o| o.name.clone()).unwrap_or_default();
                    let os_b = b.os.as_ref().map(|o| o.name.clone()).unwrap_or_default();
                    os_a.cmp(&os_b)
                },
                SortColumn::LastKeepAlive => a.last_keep_alive.cmp(&b.last_keep_alive),
            };
            if self.sort_order == SortOrder::Desc {
                res.reverse()
            } else {
                res
            }
        });
    }

    pub fn get_selected_group(&self) -> Option<&WazuhGroup> {
        let query = self.search_query.to_lowercase();
        let filtered_groups: Vec<_> = if self.is_searching {
            self.groups.iter().filter(|g| g.name.to_lowercase().contains(&query)).collect()
        } else {
            self.groups.iter().collect()
        };
        self.groups_table_state.selected().and_then(|idx| filtered_groups.get(idx).copied())
    }

    pub fn export_logs(&mut self) -> Result<String, String> {
        let logs_to_export = match self.active_view {
            ActiveView::SecurityEvents => &self.logs,
            ActiveView::AgentInspector if self.inspector_tab == InspectorTab::Logs => &self.agent_logs,
            _ => return Err("No logs to export in this view".to_string()),
        };

        if logs_to_export.is_empty() {
            return Err("No logs available to export".to_string());
        }

        let filename = format!("wazuh_export_{}.json", chrono::Local::now().format("%Y%m%d_%H%M%S"));
        let mut file = File::create(&filename).map_err(|e| format!("Failed to create file: {}", e))?;
        
        let json_content = serde_json::to_string_pretty(logs_to_export).map_err(|e| format!("JSON error: {}", e))?;
        file.write_all(json_content.as_bytes()).map_err(|e| format!("Write error: {}", e))?;

        Ok(filename)
    }
}
