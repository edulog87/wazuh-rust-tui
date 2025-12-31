use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub url: String,
    pub username: String,
    pub password: String,
    pub os_url: Option<String>,
    pub os_username: Option<String>,
    pub os_password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthData {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub data: AuthData,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WazuhOS {
    pub name: Option<String>,
    pub version: Option<String>,
    pub platform: Option<String>,
    pub arch: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WazuhAgent {
    pub id: String,
    pub name: String,
    pub ip: Option<String>,
    pub status: String,
    pub version: Option<String>,
    pub node_name: Option<String>,
    pub group: Option<Vec<String>>,
    #[serde(rename = "dateAdd")]
    pub date_add: Option<String>,
    #[serde(rename = "lastKeepAlive")]
    pub last_keep_alive: Option<String>,
    pub os: Option<WazuhOS>,
    pub manager: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhAgentsData {
    pub affected_items: Vec<WazuhAgent>,
    pub total_affected_items: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhAgentsResponse {
    pub data: WazuhAgentsData,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WazuhGroup {
    pub name: String,
    pub count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhGroupsData {
    pub affected_items: Vec<WazuhGroup>,
    pub total_affected_items: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhGroupsResponse {
    pub data: WazuhGroupsData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhHardwareCpu {
    pub cores: u32,
    pub mhz: f64,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhHardwareRam {
    pub free: u64,
    pub total: u64,
    pub usage: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhHardwareScan {
    pub id: u32,
    pub time: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhHardwareItem {
    pub cpu: WazuhHardwareCpu,
    pub ram: WazuhHardwareRam,
    pub scan: WazuhHardwareScan,
    pub board_serial: String,
    pub agent_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhHardwareData {
    pub affected_items: Vec<WazuhHardwareItem>,
    pub total_affected_items: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhHardwareResponse {
    pub data: WazuhHardwareData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhProcessItem {
    pub name: Option<String>,
    pub cmd: Option<String>,
    pub pid: String,
    pub state: Option<String>,
    pub agent_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhProcessesData {
    pub affected_items: Vec<WazuhProcessItem>,
    pub total_affected_items: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhProcessesResponse {
    pub data: WazuhProcessesData,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WazuhProgramItem {
    pub name: String,
    pub version: String,
    pub vendor: Option<String>,
    pub description: Option<String>,
    pub agent_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WazuhProgramsData {
    pub affected_items: Vec<WazuhProgramItem>,
    pub total_affected_items: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WazuhProgramsResponse {
    pub data: WazuhProgramsData,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentSummary {
    pub total: u32,
    pub active: u32,
    pub disconnected: u32,
    pub never_connected: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WazuhVulnerabilityPackage {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WazuhVulnerabilityItem {
    pub cve: String,
    pub severity: String,
    pub status: Option<String>,
    pub title: Option<String>,
    pub package: Option<WazuhVulnerabilityPackage>,
    // Fallback for older versions or different endpoints
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerabilitySummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub untriaged: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhVulnerabilitiesData {
    pub affected_items: Vec<WazuhVulnerabilityItem>,
    pub total_affected_items: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WazuhVulnerabilitiesResponse {
    pub data: WazuhVulnerabilitiesData,
}

// OpenSearch vulnerability response structures (Wazuh 4.x)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OSVulnerabilityScore {
    pub base: f64,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OSVulnerabilityScanner {
    pub condition: Option<String>,
    pub reference: Option<String>,
    pub source: Option<String>,
    pub vendor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OSVulnerabilityDetails {
    pub category: Option<String>,
    pub classification: Option<String>,
    pub description: Option<String>,
    pub detected_at: Option<String>,
    pub enumeration: Option<String>,
    pub id: String,
    pub published_at: Option<String>,
    pub reference: Option<String>,
    pub scanner: Option<OSVulnerabilityScanner>,
    pub score: Option<OSVulnerabilityScore>,
    pub severity: Option<String>,
    pub under_evaluation: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OSPackage {
    pub name: Option<String>,
    pub version: Option<String>,
    #[serde(rename = "type")]
    pub pkg_type: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OSAgent {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OSVulnerabilityHit {
    pub vulnerability: OSVulnerabilityDetails,
    pub package: Option<OSPackage>,
    pub agent: Option<OSAgent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OSVulnerabilityHitWrapper {
    #[serde(rename = "_source")]
    pub source: OSVulnerabilityHit,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OSVulnerabilityHitsTotal {
    pub value: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OSVulnerabilityHits {
    pub total: OSVulnerabilityHitsTotal,
    pub hits: Vec<OSVulnerabilityHitWrapper>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OSVulnerabilityResponse {
    pub hits: OSVulnerabilityHits,
}
