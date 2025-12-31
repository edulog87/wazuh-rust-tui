use reqwest::Client;
use crate::models::{Config, AuthResponse, WazuhAgentsResponse, WazuhGroupsResponse};
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct WazuhApi {
    pub client: Client,
    pub config: Config,
    pub token: Arc<RwLock<Option<String>>>,
}

impl WazuhApi {
    pub fn new(config: Config) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        
        Self {
            client,
            config,
            token: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn authenticate(&self) -> Result<String> {
        let url = format!("{}/security/user/authenticate", self.config.url);
        
        let response = self.client
            .post(&url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Authentication failed with status: {}", response.status()));
        }

        let auth_res: AuthResponse = response.json().await?;
        let token = auth_res.data.token;
        
        let mut token_lock = self.token.write().await;
        *token_lock = Some(token.clone());
        
        Ok(token)
    }

    async fn get_token(&self) -> Result<String> {
        {
            let token_lock = self.token.read().await;
            if let Some(token) = &*token_lock {
                return Ok(token.clone());
            }
        }
        self.authenticate().await
    }

    async fn request(&self, method: reqwest::Method, url: &str, body: Option<serde_json::Value>) -> Result<reqwest::Response> {
        let token = self.get_token().await?;
        let mut rb = self.client.request(method.clone(), url).bearer_auth(&token);
        
        if let Some(b) = body.clone() {
            rb = rb.json(&b);
        }

        let response = rb.send().await?;
        let status = response.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            let token = self.authenticate().await?;
            let mut rb = self.client.request(method, url).bearer_auth(token);
            if let Some(b) = body {
                rb = rb.json(&b);
            }
            let response = rb.send().await?;
            if !response.status().is_success() {
                let error_text = response.text().await?;
                return Err(anyhow!("Request failed with status {}: {}", status, error_text));
            }
            return Ok(response);
        }

        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Request failed with status {}: {}", status, error_text));
        }

        Ok(response)
    }

    pub async fn list_agents(&self, group: Option<&str>, offset: u32, limit: u32) -> Result<WazuhAgentsResponse> {
        let mut url = format!("{}/agents?offset={}&limit={}", self.config.url, offset, limit);
        if let Some(g) = group {
            if g != "all" {
                url.push_str(&format!("&group={}", g));
            }
        }

        let response = self.request(reqwest::Method::GET, &url, None).await?;
        Ok(response.json().await?)
    }

    pub async fn get_groups(&self) -> Result<WazuhGroupsResponse> {
        let url = format!("{}/groups", self.config.url);
        let response = self.request(reqwest::Method::GET, &url, None).await?;
        Ok(response.json().await?)
    }

    pub async fn create_group(&self, group_id: &str) -> Result<serde_json::Value> {
        let url = format!("{}/groups", self.config.url);
        let body = serde_json::json!({ "group_id": group_id });
        let response = self.request(reqwest::Method::POST, &url, Some(body)).await?;
        Ok(response.json().await?)
    }

    pub async fn assign_agents_to_group(&self, group_id: &str, agent_ids: &[&str]) -> Result<serde_json::Value> {
        let url = format!("{}/groups/{}/agents?agents_list={}", self.config.url, group_id, agent_ids.join(","));
        let response = self.request(reqwest::Method::PUT, &url, None).await?;
        Ok(response.json().await?)
    }

    pub async fn remove_agents_from_group(&self, group_id: &str, agent_ids: &[&str]) -> Result<serde_json::Value> {
        let url = format!("{}/groups/{}/agents?agents_list={}", self.config.url, group_id, agent_ids.join(","));
        let response = self.request(reqwest::Method::DELETE, &url, None).await?;
        Ok(response.json().await?)
    }

    pub async fn delete_group(&self, group_id: &str) -> Result<serde_json::Value> {
        let url = format!("{}/groups?groups_list={}", self.config.url, group_id);
        let response = self.request(reqwest::Method::DELETE, &url, None).await?;
        Ok(response.json().await?)
    }

    pub async fn get_hardware_info(&self, agent_id: &str) -> Result<crate::models::WazuhHardwareResponse> {
        let url = format!("{}/syscollector/{}/hardware", self.config.url, agent_id);
        let response = self.request(reqwest::Method::GET, &url, None).await?;
        Ok(response.json().await?)
    }

    pub async fn get_processes(&self, agent_id: &str) -> Result<crate::models::WazuhProcessesResponse> {
        let url = format!("{}/syscollector/{}/processes", self.config.url, agent_id);
        let response = self.request(reqwest::Method::GET, &url, None).await?;
        Ok(response.json().await?)
    }

    pub async fn get_programs(&self, agent_id: &str) -> Result<crate::models::WazuhProgramsResponse> {
        let url = format!("{}/syscollector/{}/packages", self.config.url, agent_id);
        let response = self.request(reqwest::Method::GET, &url, None).await?;
        Ok(response.json().await?)
    }

    pub async fn get_vulnerabilities(&self, agent_id: &str) -> Result<crate::models::WazuhVulnerabilitiesResponse> {
        // Wazuh 4.x stores vulnerabilities in OpenSearch, not in REST API
        let os_url = self.config.os_url.as_ref().ok_or_else(|| anyhow!("OpenSearch URL not configured"))?;
        
        let query = serde_json::json!({
            "size": 500,
            "query": {
                "bool": {
                    "must": [
                        { "term": { "agent.id": agent_id } }
                    ]
                }
            },
            "sort": [
                { "vulnerability.severity": { "order": "asc" } }
            ]
        });

        let mut rb = self.client.post(format!("{}/wazuh-states-vulnerabilities*/_search", os_url));
        if let (Some(u), Some(p)) = (&self.config.os_username, &self.config.os_password) {
            rb = rb.basic_auth(u, Some(p));
        }

        let response = rb.json(&query).send().await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("OpenSearch query failed: {}", error_text));
        }
        
        let os_response: crate::models::OSVulnerabilityResponse = response.json().await?;
        
        // Convert OpenSearch format to our standard format
        let items: Vec<crate::models::WazuhVulnerabilityItem> = os_response.hits.hits.iter().map(|hit| {
            let src = &hit.source;
            let pkg = src.package.as_ref();
            
            crate::models::WazuhVulnerabilityItem {
                cve: src.vulnerability.id.clone(),
                severity: src.vulnerability.severity.clone().unwrap_or_else(|| "-".to_string()),
                status: None,
                title: src.vulnerability.description.clone(),
                package: pkg.map(|p| crate::models::WazuhVulnerabilityPackage {
                    name: p.name.clone().unwrap_or_default(),
                    version: p.version.clone().unwrap_or_default(),
                    architecture: None,
                }),
                name: pkg.and_then(|p| p.name.clone()),
                version: pkg.and_then(|p| p.version.clone()),
            }
        }).collect();
        
        let total = os_response.hits.total.value;
        
        Ok(crate::models::WazuhVulnerabilitiesResponse {
            data: crate::models::WazuhVulnerabilitiesData {
                affected_items: items,
                total_affected_items: total,
            }
        })
    }

    pub async fn upgrade_agents(&self, agent_ids: &[&str]) -> Result<serde_json::Value> {
        let url = format!("{}/agents/upgrade?agents_list={}", self.config.url, agent_ids.join(","));
        let response = self.request(reqwest::Method::PUT, &url, None).await?;
        Ok(response.json().await?)
    }

    pub async fn get_agent_config(&self, agent_id: &str, component: &str) -> Result<serde_json::Value> {
        // Wazuh config endpoint format: /agents/{id}/config/{component}/{section}
        // Valid components: agent, agentless, analysis, auth, com, csyslog, integrator, 
        //                   logcollector, mail, monitor, request, syscheck, wazuh-db, wmodules
        // Common mappings: component and section are often the same (syscheck/syscheck)
        // Special cases: logcollector/localfile, agent/client, analysis/global
        let section = match component {
            "logcollector" => "localfile",
            "agent" => "client",  // agent component uses client section
            "analysis" => "global",  // Note: may fail if analysis module is disabled
            "wmodules" => "wmodules",
            _ => component,  // For syscheck, auth, etc. section = component
        };
        
        let url = format!("{}/agents/{}/config/{}/{}", self.config.url, agent_id, component, section);
        let response = self.request(reqwest::Method::GET, &url, None).await?;
        let json: serde_json::Value = response.json().await?;
        
        // Config is returned in data.{section} format
        if let Some(data) = json.get("data") {
            if let Some(config) = data.get(section) {
                return Ok(config.clone());
            }
            // Fallback to returning the whole data object
            return Ok(data.clone());
        }
        
        Ok(json)
    }

    pub async fn get_summary(&self) -> Result<crate::models::AgentSummary> {
        let response = self.list_agents(None, 0, 500).await?;
        let agents = response.data.affected_items;
        
        let mut summary = crate::models::AgentSummary {
            total: response.data.total_affected_items,
            active: 0,
            disconnected: 0,
            never_connected: 0,
        };

        for agent in agents {
            match agent.status.as_str() {
                "active" => summary.active += 1,
                "disconnected" => summary.disconnected += 1,
                "never_connected" => summary.never_connected += 1,
                _ => {}
            }
        }

        Ok(summary)
    }

    pub async fn restart_agents(&self, agent_ids: &[&str]) -> Result<serde_json::Value> {
        let url = format!("{}/agents/restart?agents_list={}", self.config.url, agent_ids.join(","));
        let response = self.request(reqwest::Method::PUT, &url, None).await?;
        Ok(response.json().await?)
    }

    pub async fn update_agent_config(&self, agent_id: &str, component: &str, config: serde_json::Value) -> Result<serde_json::Value> {
        // Use same section mapping as get_agent_config
        let section = match component {
            "logcollector" => "localfile",
            "agent" => "client",
            "analysis" => "global",
            _ => component,
        };
        
        let url = format!("{}/agents/{}/config/{}/{}", self.config.url, agent_id, component, section);
        let response = self.request(reqwest::Method::PUT, &url, Some(config)).await?;
        Ok(response.json().await?)
    }

    pub async fn get_logs(&self, agent_id: Option<&str>, minutes: u32, offset: u32, limit: u32, filter: Option<&crate::app::LogFilter>) -> Result<serde_json::Value> {
        let os_url = self.config.os_url.as_ref().ok_or_else(|| anyhow!("OpenSearch URL not configured"))?;
        
        let mut must = vec![
            serde_json::json!({
                "range": {
                    "@timestamp": {
                        "gte": format!("now-{}m", minutes),
                        "lte": "now"
                    }
                }
            })
        ];

        if let Some(f) = filter {
            // Severity filter
            let severity_query = match f.mode {
                crate::app::SeverityFilterMode::Min => serde_json::json!({ "range": { "rule.level": { "gte": f.val1 } } }),
                crate::app::SeverityFilterMode::Max => serde_json::json!({ "range": { "rule.level": { "lte": f.val1 } } }),
                crate::app::SeverityFilterMode::Exact => serde_json::json!({ "term": { "rule.level": f.val1 } }),
                crate::app::SeverityFilterMode::Range => serde_json::json!({ "range": { "rule.level": { "gte": f.val1, "lte": f.val2 } } }),
            };
            must.push(severity_query);
            
            // Agent name filter (wildcard search)
            if !f.agent_filter.is_empty() {
                must.push(serde_json::json!({
                    "wildcard": {
                        "agent.name": {
                            "value": format!("*{}*", f.agent_filter.to_lowercase()),
                            "case_insensitive": true
                        }
                    }
                }));
            }
            
            // Rule ID filter (supports comma-separated list and wildcards)
            if !f.rule_id_filter.is_empty() {
                if f.rule_id_filter.contains(',') {
                    // Multiple rule IDs
                    let rule_ids: Vec<&str> = f.rule_id_filter.split(',').map(|s| s.trim()).collect();
                    must.push(serde_json::json!({
                        "terms": {
                            "rule.id": rule_ids
                        }
                    }));
                } else if f.rule_id_filter.contains('*') {
                    // Wildcard search
                    must.push(serde_json::json!({
                        "wildcard": {
                            "rule.id": {
                                "value": f.rule_id_filter.clone()
                            }
                        }
                    }));
                } else {
                    // Exact match
                    must.push(serde_json::json!({
                        "term": {
                            "rule.id": f.rule_id_filter.clone()
                        }
                    }));
                }
            }
            
            // Description filter (full-text search)
            if !f.description_filter.is_empty() {
                must.push(serde_json::json!({
                    "match": {
                        "rule.description": {
                            "query": f.description_filter.clone(),
                            "operator": "and"
                        }
                    }
                }));
            }
            
            // MITRE filter (ID or tactic)
            if !f.mitre_filter.is_empty() {
                let mitre_lower = f.mitre_filter.to_lowercase();
                must.push(serde_json::json!({
                    "bool": {
                        "should": [
                            { "wildcard": { "rule.mitre.id": { "value": format!("*{}*", mitre_lower), "case_insensitive": true } } },
                            { "wildcard": { "rule.mitre.tactic": { "value": format!("*{}*", mitre_lower), "case_insensitive": true } } },
                            { "wildcard": { "rule.mitre.technique": { "value": format!("*{}*", mitre_lower), "case_insensitive": true } } }
                        ],
                        "minimum_should_match": 1
                    }
                }));
            }
        }

        if let Some(id) = agent_id {
            must.push(serde_json::json!({ "term": { "agent.id": id } }));
        }

        let query = serde_json::json!({
            "from": offset,
            "size": limit,
            "sort": [{ "@timestamp": { "order": "desc" } }],
            "query": {
                "bool": {
                    "must": must
                }
            }
        });

        let mut rb = self.client.post(format!("{}/wazuh-alerts-*/_search", os_url));
        if let (Some(u), Some(p)) = (&self.config.os_username, &self.config.os_password) {
            rb = rb.basic_auth(u, Some(p));
        }

        let response = rb.json(&query).send().await?;
        Ok(response.json().await?)
    }
}

#[cfg(test)]
mod tests;
