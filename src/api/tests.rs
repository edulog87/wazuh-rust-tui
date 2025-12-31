use crate::api::WazuhApi;
use crate::models::{Config, WazuhAgentsResponse};

#[tokio::test]
async fn test_auth_failure() {
    let config = Config {
        url: "https://localhost:55000".to_string(),
        username: "invalid".to_string(),
        password: "password".to_string(),
        os_url: None,
        os_username: None,
        os_password: None,
    };
    let api = WazuhApi::new(config);
    let result = api.authenticate().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_deserialization_agent() {
    let json = r#"{
        "data": {
            "affected_items": [
                {
                    "id": "001",
                    "name": "agent1",
                    "status": "active"
                }
            ],
            "total_affected_items": 1
        }
    }"#;
    let res: WazuhAgentsResponse = serde_json::from_str(json).unwrap();
    assert_eq!(res.data.affected_items[0].id, "001");
}

#[tokio::test]
async fn test_deserialization_hardware() {
    let json = r#"{
        "data": {
            "affected_items": [
                {
                    "cpu": {
                        "cores": 4,
                        "mhz": 2400.0,
                        "name": "Intel Core i7"
                    },
                    "ram": {
                        "free": 1024,
                        "total": 4096,
                        "usage": 75
                    },
                    "scan": {
                        "id": 1,
                        "time": "2023-01-01T00:00:00Z"
                    },
                    "board_serial": "XYZ123",
                    "agent_id": "001"
                }
            ],
            "total_affected_items": 1
        }
    }"#;
    let res: crate::models::WazuhHardwareResponse = serde_json::from_str(json).unwrap();
    assert_eq!(res.data.affected_items[0].cpu.cores, 4);
    assert_eq!(res.data.affected_items[0].board_serial, "XYZ123");
}

#[tokio::test]
async fn test_deserialization_processes() {
    let json = r#"{
        "data": {
            "affected_items": [
                {
                    "name": "systemd",
                    "cmd": "/usr/lib/systemd/systemd",
                    "pid": "1",
                    "state": "running",
                    "agent_id": "001"
                }
            ],
            "total_affected_items": 1
        }
    }"#;
    let res: crate::models::WazuhProcessesResponse = serde_json::from_str(json).unwrap();
    assert_eq!(res.data.affected_items[0].pid, "1");
}

#[tokio::test]
async fn test_deserialization_programs() {
    let json = r#"{
        "data": {
            "affected_items": [
                {
                    "name": "libc6",
                    "version": "2.31-0ubuntu9.9",
                    "vendor": "Ubuntu",
                    "description": "GNU C Library",
                    "agent_id": "001"
                }
            ],
            "total_affected_items": 1
        }
    }"#;
    let res: crate::models::WazuhProgramsResponse = serde_json::from_str(json).unwrap();
    assert_eq!(res.data.affected_items[0].name, "libc6");
}

#[tokio::test]
async fn test_deserialization_groups() {
    let json = r#"{
        "data": {
            "affected_items": [
                {
                    "name": "default",
                    "count": 5
                }
            ],
            "total_affected_items": 1
        }
    }"#;
    let res: crate::models::WazuhGroupsResponse = serde_json::from_str(json).unwrap();
    assert_eq!(res.data.affected_items[0].name, "default");
    assert_eq!(res.data.affected_items[0].count, Some(5));
}

#[tokio::test]
async fn test_deserialization_vulnerabilities_nested() {
    let json = r#"{
        "data": {
            "affected_items": [
                {
                    "cve": "CVE-2021-1234",
                    "severity": "High",
                    "package": {
                        "name": "nested-package",
                        "version": "2.0.0"
                    },
                    "status": "VALID"
                }
            ],
            "total_affected_items": 1
        }
    }"#;
    let res: crate::models::WazuhVulnerabilitiesResponse = serde_json::from_str(json).unwrap();
    assert_eq!(res.data.affected_items[0].cve, "CVE-2021-1234");
    assert_eq!(res.data.affected_items[0].package.as_ref().unwrap().name, "nested-package");
}

#[tokio::test]
async fn test_deserialization_vulnerabilities_flat() {
    let json = r#"{
        "data": {
            "affected_items": [
                {
                    "cve": "CVE-2021-5678",
                    "severity": "Medium",
                    "name": "flat-package",
                    "version": "1.0.0"
                }
            ],
            "total_affected_items": 1
        }
    }"#;
    let res: crate::models::WazuhVulnerabilitiesResponse = serde_json::from_str(json).unwrap();
    assert_eq!(res.data.affected_items[0].cve, "CVE-2021-5678");
    assert_eq!(res.data.affected_items[0].name, Some("flat-package".to_string()));
}

#[tokio::test]
async fn test_deserialization_logs() {
    let json = r#"{
        "hits": {
            "total": { "value": 1 },
            "hits": [
                {
                    "_source": {
                        "@timestamp": "2023-01-01T00:00:00Z",
                        "rule": {
                            "level": 10,
                            "description": "Test alert"
                        },
                        "agent": {
                            "id": "001",
                            "name": "agent1"
                        }
                    }
                }
            ]
        }
    }"#;
    let res: serde_json::Value = serde_json::from_str(json).unwrap();
    let hits = res.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["_source"]["rule"]["level"], 10);
}

#[test]
fn test_log_filter_query_generation() {
    use crate::app::{LogFilter, SeverityFilterMode};
    
    // Test Exact mode
    let mut filter = LogFilter::default();
    filter.mode = SeverityFilterMode::Exact;
    filter.val1 = 10;
    let query = serde_json::json!({ "term": { "rule.level": filter.val1 } });
    assert_eq!(query["term"]["rule.level"], 10);

    // Test Range mode
    let mut filter = LogFilter::default();
    filter.mode = SeverityFilterMode::Range;
    filter.val1 = 5;
    filter.val2 = 12;
    let query = serde_json::json!({ "range": { "rule.level": { "gte": filter.val1, "lte": filter.val2 } } });
    assert_eq!(query["range"]["rule.level"]["gte"], 5);
    assert_eq!(query["range"]["rule.level"]["lte"], 12);
}

// OpenSearch vulnerability response deserialization test
#[tokio::test]
async fn test_deserialization_os_vulnerabilities() {
    let json = r#"{
        "hits": {
            "total": { "value": 2 },
            "hits": [
                {
                    "_source": {
                        "agent": {
                            "id": "005",
                            "name": "SRVDB1"
                        },
                        "package": {
                            "name": "pip",
                            "version": "23.3.1",
                            "type": "pypi"
                        },
                        "vulnerability": {
                            "id": "CVE-2025-8869",
                            "severity": "Critical",
                            "description": "pip vulnerability",
                            "detected_at": "2025-12-24T16:22:51.414Z",
                            "enumeration": "CVE",
                            "score": {
                                "base": 9.8,
                                "version": "3.1"
                            }
                        }
                    }
                }
            ]
        }
    }"#;
    let res: crate::models::OSVulnerabilityResponse = serde_json::from_str(json).unwrap();
    assert_eq!(res.hits.total.value, 2);
    assert_eq!(res.hits.hits.len(), 1);
    assert_eq!(res.hits.hits[0].source.vulnerability.id, "CVE-2025-8869");
    assert_eq!(res.hits.hits[0].source.vulnerability.severity, Some("Critical".to_string()));
    assert_eq!(res.hits.hits[0].source.package.as_ref().unwrap().name, Some("pip".to_string()));
}

// ============================================================================
// INTEGRATION TESTS - These tests require a live Wazuh API
// Run with: cargo test --features integration -- --ignored
// ============================================================================

/// Helper to create a config for integration tests
fn get_integration_config() -> Config {
    Config {
        url: "https://192.168.0.113:55000".to_string(),
        username: "wazuh".to_string(),
        password: "xxxxxxx".to_string(),
        os_url: Some("https://192.168.0.113:9200".to_string()),
        os_username: Some("wazuh".to_string()),
        os_password: Some("xxxxxxx".to_string()),
    }
}

#[tokio::test]
#[ignore] // Run with: cargo test test_real_authentication -- --ignored
async fn test_real_authentication() {
    let config = get_integration_config();
    let api = WazuhApi::new(config);
    
    let result = api.authenticate().await;
    assert!(result.is_ok(), "Authentication failed: {:?}", result.err());
    
    let token = result.unwrap();
    assert!(!token.is_empty(), "Token should not be empty");
    println!("Authentication successful, token length: {}", token.len());
}

#[tokio::test]
#[ignore]
async fn test_real_list_agents() {
    let config = get_integration_config();
    let api = WazuhApi::new(config);
    
    let result = api.list_agents(None, 0, 10).await;
    assert!(result.is_ok(), "Failed to list agents: {:?}", result.err());
    
    let response = result.unwrap();
    assert!(response.data.total_affected_items > 0, "Expected at least one agent");
    println!("Found {} agents", response.data.total_affected_items);
    
    for agent in &response.data.affected_items {
        println!("  - {} ({}): {}", agent.id, agent.name, agent.status);
    }
}

#[tokio::test]
#[ignore]
async fn test_real_get_vulnerabilities() {
    let config = get_integration_config();
    let api = WazuhApi::new(config);
    
    // First get an agent ID
    let agents = api.list_agents(None, 0, 10).await.expect("Failed to list agents");
    let agent = agents.data.affected_items.iter()
        .find(|a| a.status == "active" && a.id != "000")
        .expect("No active non-manager agent found");
    
    println!("Testing vulnerabilities for agent {} ({})", agent.id, agent.name);
    
    let result = api.get_vulnerabilities(&agent.id).await;
    assert!(result.is_ok(), "Failed to get vulnerabilities: {:?}", result.err());
    
    let response = result.unwrap();
    println!("Found {} vulnerabilities", response.data.total_affected_items);
    
    // Print first few vulnerabilities
    for vuln in response.data.affected_items.iter().take(5) {
        let pkg_name = vuln.package.as_ref()
            .map(|p| p.name.clone())
            .or(vuln.name.clone())
            .unwrap_or_else(|| "unknown".to_string());
        println!("  - {} [{}]: {}", vuln.cve, vuln.severity, pkg_name);
    }
}

#[tokio::test]
#[ignore]
async fn test_real_get_agent_config() {
    let config = get_integration_config();
    let api = WazuhApi::new(config);
    
    // First get an agent ID
    let agents = api.list_agents(None, 0, 10).await.expect("Failed to list agents");
    let agent = agents.data.affected_items.iter()
        .find(|a| a.status == "active" && a.id != "000")
        .expect("No active non-manager agent found");
    
    println!("Testing config for agent {} ({})", agent.id, agent.name);
    
    // Valid components: agent, agentless, analysis, auth, com, csyslog, integrator, 
    //                   logcollector, mail, monitor, request, syscheck, wazuh-db, wmodules
    
    // Test syscheck config (most reliable)
    let result = api.get_agent_config(&agent.id, "syscheck").await;
    assert!(result.is_ok(), "Failed to get syscheck config: {:?}", result.err());
    
    let config_json = result.unwrap();
    println!("Syscheck config keys: {:?}", 
        config_json.as_object().map(|o| o.keys().collect::<Vec<_>>()));
    
    // Test logcollector config
    let result = api.get_agent_config(&agent.id, "logcollector").await;
    assert!(result.is_ok(), "Failed to get logcollector config: {:?}", result.err());
    println!("Logcollector config retrieved successfully");
    
    // Test wmodules (wazuh modules) config
    let result = api.get_agent_config(&agent.id, "wmodules").await;
    assert!(result.is_ok(), "Failed to get wmodules config: {:?}", result.err());
    println!("Wmodules config retrieved successfully");
    
    // Test agent config (client settings)
    let result = api.get_agent_config(&agent.id, "agent").await;
    assert!(result.is_ok(), "Failed to get agent config: {:?}", result.err());
    println!("Agent config retrieved successfully");
}

#[tokio::test]
#[ignore]
async fn test_real_get_hardware() {
    let config = get_integration_config();
    let api = WazuhApi::new(config);
    
    let agents = api.list_agents(None, 0, 10).await.expect("Failed to list agents");
    let agent = agents.data.affected_items.iter()
        .find(|a| a.status == "active" && a.id != "000")
        .expect("No active non-manager agent found");
    
    let result = api.get_hardware_info(&agent.id).await;
    assert!(result.is_ok(), "Failed to get hardware info: {:?}", result.err());
    
    let hw = result.unwrap();
    if let Some(item) = hw.data.affected_items.first() {
        println!("CPU: {} ({} cores @ {} MHz)", item.cpu.name, item.cpu.cores, item.cpu.mhz);
        println!("RAM: {} / {} MB ({}% used)", 
            item.ram.free / 1024 / 1024, 
            item.ram.total / 1024 / 1024, 
            item.ram.usage);
    }
}

#[tokio::test]
#[ignore]
async fn test_real_get_logs() {
    let config = get_integration_config();
    let api = WazuhApi::new(config);
    
    let result = api.get_logs(None, 60, 0, 10, None).await;
    assert!(result.is_ok(), "Failed to get logs: {:?}", result.err());
    
    let logs = result.unwrap();
    let hits = logs.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array());
    
    if let Some(hits) = hits {
        println!("Found {} log entries", hits.len());
        for hit in hits.iter().take(3) {
            if let Some(source) = hit.get("_source") {
                let level = source.get("rule").and_then(|r| r.get("level")).and_then(|l| l.as_i64()).unwrap_or(0);
                let desc = source.get("rule").and_then(|r| r.get("description")).and_then(|d| d.as_str()).unwrap_or("N/A");
                println!("  - Level {}: {}", level, desc);
            }
        }
    }
}
