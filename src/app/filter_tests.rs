use crate::app::filter::{AgentFilter, FilterPredicate};
use crate::models::{WazuhAgent, WazuhOS};

#[test]
fn test_agent_filter_parse() {
    let query = "name:web st:active sev:high";
    let filter = AgentFilter::parse(query);
    
    assert_eq!(filter.predicates.len(), 3);
    assert!(filter.predicates.contains(&FilterPredicate::Name("web".to_string())));
    assert!(filter.predicates.contains(&FilterPredicate::Status("active".to_string())));
    assert!(filter.predicates.contains(&FilterPredicate::Severity(8)));
}

#[test]
fn test_agent_filter_matches() {
    let agent = WazuhAgent {
        id: "001".to_string(),
        name: "Web-Server-01".to_string(),
        ip: Some("192.168.1.10".to_string()),
        status: "active".to_string(),
        version: None,
        node_name: None,
        group: None,
        date_add: None,
        last_keep_alive: None,
        os: Some(WazuhOS {
            name: Some("Ubuntu Linux".to_string()),
            version: None,
            platform: None,
            arch: None,
        }),
        manager: None,
    };

    // Test name match
    let filter = AgentFilter::parse("name:web");
    assert!(filter.matches(&agent));

    // Test status match
    let filter = AgentFilter::parse("st:active");
    assert!(filter.matches(&agent));

    // Test OS match
    let filter = AgentFilter::parse("os:ubuntu");
    assert!(filter.matches(&agent));

    // Test global match
    let filter = AgentFilter::parse("01");
    assert!(filter.matches(&agent));

    // Test mismatch
    let filter = AgentFilter::parse("os:windows");
    assert!(!filter.matches(&agent));
}

#[test]
fn test_agent_filter_named_severity() {
    assert_eq!(AgentFilter::parse("sev:critical").predicates[0], FilterPredicate::Severity(12));
    assert_eq!(AgentFilter::parse("sev:high").predicates[0], FilterPredicate::Severity(8));
    assert_eq!(AgentFilter::parse("sev:medium").predicates[0], FilterPredicate::Severity(4));
    assert_eq!(AgentFilter::parse("sev:low").predicates[0], FilterPredicate::Severity(0));
}
