use crate::models::WazuhAgent;

#[derive(Debug, Clone, PartialEq)]
pub enum FilterPredicate {
    Name(String),
    Id(String),
    Ip(String),
    Status(String),
    Os(String),
    Severity(u32), // For severity filtering
    Global(String),
}

#[derive(Debug, Default, Clone)]
pub struct AgentFilter {
    pub predicates: Vec<FilterPredicate>,
    pub raw_query: String,
}

impl AgentFilter {
    pub fn parse(query: &str) -> Self {
        let mut predicates = Vec::new();
        let parts = query.split_whitespace();

        for part in parts {
            if let Some((field, value)) = part.split_once(':') {
                match field.to_lowercase().as_str() {
                    "name" | "n" => predicates.push(FilterPredicate::Name(value.to_lowercase())),
                    "id" => predicates.push(FilterPredicate::Id(value.to_lowercase())),
                    "ip" => predicates.push(FilterPredicate::Ip(value.to_lowercase())),
                    "status" | "st" => predicates.push(FilterPredicate::Status(value.to_lowercase())),
                    "os" => predicates.push(FilterPredicate::Os(value.to_lowercase())),
                    "sev" | "s" => {
                        match value.to_lowercase().as_str() {
                            "crit" | "critical" => predicates.push(FilterPredicate::Severity(12)),
                            "high" => predicates.push(FilterPredicate::Severity(8)),
                            "med" | "medium" => predicates.push(FilterPredicate::Severity(4)),
                            "low" => predicates.push(FilterPredicate::Severity(0)),
                            _ => {
                                if let Ok(val) = value.parse::<u32>() {
                                    predicates.push(FilterPredicate::Severity(val));
                                }
                            }
                        }
                    }
                    _ => predicates.push(FilterPredicate::Global(part.to_lowercase())),
                }
            } else {
                predicates.push(FilterPredicate::Global(part.to_lowercase()));
            }
        }

        Self {
            predicates,
            raw_query: query.to_string(),
        }
    }

    pub fn matches(&self, agent: &WazuhAgent) -> bool {
        if self.predicates.is_empty() {
            return true;
        }

        // All predicates must match (AND logic)
        self.predicates.iter().all(|p| match p {
            FilterPredicate::Name(val) => agent.name.to_lowercase().contains(val),
            FilterPredicate::Id(val) => agent.id.to_lowercase().contains(val),
            FilterPredicate::Ip(val) => agent.ip.as_ref().map(|ip| ip.contains(val)).unwrap_or(false),
            FilterPredicate::Status(val) => agent.status.to_lowercase() == *val,
            FilterPredicate::Os(val) => agent.os.as_ref().map(|os| {
                os.name.as_ref().map(|n| n.to_lowercase().contains(val)).unwrap_or(false)
            }).unwrap_or(false),
            FilterPredicate::Severity(_) => true, // Severity might need access to vulnerabilities or rule stats, which aren't in WazuhAgent directly
            FilterPredicate::Global(val) => {
                agent.name.to_lowercase().contains(val) ||
                agent.id.to_lowercase().contains(val) ||
                agent.ip.as_ref().map(|ip| ip.contains(val)).unwrap_or(false)
            }
        })
    }
}
