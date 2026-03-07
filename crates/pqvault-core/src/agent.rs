use chrono::{DateTime, Local, Duration};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::crypto::{password_decrypt, password_encrypt};
use crate::keychain::get_master_password;

fn agent_data_path() -> PathBuf {
    dirs::home_dir().unwrap().join(".pqvault").join("agents.enc")
}

/// Agent token for scoped access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentToken {
    pub id: String,
    pub name: String,
    pub token: String,
    pub allowed_keys: Vec<String>,
    pub allowed_categories: Vec<String>,
    pub created: String,
    pub expires: Option<String>,
    pub last_used: Option<String>,
    pub total_requests: u64,
    pub budget: Option<AgentBudget>,
    pub active: bool,
}

/// Per-agent spending budget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBudget {
    pub max_monthly_usd: f64,
    pub current_monthly_usd: f64,
    pub month: String, // "2026-03" format
    pub circuit_breaker_triggered: bool,
    pub max_requests_per_hour: Option<u32>,
    pub requests_this_hour: u32,
    pub hour_start: Option<String>,
}

/// All agent data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentData {
    pub tokens: HashMap<String, AgentToken>,
}

/// Load agent data from encrypted storage
pub fn load_agents() -> AgentData {
    let path = agent_data_path();
    if !path.exists() {
        return AgentData::default();
    }

    if let Ok(Some(pw)) = get_master_password() {
        if let Ok(encrypted) = fs::read(&path) {
            if let Ok(plaintext) = password_decrypt(&encrypted, &pw) {
                if let Ok(content) = String::from_utf8(plaintext) {
                    if let Ok(data) = serde_json::from_str(&content) {
                        return data;
                    }
                }
            }
        }
    }

    AgentData::default()
}

/// Save agent data to encrypted storage
pub fn save_agents(data: &AgentData) -> bool {
    if let Ok(Some(pw)) = get_master_password() {
        if let Ok(json) = serde_json::to_string_pretty(data) {
            if let Ok(encrypted) = password_encrypt(json.as_bytes(), &pw) {
                let dir = agent_data_path().parent().unwrap().to_path_buf();
                let _ = fs::create_dir_all(&dir);
                if fs::write(agent_data_path(), &encrypted).is_ok() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(
                            agent_data_path(),
                            fs::Permissions::from_mode(0o600),
                        );
                    }
                    return true;
                }
            }
        }
    }
    false
}

/// Generate a random agent token
fn generate_agent_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 24] = rng.gen();
    format!("pqv_{}", hex::encode(bytes))
}

/// Generate a short unique ID
fn generate_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 6] = rng.gen();
    hex::encode(bytes)
}

/// Create a new agent token
pub fn create_agent(
    name: &str,
    allowed_keys: Vec<String>,
    allowed_categories: Vec<String>,
    expires_hours: Option<i64>,
    max_monthly_usd: Option<f64>,
    max_requests_per_hour: Option<u32>,
) -> AgentToken {
    let mut data = load_agents();

    let id = generate_id();
    let token = generate_agent_token();
    let now = Local::now();

    let expires = expires_hours.map(|h| {
        (now + Duration::hours(h)).to_rfc3339()
    });

    let budget = max_monthly_usd.map(|max| AgentBudget {
        max_monthly_usd: max,
        current_monthly_usd: 0.0,
        month: now.format("%Y-%m").to_string(),
        circuit_breaker_triggered: false,
        max_requests_per_hour,
        requests_this_hour: 0,
        hour_start: None,
    });

    let agent = AgentToken {
        id: id.clone(),
        name: name.to_string(),
        token: token.clone(),
        allowed_keys,
        allowed_categories,
        created: now.to_rfc3339(),
        expires,
        last_used: None,
        total_requests: 0,
        budget,
        active: true,
    };

    data.tokens.insert(id.clone(), agent.clone());
    save_agents(&data);

    crate::audit::log_access("agent_create", &id, "", name);

    agent
}

/// Revoke an agent token
pub fn revoke_agent(id: &str) -> Option<String> {
    let mut data = load_agents();
    if let Some(agent) = data.tokens.get_mut(id) {
        agent.active = false;
        let name = agent.name.clone();
        save_agents(&data);
        crate::audit::log_access("agent_revoke", id, "", &name);
        Some(name)
    } else {
        None
    }
}

/// List all agent tokens
pub fn list_agents() -> Vec<AgentToken> {
    let data = load_agents();
    let mut agents: Vec<_> = data.tokens.values().cloned().collect();
    agents.sort_by(|a, b| a.created.cmp(&b.created));
    agents
}

/// Validate an agent token and check permissions
pub fn validate_agent_access(token: &str, key_name: &str, key_category: &str) -> AgentAccessResult {
    let mut data = load_agents();

    // Find agent ID by token
    let agent_id = match data.tokens.values().find(|a| a.token == token) {
        Some(a) => a.id.clone(),
        None => return AgentAccessResult::Denied("Invalid token".to_string()),
    };

    let agent = data.tokens.get(&agent_id).unwrap();

    // Check active
    if !agent.active {
        return AgentAccessResult::Denied("Token revoked".to_string());
    }

    // Check expiry
    if let Some(ref expires) = agent.expires {
        if let Ok(exp) = DateTime::parse_from_rfc3339(expires) {
            if Local::now() > exp {
                return AgentAccessResult::Denied("Token expired".to_string());
            }
        }
    }

    // Check key permission
    let key_allowed = agent.allowed_keys.is_empty()
        || agent.allowed_keys.contains(&key_name.to_string())
        || agent.allowed_keys.iter().any(|k| k == "*");

    let cat_allowed = agent.allowed_categories.is_empty()
        || agent.allowed_categories.contains(&key_category.to_string())
        || agent.allowed_categories.iter().any(|c| c == "*");

    if !key_allowed && !cat_allowed {
        return AgentAccessResult::Denied(format!(
            "Agent '{}' not authorized for key '{}'",
            agent.name, key_name
        ));
    }

    // Now get mutable reference for updates
    let agent = data.tokens.get_mut(&agent_id).unwrap();

    // Check budget
    if let Some(ref mut budget) = agent.budget {
        let current_month = Local::now().format("%Y-%m").to_string();
        if budget.month != current_month {
            budget.current_monthly_usd = 0.0;
            budget.month = current_month;
            budget.circuit_breaker_triggered = false;
        }

        if budget.circuit_breaker_triggered {
            let msg = format!(
                "Circuit breaker triggered for '{}' (${:.2}/${:.2})",
                agent.name, budget.current_monthly_usd, budget.max_monthly_usd
            );
            return AgentAccessResult::Denied(msg);
        }

        if budget.current_monthly_usd >= budget.max_monthly_usd {
            budget.circuit_breaker_triggered = true;
            let msg = format!(
                "Budget exceeded for '{}' (${:.2}/${:.2})",
                agent.name, budget.current_monthly_usd, budget.max_monthly_usd
            );
            save_agents(&data);
            return AgentAccessResult::Denied(msg);
        }

        // Check rate limit
        if let Some(max_rph) = budget.max_requests_per_hour {
            let now = Local::now();
            let hour_key = now.format("%Y-%m-%dT%H").to_string();
            if budget.hour_start.as_deref() != Some(&hour_key) {
                budget.requests_this_hour = 0;
                budget.hour_start = Some(hour_key);
            }
            if budget.requests_this_hour >= max_rph {
                let msg = format!(
                    "Rate limit exceeded for '{}' ({}/{} per hour)",
                    agent.name, budget.requests_this_hour, max_rph
                );
                return AgentAccessResult::RateLimited(msg);
            }
            budget.requests_this_hour += 1;
        }
    }

    // Update usage
    agent.last_used = Some(Local::now().to_rfc3339());
    agent.total_requests += 1;

    let agent_name = agent.name.clone();
    let result_id = agent.id.clone();
    save_agents(&data);

    AgentAccessResult::Allowed {
        agent_name,
        agent_id: result_id,
    }
}

/// Record cost against an agent's budget
pub fn record_agent_cost(agent_id: &str, cost_usd: f64) {
    let mut data = load_agents();
    if let Some(agent) = data.tokens.get_mut(agent_id) {
        if let Some(ref mut budget) = agent.budget {
            budget.current_monthly_usd += cost_usd;

            // Check circuit breaker threshold (3x average rate)
            if budget.current_monthly_usd > budget.max_monthly_usd * 0.8 {
                // Warning threshold at 80%
                crate::audit::log_access(
                    "agent_budget_warning",
                    agent_id,
                    "",
                    &format!(
                        "{}: ${:.2}/${:.2} (80%)",
                        agent.name, budget.current_monthly_usd, budget.max_monthly_usd
                    ),
                );
            }
        }
        save_agents(&data);
    }
}

#[derive(Debug)]
pub enum AgentAccessResult {
    Allowed { agent_name: String, agent_id: String },
    Denied(String),
    RateLimited(String),
}
