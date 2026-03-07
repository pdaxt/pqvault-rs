# Feature 022: Per-Agent Budget Caps

## Status: Planned
## Phase: 3 (v2.3)
## Priority: Critical

## Problem

A single AI agent can burn through an entire API budget with no spending limits. An agent calling OpenAI's API 10,000 times in an hour with GPT-4 can easily rack up $500+. There are no per-agent, per-key, or per-time-period spending caps. Operators only discover the damage when they receive the provider's invoice. By then, the budget is already gone.

## Solution

Define per-agent-per-key monthly budget caps enforced at the `vault_proxy` level. Before forwarding any proxied request, the system checks the agent's accumulated spend for that key in the current billing period. If the budget is exceeded, the request is rejected with a clear error message. Budgets reset on a configurable day of the month. Supports warning thresholds (e.g., alert at 80% of budget).

## Implementation

### Files to Create/Modify

- `crates/pqvault-agent-mcp/src/budgets.rs` — Budget definition, tracking, enforcement
- `crates/pqvault-proxy-mcp/src/proxy.rs` — Integrate budget check before proxying
- `crates/pqvault-core/src/models.rs` — AgentBudget struct in VaultMetadata
- `crates/pqvault-agent-mcp/src/lib.rs` — Budget management MCP tools
- `crates/pqvault-cli/src/main.rs` — Budget CLI commands

### Data Model Changes

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentBudget {
    /// Budget identifier
    pub id: String,
    /// Agent token ID this budget applies to
    pub agent_id: String,
    /// Key name this budget applies to (or "*" for all keys)
    pub key_name: String,
    /// Maximum monthly spend in USD
    pub max_monthly_usd: f64,
    /// Current month's accumulated spend
    pub current_month_usd: f64,
    /// Day of month when budget resets (1-28)
    pub reset_day: u8,
    /// Warning threshold (0.0 to 1.0, e.g., 0.8 = warn at 80%)
    pub warn_threshold: f64,
    /// Whether to hard-block when budget exceeded
    pub hard_limit: bool,
    /// Current billing period start
    pub period_start: String,
    /// Whether warning has been sent for this period
    pub warning_sent: bool,
    /// Historical spending by period
    pub history: Vec<BudgetPeriod>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BudgetPeriod {
    pub period_start: String,
    pub period_end: String,
    pub total_spent_usd: f64,
    pub request_count: u64,
}

/// Budget check result
#[derive(Debug)]
pub enum BudgetCheckResult {
    /// Within budget, proceed
    Allowed { remaining_usd: f64 },
    /// At warning threshold
    Warning { spent_usd: f64, max_usd: f64, percent: f64 },
    /// Over budget, request blocked
    Blocked { spent_usd: f64, max_usd: f64 },
    /// No budget defined for this agent/key
    NoBudget,
}

/// Cost estimation for common providers
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CostEstimator {
    pub provider: String,
    pub cost_per_request_usd: f64,
    pub cost_model: CostModel,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CostModel {
    /// Fixed cost per request
    PerRequest(f64),
    /// Cost based on tokens (for LLM APIs)
    PerToken { input_cost: f64, output_cost: f64 },
    /// Cost based on data volume
    PerMB(f64),
}
```

### MCP Tools

```rust
// Tool: agent_set_budget
{
    "name": "agent_set_budget",
    "description": "Set monthly spending limit for an agent on a specific key",
    "params": {
        "agent_id": "agt_abc123",
        "key_name": "OPENAI_API_KEY",
        "max_monthly_usd": 100.00,
        "warn_threshold": 0.8,
        "hard_limit": true,
        "reset_day": 1
    },
    "returns": {
        "budget_id": "bgt_def456",
        "agent_name": "code-gen-agent",
        "key_name": "OPENAI_API_KEY",
        "max_monthly_usd": 100.00,
        "current_spend": 0.00
    }
}

// Tool: agent_budget_status
{
    "name": "agent_budget_status",
    "params": {
        "agent_id": "agt_abc123"    // optional, all agents if omitted
    },
    "returns": {
        "budgets": [
            {
                "agent_name": "code-gen-agent",
                "key_name": "OPENAI_API_KEY",
                "max_monthly_usd": 100.00,
                "current_spend": 67.50,
                "percent_used": 67.5,
                "days_remaining": 16,
                "projected_monthly": 135.00,
                "status": "warning"
            }
        ]
    }
}

// Tool: agent_record_cost
{
    "name": "agent_record_cost",
    "description": "Record API usage cost for budget tracking",
    "params": {
        "agent_id": "agt_abc123",
        "key_name": "OPENAI_API_KEY",
        "cost_usd": 0.05,
        "request_metadata": { "model": "gpt-4", "tokens": 1500 }
    },
    "returns": { "recorded": true, "current_spend": 67.55 }
}
```

### CLI Commands

```bash
# Set a budget
pqvault budget set --agent agt_abc123 --key OPENAI_API_KEY --max 100 --warn 80%

# View budget status
pqvault budget status

# View specific agent's budgets
pqvault budget status --agent agt_abc123

# View budget history
pqvault budget history --agent agt_abc123 --months 3

# Remove a budget
pqvault budget remove bgt_def456

# Set global default budget for all agents
pqvault budget set-default --max 50 --warn 80%
```

## Core Implementation

```rust
// crates/pqvault-agent-mcp/src/budgets.rs

use chrono::{Utc, Datelike, Duration, NaiveDate};
use anyhow::{bail, Result};

pub struct BudgetManager;

impl BudgetManager {
    /// Check if an agent's request is within budget
    pub fn check_budget(
        vault: &Vault,
        agent_id: &str,
        key_name: &str,
        estimated_cost: f64,
    ) -> BudgetCheckResult {
        let budget = match vault.metadata.agent_budgets.iter()
            .find(|b| b.agent_id == agent_id && (b.key_name == key_name || b.key_name == "*"))
        {
            Some(b) => b,
            None => return BudgetCheckResult::NoBudget,
        };

        // Check if we need to reset the budget period
        let should_reset = Self::should_reset_period(budget);
        let current_spend = if should_reset { 0.0 } else { budget.current_month_usd };
        let projected_spend = current_spend + estimated_cost;

        if budget.hard_limit && projected_spend > budget.max_monthly_usd {
            return BudgetCheckResult::Blocked {
                spent_usd: current_spend,
                max_usd: budget.max_monthly_usd,
            };
        }

        let percent = current_spend / budget.max_monthly_usd;
        if percent >= budget.warn_threshold {
            return BudgetCheckResult::Warning {
                spent_usd: current_spend,
                max_usd: budget.max_monthly_usd,
                percent: percent * 100.0,
            };
        }

        BudgetCheckResult::Allowed {
            remaining_usd: budget.max_monthly_usd - current_spend,
        }
    }

    /// Record a cost against an agent's budget
    pub fn record_cost(
        vault: &mut Vault,
        agent_id: &str,
        key_name: &str,
        cost_usd: f64,
    ) -> Result<f64> {
        let budget = vault.metadata.agent_budgets.iter_mut()
            .find(|b| b.agent_id == agent_id && (b.key_name == key_name || b.key_name == "*"))
            .ok_or_else(|| anyhow::anyhow!("No budget found for agent {} / key {}", agent_id, key_name))?;

        // Reset period if needed
        if Self::should_reset_period(budget) {
            // Archive current period
            budget.history.push(BudgetPeriod {
                period_start: budget.period_start.clone(),
                period_end: Utc::now().to_rfc3339(),
                total_spent_usd: budget.current_month_usd,
                request_count: 0, // TODO: track request count
            });

            budget.current_month_usd = 0.0;
            budget.period_start = Utc::now().to_rfc3339();
            budget.warning_sent = false;

            // Keep only last 12 periods
            if budget.history.len() > 12 {
                budget.history.drain(0..budget.history.len() - 12);
            }
        }

        budget.current_month_usd += cost_usd;
        let new_total = budget.current_month_usd;

        vault.save()?;
        Ok(new_total)
    }

    /// Set a budget for an agent/key combination
    pub fn set_budget(
        vault: &mut Vault,
        agent_id: &str,
        key_name: &str,
        max_monthly_usd: f64,
        warn_threshold: f64,
        hard_limit: bool,
        reset_day: u8,
    ) -> Result<String> {
        // Validate
        if max_monthly_usd <= 0.0 {
            bail!("Budget must be positive");
        }
        if warn_threshold < 0.0 || warn_threshold > 1.0 {
            bail!("Warn threshold must be between 0.0 and 1.0");
        }
        if reset_day < 1 || reset_day > 28 {
            bail!("Reset day must be between 1 and 28");
        }

        // Remove existing budget for this combination
        vault.metadata.agent_budgets.retain(|b| {
            !(b.agent_id == agent_id && b.key_name == key_name)
        });

        let budget_id = format!("bgt_{}", &uuid::Uuid::new_v4().to_string()[..8]);

        vault.metadata.agent_budgets.push(AgentBudget {
            id: budget_id.clone(),
            agent_id: agent_id.to_string(),
            key_name: key_name.to_string(),
            max_monthly_usd,
            current_month_usd: 0.0,
            reset_day,
            warn_threshold,
            hard_limit,
            period_start: Utc::now().to_rfc3339(),
            warning_sent: false,
            history: Vec::new(),
        });

        vault.save()?;
        Ok(budget_id)
    }

    fn should_reset_period(budget: &AgentBudget) -> bool {
        if let Ok(start) = chrono::DateTime::parse_from_rfc3339(&budget.period_start) {
            let start = start.with_timezone(&Utc);
            let now = Utc::now();

            // Check if we've passed the reset day since the period started
            if now.month() != start.month() || now.year() != start.year() {
                return now.day() >= budget.reset_day as u32;
            }
        }
        false
    }

    /// Project end-of-month spend based on current rate
    pub fn project_monthly_spend(budget: &AgentBudget) -> f64 {
        if let Ok(start) = chrono::DateTime::parse_from_rfc3339(&budget.period_start) {
            let days_elapsed = (Utc::now() - start.with_timezone(&Utc)).num_days().max(1) as f64;
            let daily_rate = budget.current_month_usd / days_elapsed;
            daily_rate * 30.0
        } else {
            budget.current_month_usd
        }
    }
}
```

### Proxy Integration

```rust
// In crates/pqvault-proxy-mcp/src/proxy.rs

async fn proxy_with_budget_check(
    vault: &mut Vault,
    agent_id: &str,
    key_name: &str,
    request: &ProxyRequest,
) -> Result<ProxyResponse> {
    let estimated_cost = estimate_cost(key_name, request);

    match BudgetManager::check_budget(vault, agent_id, key_name, estimated_cost) {
        BudgetCheckResult::Blocked { spent_usd, max_usd } => {
            bail!(
                "Budget exceeded for agent on key '{}': ${:.2} / ${:.2} monthly limit",
                key_name, spent_usd, max_usd
            );
        }
        BudgetCheckResult::Warning { percent, .. } => {
            eprintln!("[budget] WARNING: Agent at {:.0}% of budget for {}", percent, key_name);
            // Continue but log warning
        }
        _ => {}
    }

    // Forward request
    let response = forward_request(request, key_value).await?;

    // Record actual cost
    let actual_cost = extract_cost_from_response(&response, key_name);
    BudgetManager::record_cost(vault, agent_id, key_name, actual_cost)?;

    Ok(response)
}
```

## Dependencies

- `uuid = { version = "1", features = ["v4"] }` — Budget ID generation
- Uses existing `chrono` for date/period calculations
- Requires Feature 021 (Agent-Scoped Tokens) for agent identification

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_within_budget_allowed() {
        let mut vault = create_test_vault();
        BudgetManager::set_budget(&mut vault, "agent1", "KEY", 100.0, 0.8, true, 1).unwrap();
        BudgetManager::record_cost(&mut vault, "agent1", "KEY", 50.0).unwrap();

        match BudgetManager::check_budget(&vault, "agent1", "KEY", 1.0) {
            BudgetCheckResult::Allowed { remaining_usd } => {
                assert!((remaining_usd - 50.0).abs() < 0.01);
            }
            other => panic!("Expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn test_over_budget_blocked() {
        let mut vault = create_test_vault();
        BudgetManager::set_budget(&mut vault, "agent1", "KEY", 100.0, 0.8, true, 1).unwrap();
        BudgetManager::record_cost(&mut vault, "agent1", "KEY", 100.0).unwrap();

        match BudgetManager::check_budget(&vault, "agent1", "KEY", 1.0) {
            BudgetCheckResult::Blocked { .. } => {}
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_warning_threshold() {
        let mut vault = create_test_vault();
        BudgetManager::set_budget(&mut vault, "agent1", "KEY", 100.0, 0.8, true, 1).unwrap();
        BudgetManager::record_cost(&mut vault, "agent1", "KEY", 85.0).unwrap();

        match BudgetManager::check_budget(&vault, "agent1", "KEY", 1.0) {
            BudgetCheckResult::Warning { percent, .. } => {
                assert!(percent > 80.0);
            }
            other => panic!("Expected Warning, got {:?}", other),
        }
    }

    #[test]
    fn test_no_budget_passes() {
        let vault = create_test_vault();
        match BudgetManager::check_budget(&vault, "agent1", "KEY", 1000.0) {
            BudgetCheckResult::NoBudget => {}
            other => panic!("Expected NoBudget, got {:?}", other),
        }
    }

    #[test]
    fn test_wildcard_budget() {
        let mut vault = create_test_vault();
        BudgetManager::set_budget(&mut vault, "agent1", "*", 200.0, 0.8, true, 1).unwrap();

        match BudgetManager::check_budget(&vault, "agent1", "ANY_KEY", 1.0) {
            BudgetCheckResult::Allowed { .. } => {}
            other => panic!("Expected Allowed, got {:?}", other),
        }
    }
}
```

### Manual Verification

1. Create an agent token and set a $10 budget
2. Make proxied requests until approaching $10
3. Verify warning at 80% ($8)
4. Verify hard block at 100% ($10)
5. Wait for budget reset day and verify counter resets

## Example Usage

```bash
# Set budget for code-gen agent on OpenAI
$ pqvault budget set --agent agt_abc123 --key OPENAI_API_KEY --max 100 --warn 80%
Budget created: bgt_def456
  Agent: code-gen-agent
  Key: OPENAI_API_KEY
  Monthly limit: $100.00
  Warning at: $80.00 (80%)
  Hard limit: enabled
  Resets: 1st of each month

# Check budget status
$ pqvault budget status
Agent Budget Status (January 2025)
  Agent             Key              Spent      Limit     Used   Status
  code-gen-agent    OPENAI_API_KEY   $67.50     $100.00   67%    OK
  code-gen-agent    ANTHROPIC_KEY    $12.30     $50.00    25%    OK
  ci-pipeline       STRIPE_KEY       $0.45      $10.00    5%     OK
  admin-agent       *                $125.00    $500.00   25%    OK

  Projected month-end: $245.00 / $660.00 total budget

# Budget exceeded
$ pqvault budget status
  code-gen-agent    OPENAI_API_KEY   $102.30    $100.00   102%   BLOCKED
  WARNING: 1 budget exceeded. Agent requests are being blocked.
```
