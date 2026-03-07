# Feature 023: Cost Circuit Breaker

## Status: Done
## Phase: 3 (v2.3)
## Priority: Critical

## Problem

An AI agent stuck in a retry loop can drain hundreds of dollars in minutes. The per-agent budget cap (Feature 022) checks monthly totals, but it does not detect anomalous spending rates. An agent that normally spends $3/hour suddenly spending $50/minute should be immediately halted — not allowed to continue until it hits the monthly ceiling. Without rate-based detection, the circuit breaker fires too late.

## Solution

Track spending rate in a rolling 5-minute window. If the rate exceeds a configurable threshold (default: 3x the agent's average rate), automatically revoke the agent's token, block all further requests, fire an alert, and require manual re-enablement. This is a last-resort safety mechanism that catches runaway agents before they cause significant financial damage.

## Implementation

### Files to Create/Modify

- `crates/pqvault-agent-mcp/src/circuit_breaker.rs` — Rate monitoring, trip logic, alert firing
- `crates/pqvault-agent-mcp/src/lib.rs` — Integrate circuit breaker into request pipeline
- `crates/pqvault-proxy-mcp/src/proxy.rs` — Check circuit breaker before forwarding
- `crates/pqvault-core/src/models.rs` — CircuitBreakerConfig in VaultMetadata

### Data Model Changes

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Multiplier over average rate to trigger (default: 3.0)
    pub rate_multiplier: f64,
    /// Rolling window size in seconds (default: 300 = 5 minutes)
    pub window_seconds: u64,
    /// Minimum number of requests in window before breaker can trip
    pub min_requests_in_window: u32,
    /// Minimum dollar amount in window before breaker can trip
    pub min_amount_usd: f64,
    /// Whether circuit breaker is enabled
    pub enabled: bool,
    /// Action to take when tripped
    pub action: CircuitBreakerAction,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CircuitBreakerAction {
    /// Revoke agent token (requires manual re-enable)
    RevokeToken,
    /// Block requests but keep token active
    BlockRequests,
    /// Log warning but allow requests to continue
    WarnOnly,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            rate_multiplier: 3.0,
            window_seconds: 300,
            min_requests_in_window: 10,
            min_amount_usd: 5.0,
            enabled: true,
            action: CircuitBreakerAction::RevokeToken,
        }
    }
}

/// State of a circuit breaker for a specific agent
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CircuitBreakerState {
    pub agent_id: String,
    pub status: BreakerStatus,
    /// Recent requests in the rolling window
    pub recent_requests: Vec<CostEvent>,
    /// Historical average rate (USD per 5 minutes)
    pub average_rate: f64,
    /// When the breaker tripped (if tripped)
    pub tripped_at: Option<String>,
    /// Why the breaker tripped
    pub trip_reason: Option<String>,
    /// Total number of times this breaker has tripped
    pub trip_count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum BreakerStatus {
    /// Normal operation
    Closed,
    /// Breaker tripped — requests blocked
    Open,
    /// Manual reset initiated, monitoring closely
    HalfOpen,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CostEvent {
    pub timestamp: String,
    pub cost_usd: f64,
    pub key_name: String,
}

/// Alert generated when circuit breaker trips
#[derive(Serialize, Deserialize, Debug)]
pub struct CircuitBreakerAlert {
    pub agent_id: String,
    pub agent_name: String,
    pub current_rate_usd_per_5min: f64,
    pub average_rate_usd_per_5min: f64,
    pub multiplier: f64,
    pub tripped_at: String,
    pub action_taken: String,
    pub recent_requests: Vec<CostEvent>,
}
```

### MCP Tools

```rust
// Tool: agent_circuit_breaker_status
{
    "name": "agent_circuit_breaker_status",
    "params": {},
    "returns": {
        "breakers": [
            {
                "agent_name": "code-gen-agent",
                "status": "closed",
                "current_rate": 2.50,
                "average_rate": 3.00,
                "threshold": 9.00,
                "trip_count": 0
            }
        ]
    }
}

// Tool: agent_circuit_breaker_reset
{
    "name": "agent_circuit_breaker_reset",
    "description": "Manually reset a tripped circuit breaker",
    "params": {
        "agent_id": "agt_abc123",
        "acknowledge": true
    },
    "returns": {
        "reset": true,
        "new_status": "half_open",
        "message": "Circuit breaker reset. Monitoring closely for 5 minutes."
    }
}

// Tool: agent_circuit_breaker_configure
{
    "name": "agent_circuit_breaker_configure",
    "params": {
        "agent_id": "agt_abc123",
        "rate_multiplier": 3.0,
        "window_seconds": 300,
        "action": "RevokeToken"
    },
    "returns": { "configured": true }
}
```

### CLI Commands

```bash
# View circuit breaker status
pqvault circuit-breaker status

# Reset a tripped breaker
pqvault circuit-breaker reset agt_abc123

# Configure breaker for an agent
pqvault circuit-breaker configure agt_abc123 --multiplier 3.0 --window 5m --action revoke

# View trip history
pqvault circuit-breaker history

# Disable breaker for an agent (dangerous)
pqvault circuit-breaker disable agt_abc123 --confirm
```

## Core Implementation

```rust
// crates/pqvault-agent-mcp/src/circuit_breaker.rs

use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use anyhow::Result;

pub struct CircuitBreaker {
    states: HashMap<String, CircuitBreakerState>,
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            states: HashMap::new(),
            config,
        }
    }

    /// Record a cost event and check if breaker should trip
    pub fn record_and_check(
        &mut self,
        agent_id: &str,
        key_name: &str,
        cost_usd: f64,
    ) -> BreakerCheckResult {
        if !self.config.enabled {
            return BreakerCheckResult::Allowed;
        }

        let state = self.states
            .entry(agent_id.to_string())
            .or_insert_with(|| CircuitBreakerState {
                agent_id: agent_id.to_string(),
                status: BreakerStatus::Closed,
                recent_requests: Vec::new(),
                average_rate: 0.0,
                tripped_at: None,
                trip_reason: None,
                trip_count: 0,
            });

        // If breaker is already open, reject
        if state.status == BreakerStatus::Open {
            return BreakerCheckResult::Blocked {
                reason: "Circuit breaker is open".into(),
                tripped_at: state.tripped_at.clone().unwrap_or_default(),
            };
        }

        // Add event to rolling window
        let now = Utc::now();
        state.recent_requests.push(CostEvent {
            timestamp: now.to_rfc3339(),
            cost_usd,
            key_name: key_name.to_string(),
        });

        // Remove events outside the window
        let window_start = now - Duration::seconds(self.config.window_seconds as i64);
        state.recent_requests.retain(|e| {
            DateTime::parse_from_rfc3339(&e.timestamp)
                .map(|dt| dt.with_timezone(&Utc) > window_start)
                .unwrap_or(false)
        });

        // Calculate current rate
        let window_cost: f64 = state.recent_requests.iter().map(|e| e.cost_usd).sum();
        let window_count = state.recent_requests.len() as u32;

        // Not enough data to trip
        if window_count < self.config.min_requests_in_window {
            return BreakerCheckResult::Allowed;
        }
        if window_cost < self.config.min_amount_usd {
            return BreakerCheckResult::Allowed;
        }

        // Check rate against threshold
        let threshold = state.average_rate * self.config.rate_multiplier;

        // Update rolling average (exponential moving average)
        if state.average_rate == 0.0 {
            state.average_rate = window_cost;
        } else {
            // Blend: 90% old average, 10% new observation
            state.average_rate = state.average_rate * 0.9 + window_cost * 0.1;
        }

        if threshold > 0.0 && window_cost > threshold {
            // TRIP!
            state.status = BreakerStatus::Open;
            state.tripped_at = Some(now.to_rfc3339());
            state.trip_reason = Some(format!(
                "Spend rate ${:.2}/{}s exceeds {:.1}x average (${:.2}/{}s)",
                window_cost, self.config.window_seconds,
                self.config.rate_multiplier,
                state.average_rate, self.config.window_seconds,
            ));
            state.trip_count += 1;

            return BreakerCheckResult::Tripped {
                current_rate: window_cost,
                average_rate: state.average_rate,
                multiplier: window_cost / state.average_rate,
                alert: self.generate_alert(state),
            };
        }

        // Half-open monitoring: if we were half-open and still under threshold, close
        if state.status == BreakerStatus::HalfOpen {
            state.status = BreakerStatus::Closed;
        }

        BreakerCheckResult::Allowed
    }

    /// Reset a tripped breaker
    pub fn reset(&mut self, agent_id: &str) -> Result<()> {
        let state = self.states.get_mut(agent_id)
            .ok_or_else(|| anyhow::anyhow!("No circuit breaker state for agent {}", agent_id))?;

        state.status = BreakerStatus::HalfOpen;
        state.recent_requests.clear();
        Ok(())
    }

    fn generate_alert(&self, state: &CircuitBreakerState) -> CircuitBreakerAlert {
        CircuitBreakerAlert {
            agent_id: state.agent_id.clone(),
            agent_name: state.agent_id.clone(), // Resolved by caller
            current_rate_usd_per_5min: state.recent_requests.iter().map(|e| e.cost_usd).sum(),
            average_rate_usd_per_5min: state.average_rate,
            multiplier: state.recent_requests.iter().map(|e| e.cost_usd).sum::<f64>() / state.average_rate.max(0.001),
            tripped_at: state.tripped_at.clone().unwrap_or_default(),
            action_taken: format!("{:?}", self.config.action),
            recent_requests: state.recent_requests.clone(),
        }
    }
}

#[derive(Debug)]
pub enum BreakerCheckResult {
    Allowed,
    Blocked { reason: String, tripped_at: String },
    Tripped { current_rate: f64, average_rate: f64, multiplier: f64, alert: CircuitBreakerAlert },
}
```

## Dependencies

- No new dependencies
- Uses existing `chrono`
- Requires Feature 021 (Agent-Scoped Tokens) for token revocation
- Requires Feature 022 (Per-Agent Budget Caps) for cost tracking integration

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_rate_allowed() {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig {
            min_requests_in_window: 5,
            min_amount_usd: 1.0,
            rate_multiplier: 3.0,
            ..Default::default()
        });

        // Establish baseline
        for _ in 0..10 {
            let result = cb.record_and_check("agent1", "KEY", 0.1);
            assert!(matches!(result, BreakerCheckResult::Allowed));
        }
    }

    #[test]
    fn test_spike_trips_breaker() {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig {
            min_requests_in_window: 3,
            min_amount_usd: 1.0,
            rate_multiplier: 3.0,
            ..Default::default()
        });

        // Establish baseline ($0.10 per request)
        for _ in 0..20 {
            cb.record_and_check("agent1", "KEY", 0.10);
        }

        // Spike: $5.00 per request (50x normal)
        for _ in 0..5 {
            let result = cb.record_and_check("agent1", "KEY", 5.0);
            if matches!(result, BreakerCheckResult::Tripped { .. }) {
                return; // Test passes
            }
        }

        panic!("Breaker should have tripped on cost spike");
    }

    #[test]
    fn test_blocked_after_trip() {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig {
            min_requests_in_window: 1,
            min_amount_usd: 0.0,
            rate_multiplier: 2.0,
            ..Default::default()
        });

        // Establish baseline
        for _ in 0..5 {
            cb.record_and_check("agent1", "KEY", 0.1);
        }

        // Force trip with massive spike
        for _ in 0..10 {
            cb.record_and_check("agent1", "KEY", 100.0);
        }

        // Should be blocked now
        let result = cb.record_and_check("agent1", "KEY", 0.01);
        assert!(matches!(result, BreakerCheckResult::Blocked { .. }));
    }

    #[test]
    fn test_reset_allows_through() {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig::default());

        // Trip the breaker manually
        cb.states.insert("agent1".into(), CircuitBreakerState {
            agent_id: "agent1".into(),
            status: BreakerStatus::Open,
            recent_requests: vec![],
            average_rate: 1.0,
            tripped_at: Some(Utc::now().to_rfc3339()),
            trip_reason: Some("test".into()),
            trip_count: 1,
        });

        // Reset
        cb.reset("agent1").unwrap();
        let state = cb.states.get("agent1").unwrap();
        assert_eq!(state.status, BreakerStatus::HalfOpen);
    }

    #[test]
    fn test_below_minimum_doesnt_trip() {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig {
            min_requests_in_window: 100, // Requires 100 requests
            ..Default::default()
        });

        // Only 5 requests, even with high cost — shouldn't trip
        for _ in 0..5 {
            let result = cb.record_and_check("agent1", "KEY", 100.0);
            assert!(matches!(result, BreakerCheckResult::Allowed));
        }
    }
}
```

### Manual Verification

1. Configure circuit breaker for a test agent with 2x multiplier
2. Send normal requests (establish baseline rate)
3. Send burst of expensive requests — verify breaker trips
4. Verify all subsequent requests are blocked
5. Reset breaker — verify agent can send requests again (half-open)
6. Check alert was generated with correct details

## Example Usage

```bash
# Normal operation
$ pqvault circuit-breaker status
Agent                Status    Current Rate    Average    Threshold   Trips
code-gen-agent       CLOSED    $2.50/5min      $3.00/5min $9.00/5min  0
ci-pipeline          CLOSED    $0.10/5min      $0.15/5min $0.45/5min  0

# After a runaway agent
$ pqvault circuit-breaker status
Agent                Status    Current Rate    Average    Threshold   Trips
code-gen-agent       OPEN      $45.00/5min     $3.00/5min $9.00/5min  1
  TRIPPED at 2025-01-15 10:23:00 UTC
  Reason: Spend rate $45.00/300s exceeds 3.0x average ($3.00/300s)
  Action: Token revoked, all requests blocked

# Reset after investigation
$ pqvault circuit-breaker reset agt_abc123
Circuit breaker for 'code-gen-agent' reset to HALF-OPEN.
Monitoring closely for 5 minutes. If rate stays normal, will auto-close.
```
