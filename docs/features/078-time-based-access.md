# Feature 078: Time-Based Access

## Status: Done
## Phase: 8 (v2.8)
## Priority: Low

## Problem

Certain secrets should only be accessible during specific time windows. A CI/CD
deployment key used only during business hours Monday-Friday should not be retrievable
at 3 AM on a Sunday — any such access is likely unauthorized. Production database
credentials used by batch jobs should only be accessible during their scheduled
run windows. There is no mechanism to enforce temporal access restrictions.

## Solution

Implement time-based access controls that restrict when keys can be retrieved. Each
key can have a time policy specifying allowed hours, days of week, and timezone.
Access outside the window is denied with an audit log entry. Emergency override
is available with additional authentication and mandatory justification.

## Implementation

### Files to Create/Modify

```
pqvault-agent-mcp/
  src/
    access/
      mod.rs           # Access control module root
      time_policy.rs   # Time-based policy definition and evaluation
      schedule.rs      # Cron-like schedule parsing
      override_mgr.rs  # Emergency override management
    tools/
      set_time_policy.rs   # MCP tool: set time-based access policy
      check_access.rs      # MCP tool: check if access is currently allowed
```

### Data Model Changes

```rust
use chrono::{DateTime, Utc, NaiveTime, Weekday, Timelike};

/// Time-based access policy for a key
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TimePolicy {
    /// Timezone for evaluating the policy (e.g., "America/New_York")
    pub timezone: String,
    /// Allowed access windows
    pub windows: Vec<AccessWindow>,
    /// What happens outside allowed windows
    pub outside_window: OutsideAction,
    /// Emergency override configuration
    pub emergency_override: Option<OverrideConfig>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccessWindow {
    /// Optional label for this window
    pub label: Option<String>,
    /// Days of week this window applies
    pub days: Vec<Weekday>,
    /// Start time (inclusive)
    pub start_time: NaiveTime,
    /// End time (exclusive)
    pub end_time: NaiveTime,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum OutsideAction {
    /// Block access entirely
    Deny,
    /// Allow but log as anomalous
    AllowWithAlert,
    /// Require additional authentication
    RequireEscalation,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OverrideConfig {
    /// Require MFA to override
    pub require_mfa: bool,
    /// Require a justification reason
    pub require_reason: bool,
    /// Maximum override duration in minutes
    pub max_duration_minutes: u32,
    /// Notify these addresses on override
    pub notify: Vec<String>,
}

pub struct TimeEvaluator;

impl TimeEvaluator {
    pub fn is_allowed(policy: &TimePolicy, now: &DateTime<Utc>) -> TimeDecision {
        let tz: chrono_tz::Tz = policy.timezone.parse()
            .unwrap_or(chrono_tz::UTC);
        let local_now = now.with_timezone(&tz);
        let current_day = local_now.weekday();
        let current_time = local_now.time();

        for window in &policy.windows {
            if window.days.contains(&current_day) {
                let in_range = if window.start_time <= window.end_time {
                    // Normal range (e.g., 09:00 - 17:00)
                    current_time >= window.start_time && current_time < window.end_time
                } else {
                    // Overnight range (e.g., 22:00 - 06:00)
                    current_time >= window.start_time || current_time < window.end_time
                };

                if in_range {
                    return TimeDecision::Allowed {
                        window_label: window.label.clone(),
                    };
                }
            }
        }

        // Outside all windows
        match &policy.outside_window {
            OutsideAction::Deny => TimeDecision::Denied {
                reason: format!(
                    "Access denied: current time {} {} is outside allowed windows",
                    current_day, current_time.format("%H:%M")
                ),
                next_window: find_next_window(policy, &local_now),
            },
            OutsideAction::AllowWithAlert => TimeDecision::AllowedWithAlert {
                message: format!("Out-of-window access at {} {}", current_day, current_time.format("%H:%M")),
            },
            OutsideAction::RequireEscalation => TimeDecision::RequiresEscalation,
        }
    }
}

pub enum TimeDecision {
    Allowed { window_label: Option<String> },
    AllowedWithAlert { message: String },
    Denied { reason: String, next_window: Option<DateTime<Utc>> },
    RequiresEscalation,
}
```

### MCP Tools

```rust
#[tool(description = "Set a time-based access policy on a vault key")]
async fn set_time_policy(
    /// Key name to apply policy to
    key: String,
    /// Timezone (e.g., America/New_York)
    timezone: String,
    /// Allowed windows as JSON: [{"days":["Mon","Fri"],"start":"09:00","end":"17:00"}]
    windows: String,
    /// Action outside windows: deny, alert, escalate
    #[arg(default = "deny")]
    outside_action: String,
) -> Result<CallToolResult> { /* ... */ }

#[tool(description = "Check if a key is currently accessible based on time policy")]
async fn check_access(
    /// Key name to check
    key: String,
) -> Result<CallToolResult> { /* ... */ }
```

### CLI Commands

```bash
# Set business hours access for a key
pqvault policy time PROD_DB_URL \
  --timezone "America/New_York" \
  --allow "Mon-Fri 09:00-17:00" \
  --outside deny

# Allow weekday business hours + Saturday morning
pqvault policy time CI_DEPLOY_KEY \
  --timezone "UTC" \
  --allow "Mon-Fri 06:00-22:00" \
  --allow "Sat 08:00-12:00" \
  --outside alert

# Check current access status
pqvault policy time-check PROD_DB_URL

# Emergency override
pqvault override PROD_DB_URL --reason "P1 incident: database migration"

# Show time policy
pqvault policy show PROD_DB_URL --time
```

### Web UI Changes

None. Time policies shown in Key Detail Page (Feature 082).

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `chrono-tz` | 0.9 | Timezone-aware time calculations |

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn business_hours_policy() -> TimePolicy {
        TimePolicy {
            timezone: "America/New_York".into(),
            windows: vec![AccessWindow {
                label: Some("business_hours".into()),
                days: vec![Weekday::Mon, Weekday::Tue, Weekday::Wed, Weekday::Thu, Weekday::Fri],
                start_time: NaiveTime::from_hms_opt(9, 0, 0).unwrap(),
                end_time: NaiveTime::from_hms_opt(17, 0, 0).unwrap(),
            }],
            outside_window: OutsideAction::Deny,
            emergency_override: None,
        }
    }

    #[test]
    fn test_allowed_during_business_hours() {
        let policy = business_hours_policy();
        // Wednesday 10:00 AM ET = 15:00 UTC (during EST)
        let now = parse_utc("2025-03-12T15:00:00Z"); // Wednesday
        let decision = TimeEvaluator::is_allowed(&policy, &now);
        assert!(matches!(decision, TimeDecision::Allowed { .. }));
    }

    #[test]
    fn test_denied_outside_hours() {
        let policy = business_hours_policy();
        // Wednesday 11:00 PM ET = 04:00 UTC next day
        let now = parse_utc("2025-03-13T04:00:00Z");
        let decision = TimeEvaluator::is_allowed(&policy, &now);
        assert!(matches!(decision, TimeDecision::Denied { .. }));
    }

    #[test]
    fn test_denied_on_weekend() {
        let policy = business_hours_policy();
        // Saturday 10:00 AM ET
        let now = parse_utc("2025-03-15T15:00:00Z");
        let decision = TimeEvaluator::is_allowed(&policy, &now);
        assert!(matches!(decision, TimeDecision::Denied { .. }));
    }

    #[test]
    fn test_overnight_window() {
        let policy = TimePolicy {
            timezone: "UTC".into(),
            windows: vec![AccessWindow {
                label: Some("batch_job".into()),
                days: vec![Weekday::Mon, Weekday::Tue, Weekday::Wed, Weekday::Thu, Weekday::Fri],
                start_time: NaiveTime::from_hms_opt(22, 0, 0).unwrap(),
                end_time: NaiveTime::from_hms_opt(6, 0, 0).unwrap(),
            }],
            outside_window: OutsideAction::Deny,
            emergency_override: None,
        };
        let now = parse_utc("2025-03-12T02:00:00Z"); // Wednesday 2 AM
        let decision = TimeEvaluator::is_allowed(&policy, &now);
        assert!(matches!(decision, TimeDecision::Allowed { .. }));
    }

    #[test]
    fn test_allow_with_alert() {
        let mut policy = business_hours_policy();
        policy.outside_window = OutsideAction::AllowWithAlert;
        let now = parse_utc("2025-03-13T04:00:00Z"); // Outside hours
        let decision = TimeEvaluator::is_allowed(&policy, &now);
        assert!(matches!(decision, TimeDecision::AllowedWithAlert { .. }));
    }
}
```

## Example Usage

```
$ pqvault policy time PROD_DB_URL \
    --timezone "America/New_York" \
    --allow "Mon-Fri 09:00-17:00" \
    --outside deny

  Time policy set for PROD_DB_URL:
    Timezone: America/New_York (ET)
    Windows:
      Mon-Fri  09:00 - 17:00  (business hours)
    Outside: DENY

$ pqvault policy time-check PROD_DB_URL

  Time Policy Check: PROD_DB_URL
  ──────────────────────────────

  Current time: Wednesday 14:30 ET
  Status: ALLOWED (business hours window)
  Next closure: Today at 17:00 ET (2h 30m)

$ pqvault get PROD_DB_URL  # At 2:00 AM Saturday
  ERROR: Access denied for PROD_DB_URL
  Reason: Current time Sat 02:00 is outside allowed windows
  Next window: Mon 09:00 ET (55h from now)
  Use `pqvault override PROD_DB_URL --reason "..."` for emergency access.
```
