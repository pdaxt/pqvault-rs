# Feature 016: Expiry Enforcement

## Status: Planned
## Phase: 2 (v2.2)
## Priority: Medium

## Problem

Keys with `expires` dates sit active indefinitely past their expiration. The `expires` field is stored but never checked or enforced. An expired Stripe key from 2023 still shows as "active" in the vault. There are no warnings before expiry and no automatic action when a key expires. Operators discover expired keys only when production breaks.

## Solution

Enforce expiry dates by automatically setting `key_status = "expired"` when the `expires` date passes. Alert operators 7 days before expiry via health checks and dashboard warnings. Expired keys are blocked from proxy access (HTTP 403). Support configurable warning periods and grace periods before hard enforcement.

## Implementation

### Files to Create/Modify

- `crates/pqvault-health-mcp/src/expiry.rs` — Expiry checking and enforcement logic
- `crates/pqvault-health-mcp/src/lib.rs` — Integrate expiry checks into health dashboard
- `crates/pqvault-core/src/models.rs` — Add `expiry_config` to VaultMetadata
- `crates/pqvault-proxy-mcp/src/proxy.rs` — Block expired keys from proxy use

### Data Model Changes

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExpiryConfig {
    /// Days before expiry to start warning (default: 7)
    pub warn_days_before: u32,
    /// Days after expiry before hard enforcement (grace period, default: 0)
    pub grace_period_days: u32,
    /// Whether to auto-disable expired keys (default: true)
    pub auto_disable: bool,
    /// Whether to attempt auto-rotation on expiry (default: false)
    pub auto_rotate_on_expiry: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExpiryCheckResult {
    pub key_name: String,
    pub status: ExpiryStatus,
    pub expires: Option<String>,
    pub days_until_expiry: Option<i32>,
    pub action_taken: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ExpiryStatus {
    NoExpiry,
    Valid,
    Warning,
    Expired,
    ExpiredGracePeriod,
    Disabled,
}
```

### MCP Tools

```rust
// Tool: vault_check_expiry
{
    "name": "vault_check_expiry",
    "params": {},
    "returns": {
        "results": [
            { "key_name": "OLD_KEY", "status": "expired", "days_until_expiry": -15 },
            { "key_name": "STRIPE_KEY", "status": "warning", "days_until_expiry": 5 }
        ],
        "summary": { "valid": 10, "warning": 2, "expired": 1, "no_expiry": 5 }
    }
}
```

### CLI Commands

```bash
# Check expiry status of all keys
pqvault expiry check

# Set expiry on a key
pqvault expiry set STRIPE_KEY --date 2025-06-01

# Remove expiry from a key
pqvault expiry clear STRIPE_KEY

# Configure global expiry settings
pqvault expiry config --warn-days 14 --grace-days 3
```

## Core Implementation

```rust
// crates/pqvault-health-mcp/src/expiry.rs

use chrono::{DateTime, NaiveDate, Utc, Duration};
use anyhow::Result;

pub struct ExpiryChecker {
    config: ExpiryConfig,
}

impl ExpiryChecker {
    pub fn new(config: ExpiryConfig) -> Self {
        Self { config }
    }

    pub fn check_key(&self, entry: &SecretEntry) -> ExpiryCheckResult {
        let expires = match &entry.expires {
            Some(exp) => exp,
            None => return ExpiryCheckResult {
                key_name: entry.name.clone(),
                status: ExpiryStatus::NoExpiry,
                expires: None,
                days_until_expiry: None,
                action_taken: None,
            },
        };

        let expires_date = match parse_date(expires) {
            Ok(d) => d,
            Err(_) => return ExpiryCheckResult {
                key_name: entry.name.clone(),
                status: ExpiryStatus::NoExpiry,
                expires: Some(expires.clone()),
                days_until_expiry: None,
                action_taken: Some("Invalid expiry date format".into()),
            },
        };

        let now = Utc::now();
        let days_until = (expires_date - now).num_days() as i32;

        let status = if days_until < -(self.config.grace_period_days as i32) {
            ExpiryStatus::Disabled
        } else if days_until < 0 {
            if self.config.grace_period_days > 0 {
                ExpiryStatus::ExpiredGracePeriod
            } else {
                ExpiryStatus::Expired
            }
        } else if days_until <= self.config.warn_days_before as i32 {
            ExpiryStatus::Warning
        } else {
            ExpiryStatus::Valid
        };

        ExpiryCheckResult {
            key_name: entry.name.clone(),
            status,
            expires: Some(expires.clone()),
            days_until_expiry: Some(days_until),
            action_taken: None,
        }
    }

    pub fn check_all(&self, entries: &[SecretEntry]) -> Vec<ExpiryCheckResult> {
        entries.iter().map(|e| self.check_key(e)).collect()
    }

    /// Enforce expiry: auto-disable expired keys, return list of actions taken
    pub fn enforce(&self, vault: &mut Vault) -> Vec<ExpiryCheckResult> {
        let mut results = Vec::new();

        for entry in &mut vault.entries {
            let mut result = self.check_key(entry);

            match result.status {
                ExpiryStatus::Expired | ExpiryStatus::Disabled if self.config.auto_disable => {
                    entry.key_status = "expired".to_string();
                    result.action_taken = Some("Auto-disabled (expired)".into());
                }
                ExpiryStatus::Warning => {
                    result.action_taken = Some(format!(
                        "Warning: expires in {} days",
                        result.days_until_expiry.unwrap_or(0)
                    ));
                }
                _ => {}
            }

            results.push(result);
        }

        results
    }
}

fn parse_date(s: &str) -> Result<DateTime<Utc>> {
    // Try RFC3339 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    // Try YYYY-MM-DD
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(nd.and_hms_opt(0, 0, 0).unwrap().and_utc());
    }
    anyhow::bail!("Cannot parse date: {}", s)
}
```

## Dependencies

- No new dependencies. Uses existing `chrono`.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn checker() -> ExpiryChecker {
        ExpiryChecker::new(ExpiryConfig {
            warn_days_before: 7,
            grace_period_days: 0,
            auto_disable: true,
            auto_rotate_on_expiry: false,
        })
    }

    #[test]
    fn test_no_expiry() {
        let entry = make_entry("KEY", None);
        let result = checker().check_key(&entry);
        assert_eq!(result.status, ExpiryStatus::NoExpiry);
    }

    #[test]
    fn test_valid_expiry() {
        let future = (Utc::now() + Duration::days(30)).to_rfc3339();
        let entry = make_entry("KEY", Some(future));
        let result = checker().check_key(&entry);
        assert_eq!(result.status, ExpiryStatus::Valid);
        assert_eq!(result.days_until_expiry, Some(30));
    }

    #[test]
    fn test_warning_expiry() {
        let soon = (Utc::now() + Duration::days(5)).to_rfc3339();
        let entry = make_entry("KEY", Some(soon));
        let result = checker().check_key(&entry);
        assert_eq!(result.status, ExpiryStatus::Warning);
    }

    #[test]
    fn test_expired() {
        let past = (Utc::now() - Duration::days(5)).to_rfc3339();
        let entry = make_entry("KEY", Some(past));
        let result = checker().check_key(&entry);
        assert_eq!(result.status, ExpiryStatus::Expired);
    }

    #[test]
    fn test_enforce_auto_disables() {
        let past = (Utc::now() - Duration::days(5)).to_rfc3339();
        let mut vault = create_test_vault();
        vault.entries.push(make_entry("KEY", Some(past)));

        let results = checker().enforce(&mut vault);
        assert_eq!(vault.entries[0].key_status, "expired");
        assert!(results[0].action_taken.as_ref().unwrap().contains("Auto-disabled"));
    }
}
```

### Manual Verification

1. Set a key to expire tomorrow: `pqvault expiry set TEST_KEY --date 2025-01-16`
2. Run `pqvault expiry check` — should show warning
3. Wait for expiry, run check again — should show expired
4. Verify proxy rejects requests for expired key

## Example Usage

```bash
$ pqvault expiry check
Expiry Status Report
  KEY                     EXPIRES         STATUS      DAYS
  STRIPE_KEY              2025-06-01      valid       138 days
  OLD_API_KEY             2025-01-20      WARNING     5 days
  LEGACY_TOKEN            2024-12-01      EXPIRED     -45 days (auto-disabled)
  DATABASE_URL            -               no expiry   -

Summary: 1 valid, 1 warning, 1 expired, 1 no expiry
```
