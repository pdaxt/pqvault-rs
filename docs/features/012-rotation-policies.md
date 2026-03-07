# Feature 012: Rotation Policies

## Status: Planned
## Phase: 2 (v2.2)
## Priority: Critical

## Problem

The `rotation_days` field exists on `SecretEntry` but is never enforced. There is no mechanism to define, track, or enforce rotation cadences. Keys with a 90-day rotation policy sit untouched for years. Without enforceable policies, compliance requirements (SOC2, PCI-DSS, HIPAA) cannot be met, and security posture degrades silently.

## Solution

Define per-key and per-category rotation policies stored in vault metadata. A background checker (triggered by MCP health checks and CLI status commands) evaluates all keys against their policies and reports overdue rotations, upcoming deadlines, and compliance status. Policies support auto-rotation triggers — when a key becomes overdue, the rotation engine (Feature 011) can automatically rotate it.

## Implementation

### Files to Create/Modify

- `crates/pqvault-rotation-mcp/src/policy.rs` — Policy definition, evaluation, and enforcement
- `crates/pqvault-core/src/models.rs` — Add policy storage to VaultMetadata
- `crates/pqvault-rotation-mcp/src/lib.rs` — Register policy MCP tools
- `crates/pqvault-cli/src/main.rs` — Add policy management CLI commands

### Data Model Changes

```rust
/// A rotation policy — can target a specific key, category, or provider
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotationPolicy {
    /// Unique policy identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// What this policy targets
    pub target: PolicyTarget,
    /// Maximum days between rotations
    pub rotation_days: u32,
    /// Whether to auto-rotate when overdue
    pub auto_rotate: bool,
    /// Days before due date to start warning
    pub warn_days_before: u32,
    /// Whether to auto-disable overdue keys
    pub disable_if_overdue: bool,
    /// Grace period after overdue before disabling (days)
    pub grace_period_days: u32,
    /// When this policy was created
    pub created: String,
    /// Who created it
    pub created_by: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PolicyTarget {
    /// Applies to a specific key
    Key(String),
    /// Applies to all keys in a category
    Category(String),
    /// Applies to all keys from a provider
    Provider(String),
    /// Applies to all keys (global default)
    Global,
}

/// Result of evaluating a key against its applicable policy
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PolicyEvaluation {
    pub key_name: String,
    pub policy_id: String,
    pub policy_name: String,
    pub status: PolicyStatus,
    pub days_since_rotation: u32,
    pub days_until_due: i32,  // negative = overdue
    pub last_rotated: Option<String>,
    pub next_rotation_due: String,
    pub auto_rotate_enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum PolicyStatus {
    /// Key is within rotation window
    Compliant,
    /// Key is approaching rotation deadline
    Warning,
    /// Key is past rotation deadline
    Overdue,
    /// Key has been auto-disabled due to being overdue
    Disabled,
    /// Key has no applicable policy
    NoPolicyApplicable,
}

/// Add to VaultMetadata
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PolicyStore {
    pub policies: Vec<RotationPolicy>,
}
```

### MCP Tools

```rust
// Tool: rotation_policy_create
{
    "name": "rotation_policy_create",
    "description": "Create a rotation policy for keys, categories, or providers",
    "params": {
        "name": "Stripe 90-day rotation",
        "target_type": "provider",     // key|category|provider|global
        "target_value": "stripe",
        "rotation_days": 90,
        "auto_rotate": true,
        "warn_days_before": 14,
        "disable_if_overdue": false
    },
    "returns": {
        "policy_id": "pol_abc123",
        "affected_keys": ["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"]
    }
}

// Tool: rotation_policy_list
{
    "name": "rotation_policy_list",
    "params": {},
    "returns": {
        "policies": [
            {
                "id": "pol_abc123",
                "name": "Stripe 90-day rotation",
                "target": {"Provider": "stripe"},
                "rotation_days": 90,
                "auto_rotate": true,
                "affected_keys": 2
            }
        ]
    }
}

// Tool: rotation_policy_check
{
    "name": "rotation_policy_check",
    "description": "Evaluate all keys against their rotation policies",
    "params": {},
    "returns": {
        "evaluations": [...],
        "summary": {
            "compliant": 10,
            "warning": 3,
            "overdue": 2,
            "no_policy": 5
        }
    }
}
```

### CLI Commands

```bash
# Create a policy
pqvault policy create --name "Payment keys 90d" --target-category payment --days 90 --auto-rotate

# Create a global default policy
pqvault policy create --name "Default 180d" --target-global --days 180

# List policies
pqvault policy list

# Check compliance
pqvault policy check

# Delete a policy
pqvault policy delete pol_abc123

# Show policy details for a specific key
pqvault policy show STRIPE_SECRET_KEY
```

## Core Implementation

### Policy Engine

```rust
// crates/pqvault-rotation-mcp/src/policy.rs

use chrono::{DateTime, Utc, Duration};
use anyhow::Result;

pub struct PolicyEngine {
    policies: Vec<RotationPolicy>,
}

impl PolicyEngine {
    pub fn new(policies: Vec<RotationPolicy>) -> Self {
        Self { policies }
    }

    /// Find the most specific policy that applies to a key
    pub fn find_applicable_policy(&self, entry: &SecretEntry) -> Option<&RotationPolicy> {
        // Priority: Key > Category > Provider > Global
        // 1. Exact key match
        if let Some(p) = self.policies.iter().find(|p| {
            matches!(&p.target, PolicyTarget::Key(k) if k == &entry.name)
        }) {
            return Some(p);
        }

        // 2. Category match
        if let Some(p) = self.policies.iter().find(|p| {
            matches!(&p.target, PolicyTarget::Category(c) if c == &entry.category)
        }) {
            return Some(p);
        }

        // 3. Provider match
        if let Some(provider) = &entry.provider {
            if let Some(p) = self.policies.iter().find(|p| {
                matches!(&p.target, PolicyTarget::Provider(pr) if pr == provider)
            }) {
                return Some(p);
            }
        }

        // 4. Global default
        self.policies.iter().find(|p| matches!(&p.target, PolicyTarget::Global))
    }

    /// Evaluate a single key against its applicable policy
    pub fn evaluate_key(&self, entry: &SecretEntry) -> PolicyEvaluation {
        let policy = match self.find_applicable_policy(entry) {
            Some(p) => p,
            None => {
                return PolicyEvaluation {
                    key_name: entry.name.clone(),
                    policy_id: String::new(),
                    policy_name: String::new(),
                    status: PolicyStatus::NoPolicyApplicable,
                    days_since_rotation: 0,
                    days_until_due: 0,
                    last_rotated: None,
                    next_rotation_due: String::new(),
                    auto_rotate_enabled: false,
                };
            }
        };

        let last_rotated = entry.rotation_metadata
            .as_ref()
            .and_then(|m| m.last_rotated.as_ref())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|| {
                // If never rotated, use creation date
                DateTime::parse_from_rfc3339(&entry.created)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now())
            });

        let days_since = (Utc::now() - last_rotated).num_days() as u32;
        let days_until_due = policy.rotation_days as i32 - days_since as i32;
        let next_due = last_rotated + Duration::days(policy.rotation_days as i64);

        let status = if days_until_due < -(policy.grace_period_days as i32) {
            PolicyStatus::Disabled
        } else if days_until_due < 0 {
            PolicyStatus::Overdue
        } else if days_until_due <= policy.warn_days_before as i32 {
            PolicyStatus::Warning
        } else {
            PolicyStatus::Compliant
        };

        PolicyEvaluation {
            key_name: entry.name.clone(),
            policy_id: policy.id.clone(),
            policy_name: policy.name.clone(),
            status,
            days_since_rotation: days_since,
            days_until_due,
            last_rotated: Some(last_rotated.to_rfc3339()),
            next_rotation_due: next_due.to_rfc3339(),
            auto_rotate_enabled: policy.auto_rotate,
        }
    }

    /// Evaluate all keys in the vault
    pub fn evaluate_all(&self, entries: &[SecretEntry]) -> Vec<PolicyEvaluation> {
        entries.iter().map(|e| self.evaluate_key(e)).collect()
    }

    /// Get summary of all evaluations
    pub fn compliance_summary(&self, entries: &[SecretEntry]) -> ComplianceSummary {
        let evals = self.evaluate_all(entries);
        ComplianceSummary {
            compliant: evals.iter().filter(|e| e.status == PolicyStatus::Compliant).count(),
            warning: evals.iter().filter(|e| e.status == PolicyStatus::Warning).count(),
            overdue: evals.iter().filter(|e| e.status == PolicyStatus::Overdue).count(),
            disabled: evals.iter().filter(|e| e.status == PolicyStatus::Disabled).count(),
            no_policy: evals.iter().filter(|e| e.status == PolicyStatus::NoPolicyApplicable).count(),
            total: evals.len(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ComplianceSummary {
    pub compliant: usize,
    pub warning: usize,
    pub overdue: usize,
    pub disabled: usize,
    pub no_policy: usize,
    pub total: usize,
}
```

## Dependencies

- `uuid = { version = "1", features = ["v4"] }` — Generate unique policy IDs
- Uses existing `chrono` for date calculations
- Requires Feature 011 (Auto-Rotation Engine) for auto-rotate functionality

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, category: &str, provider: Option<&str>, created_days_ago: i64) -> SecretEntry {
        let created = (Utc::now() - Duration::days(created_days_ago)).to_rfc3339();
        SecretEntry {
            name: name.into(),
            category: category.into(),
            provider: provider.map(|s| s.into()),
            created,
            rotation_metadata: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_compliant_key() {
        let policy = RotationPolicy {
            id: "pol_1".into(),
            name: "90-day".into(),
            target: PolicyTarget::Global,
            rotation_days: 90,
            warn_days_before: 14,
            auto_rotate: false,
            disable_if_overdue: false,
            grace_period_days: 7,
            created: Utc::now().to_rfc3339(),
            created_by: "test".into(),
        };
        let engine = PolicyEngine::new(vec![policy]);
        let entry = make_entry("KEY_1", "api", None, 30); // 30 days old

        let eval = engine.evaluate_key(&entry);
        assert_eq!(eval.status, PolicyStatus::Compliant);
        assert_eq!(eval.days_since_rotation, 30);
        assert_eq!(eval.days_until_due, 60);
    }

    #[test]
    fn test_overdue_key() {
        let policy = RotationPolicy {
            id: "pol_1".into(),
            name: "90-day".into(),
            target: PolicyTarget::Global,
            rotation_days: 90,
            warn_days_before: 14,
            auto_rotate: false,
            disable_if_overdue: false,
            grace_period_days: 7,
            created: Utc::now().to_rfc3339(),
            created_by: "test".into(),
        };
        let engine = PolicyEngine::new(vec![policy]);
        let entry = make_entry("KEY_1", "api", None, 95); // 95 days old, 5 days overdue

        let eval = engine.evaluate_key(&entry);
        assert_eq!(eval.status, PolicyStatus::Overdue);
        assert_eq!(eval.days_until_due, -5);
    }

    #[test]
    fn test_warning_key() {
        let policy = RotationPolicy {
            id: "pol_1".into(),
            name: "90-day".into(),
            target: PolicyTarget::Global,
            rotation_days: 90,
            warn_days_before: 14,
            auto_rotate: false,
            disable_if_overdue: false,
            grace_period_days: 7,
            created: Utc::now().to_rfc3339(),
            created_by: "test".into(),
        };
        let engine = PolicyEngine::new(vec![policy]);
        let entry = make_entry("KEY_1", "api", None, 80); // 80 days old, 10 days until due

        let eval = engine.evaluate_key(&entry);
        assert_eq!(eval.status, PolicyStatus::Warning);
    }

    #[test]
    fn test_policy_priority_key_over_category() {
        let policies = vec![
            RotationPolicy {
                id: "pol_cat".into(),
                name: "Category policy".into(),
                target: PolicyTarget::Category("api".into()),
                rotation_days: 180,
                ..Default::default()
            },
            RotationPolicy {
                id: "pol_key".into(),
                name: "Key policy".into(),
                target: PolicyTarget::Key("SPECIAL_KEY".into()),
                rotation_days: 30,
                ..Default::default()
            },
        ];
        let engine = PolicyEngine::new(policies);
        let entry = make_entry("SPECIAL_KEY", "api", None, 10);

        let eval = engine.evaluate_key(&entry);
        assert_eq!(eval.policy_id, "pol_key");
    }

    #[test]
    fn test_compliance_summary() {
        let policy = RotationPolicy {
            id: "pol_1".into(),
            target: PolicyTarget::Global,
            rotation_days: 90,
            warn_days_before: 14,
            ..Default::default()
        };
        let engine = PolicyEngine::new(vec![policy]);

        let entries = vec![
            make_entry("KEY_1", "api", None, 30),  // Compliant
            make_entry("KEY_2", "api", None, 80),  // Warning
            make_entry("KEY_3", "api", None, 95),  // Overdue
        ];

        let summary = engine.compliance_summary(&entries);
        assert_eq!(summary.compliant, 1);
        assert_eq!(summary.warning, 1);
        assert_eq!(summary.overdue, 1);
    }
}
```

### Manual Verification

1. Create a global 90-day policy: `pqvault policy create --name "Default" --target-global --days 90`
2. Run `pqvault policy check` — see status of all keys
3. Add a key and verify it shows as "Compliant"
4. Create a 1-day policy for testing and verify it shows "Overdue" after a day

## Example Usage

```bash
# Create policies
$ pqvault policy create --name "Payment keys" --target-category payment --days 90 --auto-rotate --warn-days 14
Policy created: pol_a1b2c3
Affected keys: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET

$ pqvault policy create --name "Default rotation" --target-global --days 180
Policy created: pol_d4e5f6
Affected keys: 12 keys (all without more specific policy)

# Check compliance
$ pqvault policy check
Rotation Policy Compliance Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Key                     Policy              Status      Days Until Due
STRIPE_SECRET_KEY       Payment keys        WARNING     8 days
STRIPE_WEBHOOK_SECRET   Payment keys        COMPLIANT   45 days
GITHUB_TOKEN            Default rotation    OVERDUE     -12 days
DATABASE_URL            Default rotation    COMPLIANT   120 days
AWS_ACCESS_KEY          Default rotation    COMPLIANT   90 days

Summary: 3 compliant, 1 warning, 1 overdue | 0 auto-rotate pending
```
