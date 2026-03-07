# Feature 100: Self-Destructing Secrets

## Status: Planned
## Phase: 10 (v3.0)
## Priority: Low

## Problem

Some secrets are inherently temporary: one-time API tokens, temporary access grants,
demo credentials, or emergency break-glass keys. These secrets should automatically
expire after a defined condition (time elapsed, number of accesses, or specific event).
Currently users must remember to manually delete temporary secrets, and forgotten
temporary credentials become a security liability. There is no mechanism for secrets
to self-destruct after serving their purpose.

## Solution

Implement self-destructing secrets that automatically delete themselves after a
configurable trigger: N accesses, a time duration, or a specific datetime. When
triggered, the key's value is securely zeroed, the key is removed from the vault,
and an audit log entry is recorded. A warning is displayed when accessing a key
near its destruction threshold.

## Implementation

### Files to Create/Modify

```
pqvault-core/
  src/
    ephemeral/
      mod.rs           # Ephemeral secrets module root
      policy.rs        # Self-destruct policy definitions
      tracker.rs       # Access counting and time tracking
      destructor.rs    # Secure destruction execution
      scheduler.rs     # Background scheduler for time-based destruction
```

### Data Model Changes

```rust
/// Self-destruct policy for a secret
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SelfDestructPolicy {
    /// Unique policy ID
    pub policy_id: String,
    /// When to self-destruct
    pub trigger: DestructTrigger,
    /// What happens on destruction
    pub action: DestructAction,
    /// Whether to warn before destruction
    pub warn_threshold: Option<WarnThreshold>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Whether the policy is currently active
    pub active: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DestructTrigger {
    /// Delete after N accesses
    AccessCount {
        max_accesses: u32,
        current_accesses: u32,
    },
    /// Delete after a duration from creation
    Duration {
        ttl: chrono::Duration,
        expires_at: DateTime<Utc>,
    },
    /// Delete at a specific datetime
    DateTime {
        destruct_at: DateTime<Utc>,
    },
    /// Delete after N accesses OR a time limit (whichever comes first)
    AccessCountOrDuration {
        max_accesses: u32,
        current_accesses: u32,
        ttl: chrono::Duration,
        expires_at: DateTime<Utc>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DestructAction {
    /// Delete the key entirely
    Delete,
    /// Replace the value with a tombstone message
    Tombstone { message: String },
    /// Disable the key (keep metadata, remove value)
    Disable,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WarnThreshold {
    /// Warn when N% of accesses consumed
    pub access_percentage: Option<f64>,
    /// Warn when N minutes remain
    pub time_remaining_minutes: Option<u32>,
}

/// Track accesses against self-destruct policies
pub struct EphemeralTracker {
    policies: HashMap<String, SelfDestructPolicy>,
}

impl EphemeralTracker {
    /// Record an access and check if destruction should trigger
    pub async fn record_access(&mut self, key: &str) -> AccessResult {
        let policy = match self.policies.get_mut(key) {
            Some(p) if p.active => p,
            _ => return AccessResult::Allowed,
        };

        match &mut policy.trigger {
            DestructTrigger::AccessCount { max_accesses, current_accesses } => {
                *current_accesses += 1;

                if *current_accesses >= *max_accesses {
                    return AccessResult::FinalAccess {
                        message: format!("This is the final access ({}/{}). Key will be destroyed.", current_accesses, max_accesses),
                    };
                }

                // Check warning threshold
                if let Some(warn) = &policy.warn_threshold {
                    if let Some(pct) = warn.access_percentage {
                        let used = *current_accesses as f64 / *max_accesses as f64 * 100.0;
                        if used >= pct {
                            return AccessResult::AllowedWithWarning {
                                message: format!("{}/{} accesses used ({:.0}%)", current_accesses, max_accesses, used),
                            };
                        }
                    }
                }

                AccessResult::Allowed
            }
            DestructTrigger::Duration { expires_at, .. } |
            DestructTrigger::DateTime { destruct_at: expires_at } => {
                if Utc::now() >= *expires_at {
                    return AccessResult::Expired {
                        message: format!("Key expired at {}", expires_at),
                    };
                }

                let remaining = *expires_at - Utc::now();
                if let Some(warn) = &policy.warn_threshold {
                    if let Some(mins) = warn.time_remaining_minutes {
                        if remaining < chrono::Duration::minutes(mins as i64) {
                            return AccessResult::AllowedWithWarning {
                                message: format!("Key expires in {} minutes", remaining.num_minutes()),
                            };
                        }
                    }
                }

                AccessResult::Allowed
            }
            DestructTrigger::AccessCountOrDuration { max_accesses, current_accesses, expires_at, .. } => {
                *current_accesses += 1;

                if *current_accesses >= *max_accesses {
                    return AccessResult::FinalAccess {
                        message: format!("Access limit reached ({}/{})", current_accesses, max_accesses),
                    };
                }
                if Utc::now() >= *expires_at {
                    return AccessResult::Expired {
                        message: format!("Key expired at {}", expires_at),
                    };
                }

                AccessResult::Allowed
            }
        }
    }

    /// Execute destruction for a key
    pub async fn destruct(&mut self, key: &str, vault: &mut Vault) -> Result<()> {
        let policy = self.policies.get(key)
            .ok_or_else(|| anyhow!("No self-destruct policy for {}", key))?;

        match &policy.action {
            DestructAction::Delete => {
                vault.delete(key).await?;
            }
            DestructAction::Tombstone { message } => {
                vault.set(key, &format!("DESTRUCTED: {}", message)).await?;
                vault.set_metadata(key, "status", "destructed").await?;
            }
            DestructAction::Disable => {
                vault.disable(key).await?;
            }
        }

        // Log the destruction
        vault.audit_log(AuditEvent {
            event_type: AuditEventType::KeyDeleted,
            key_name: Some(key.to_string()),
            actor: "self-destruct".into(),
            source: "ephemeral".into(),
            details: format!("Self-destructed: {:?}", policy.trigger),
            ip_address: None,
        }).await?;

        Ok(())
    }
}

pub enum AccessResult {
    Allowed,
    AllowedWithWarning { message: String },
    FinalAccess { message: String },
    Expired { message: String },
}
```

### MCP Tools

No new MCP tools. Ephemeral secrets are managed via CLI.

### CLI Commands

```bash
# Create a key that self-destructs after 5 accesses
pqvault set TEMP_TOKEN "abc123" --self-destruct accesses:5

# Create a key that expires in 24 hours
pqvault set DEMO_KEY "demo_val" --self-destruct ttl:24h

# Create a key that expires at a specific time
pqvault set BREAK_GLASS "emergency_pw" --self-destruct at:2025-03-16T00:00:00Z

# Create with both limits (whichever first)
pqvault set ONE_TIME_KEY "otk_val" --self-destruct accesses:1,ttl:1h

# Set warning threshold
pqvault set TEMP_API "api_val" --self-destruct accesses:10 --warn-at 80%

# Show self-destruct status
pqvault show TEMP_TOKEN --destruct-status

# Cancel self-destruct (convert to permanent)
pqvault destruct cancel TEMP_TOKEN

# List all ephemeral keys
pqvault list --ephemeral
```

### Web UI Changes

Ephemeral keys show a countdown/progress indicator in the dashboard.

## Dependencies

No new dependencies. Uses existing `chrono` for time calculations.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_count_trigger() {
        let mut tracker = EphemeralTracker::new();
        tracker.set_policy("KEY", SelfDestructPolicy {
            trigger: DestructTrigger::AccessCount {
                max_accesses: 3,
                current_accesses: 0,
            },
            action: DestructAction::Delete,
            warn_threshold: None,
            ..default_policy()
        });

        assert!(matches!(tracker.record_access_sync("KEY"), AccessResult::Allowed));
        assert!(matches!(tracker.record_access_sync("KEY"), AccessResult::Allowed));
        assert!(matches!(tracker.record_access_sync("KEY"), AccessResult::FinalAccess { .. }));
    }

    #[test]
    fn test_time_trigger_expired() {
        let mut tracker = EphemeralTracker::new();
        tracker.set_policy("KEY", SelfDestructPolicy {
            trigger: DestructTrigger::DateTime {
                destruct_at: Utc::now() - chrono::Duration::hours(1), // Already expired
            },
            action: DestructAction::Delete,
            warn_threshold: None,
            ..default_policy()
        });

        assert!(matches!(tracker.record_access_sync("KEY"), AccessResult::Expired { .. }));
    }

    #[test]
    fn test_time_trigger_not_expired() {
        let mut tracker = EphemeralTracker::new();
        tracker.set_policy("KEY", SelfDestructPolicy {
            trigger: DestructTrigger::DateTime {
                destruct_at: Utc::now() + chrono::Duration::hours(24),
            },
            action: DestructAction::Delete,
            warn_threshold: None,
            ..default_policy()
        });

        assert!(matches!(tracker.record_access_sync("KEY"), AccessResult::Allowed));
    }

    #[test]
    fn test_warning_threshold() {
        let mut tracker = EphemeralTracker::new();
        tracker.set_policy("KEY", SelfDestructPolicy {
            trigger: DestructTrigger::AccessCount {
                max_accesses: 10,
                current_accesses: 7, // Already 70% used
            },
            action: DestructAction::Delete,
            warn_threshold: Some(WarnThreshold {
                access_percentage: Some(80.0),
                time_remaining_minutes: None,
            }),
            ..default_policy()
        });

        // 8th access = 80%, should warn
        assert!(matches!(tracker.record_access_sync("KEY"), AccessResult::AllowedWithWarning { .. }));
    }

    #[test]
    fn test_no_policy_allows_access() {
        let mut tracker = EphemeralTracker::new();
        assert!(matches!(tracker.record_access_sync("NO_POLICY_KEY"), AccessResult::Allowed));
    }

    #[test]
    fn test_tombstone_action() {
        let policy = SelfDestructPolicy {
            action: DestructAction::Tombstone {
                message: "Expired demo credential".into(),
            },
            ..default_policy()
        };
        assert!(matches!(policy.action, DestructAction::Tombstone { .. }));
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_self_destructing_key_lifecycle() {
    let mut vault = empty_test_vault().await;
    vault.set("TEMP", "secret_value").await.unwrap();
    vault.set_destruct_policy("TEMP", SelfDestructPolicy {
        trigger: DestructTrigger::AccessCount {
            max_accesses: 2,
            current_accesses: 0,
        },
        action: DestructAction::Delete,
        ..default_policy()
    }).await.unwrap();

    // Access 1: allowed
    let val = vault.get("TEMP").await.unwrap();
    assert_eq!(val.value, "secret_value");

    // Access 2: final access, triggers destruction
    let val = vault.get("TEMP").await.unwrap();
    assert_eq!(val.value, "secret_value");

    // Access 3: key should be gone
    assert!(vault.get("TEMP").await.is_err());
}

#[tokio::test]
async fn test_ttl_based_destruction() {
    let mut vault = empty_test_vault().await;
    vault.set("TEMP", "value").await.unwrap();
    vault.set_destruct_policy("TEMP", SelfDestructPolicy {
        trigger: DestructTrigger::Duration {
            ttl: chrono::Duration::seconds(0), // Immediately expire
            expires_at: Utc::now() - chrono::Duration::seconds(1),
        },
        action: DestructAction::Delete,
        ..default_policy()
    }).await.unwrap();

    // Should be expired
    assert!(vault.get("TEMP").await.is_err());
}
```

## Example Usage

```
$ pqvault set DEMO_API_KEY "demo_sk_abc123" --self-destruct accesses:5,ttl:24h

  Created: DEMO_API_KEY
  Self-destruct policy:
    Trigger: 5 accesses OR 24 hours (whichever first)
    Expires: 2025-03-16 14:30 UTC
    Action: Delete (secure wipe)

$ pqvault get DEMO_API_KEY
  demo_sk_abc123
  Warning: Ephemeral key — 4 accesses remaining, expires in 23h 58m

$ pqvault get DEMO_API_KEY
  demo_sk_abc123
  Warning: Ephemeral key — 3 accesses remaining, expires in 23h 50m

$ pqvault list --ephemeral

  Ephemeral Keys
  ─────────────────────────────────────────────

  Key              Trigger            Remaining        Expires
  ───────────────  ─────────────────  ───────────────  ──────────────
  DEMO_API_KEY     5 accesses / 24h   3 accesses, 23h  2025-03-16 14:30
  BREAK_GLASS      datetime           -                2025-03-20 00:00
  ONE_TIME_TOKEN   1 access / 1h      1 access, 45m    2025-03-15 15:15

# After all accesses used:
$ pqvault get DEMO_API_KEY
  ERROR: Key DEMO_API_KEY has self-destructed (access limit reached: 5/5)
  The key and its value have been securely wiped.
```
