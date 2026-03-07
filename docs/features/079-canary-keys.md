# Feature 079: Canary Keys

## Status: Planned
## Phase: 8 (v2.8)
## Priority: Low

## Problem

Organizations cannot detect unauthorized vault access in real-time. An attacker who
gains access to the vault could silently exfiltrate secrets without triggering any
alert until the compromised keys are used maliciously. There is no early-warning
system that detects unauthorized vault browsing or enumeration attempts.

## Solution

Implement canary keys (honeypot secrets) — fake entries that look like real high-value
secrets but serve no legitimate purpose. Any access to a canary key triggers an
immediate alert, since legitimate users and applications never need these keys. This
provides a tripwire for detecting unauthorized access, credential stuffing, or insider
threats browsing the vault.

## Implementation

### Files to Create/Modify

```
pqvault-core/
  src/
    canary/
      mod.rs           # Canary system module root
      generator.rs     # Realistic-looking fake secret generator
      detector.rs      # Access detection and alerting
      templates.rs     # Canary key templates (AWS, Stripe, etc.)

pqvault-health-mcp/
  src/
    tools/
      canary_status.rs # MCP tool: canary key status and alerts
```

### Data Model Changes

```rust
/// Canary key configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CanaryConfig {
    /// The canary key name (looks like a real key)
    pub key_name: String,
    /// Template used to generate the fake value
    pub template: CanaryTemplate,
    /// Alert configuration
    pub alert: CanaryAlert,
    /// Whether this key appears in normal listings
    pub visible_in_list: bool,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Number of times triggered
    pub trigger_count: u32,
    /// Last triggered timestamp
    pub last_triggered: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CanaryTemplate {
    /// Looks like an AWS access key
    AwsAccessKey,
    /// Looks like a Stripe secret key
    StripeSecretKey,
    /// Looks like a database URL
    DatabaseUrl,
    /// Looks like a GitHub token
    GitHubToken,
    /// Looks like a generic API key
    GenericApiKey { prefix: String, length: usize },
    /// Custom value
    Custom { value: String },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CanaryAlert {
    /// Alert severity
    pub severity: AlertSeverity,
    /// Notification channels
    pub channels: Vec<AlertChannel>,
    /// Custom alert message
    pub message: Option<String>,
    /// Whether to lock the vault on trigger
    pub auto_lock: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AlertChannel {
    AuditLog,
    Stderr,
    Webhook(String),
    Email(String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Generates realistic-looking fake secret values
pub struct CanaryGenerator;

impl CanaryGenerator {
    pub fn generate(template: &CanaryTemplate) -> String {
        match template {
            CanaryTemplate::AwsAccessKey => {
                format!("AKIA{}", random_alphanum(16).to_uppercase())
            }
            CanaryTemplate::StripeSecretKey => {
                format!("sk_live_{}", random_alphanum(24))
            }
            CanaryTemplate::DatabaseUrl => {
                format!(
                    "postgres://canary_user:{}@canary-db.internal:5432/production",
                    random_alphanum(20)
                )
            }
            CanaryTemplate::GitHubToken => {
                format!("ghp_{}", random_alphanum(36))
            }
            CanaryTemplate::GenericApiKey { prefix, length } => {
                format!("{}{}", prefix, random_alphanum(*length))
            }
            CanaryTemplate::Custom { value } => value.clone(),
        }
    }
}

/// Canary access detector
pub struct CanaryDetector {
    canaries: Vec<CanaryConfig>,
}

impl CanaryDetector {
    /// Check if a key access is a canary trigger
    pub async fn check_access(&self, key_name: &str, accessor: &AccessContext) -> Option<CanaryTriggered> {
        let canary = self.canaries.iter().find(|c| c.key_name == key_name)?;

        Some(CanaryTriggered {
            key_name: key_name.to_string(),
            accessed_by: accessor.actor.clone(),
            accessed_from: accessor.ip_address.clone(),
            accessed_at: Utc::now(),
            access_method: accessor.source.clone(),
            alert_config: canary.alert.clone(),
        })
    }

    /// Fire alerts for a triggered canary
    pub async fn fire_alert(&self, trigger: &CanaryTriggered) -> Result<()> {
        for channel in &trigger.alert_config.channels {
            match channel {
                AlertChannel::AuditLog => {
                    log_canary_trigger(trigger).await?;
                }
                AlertChannel::Stderr => {
                    eprintln!("CANARY TRIGGERED: {} accessed by {} from {}",
                        trigger.key_name, trigger.accessed_by,
                        trigger.accessed_from.as_deref().unwrap_or("unknown")
                    );
                }
                AlertChannel::Webhook(url) => {
                    send_webhook_alert(url, trigger).await?;
                }
                AlertChannel::Email(addr) => {
                    send_email_alert(addr, trigger).await?;
                }
            }
        }

        if trigger.alert_config.auto_lock {
            lock_vault().await?;
        }

        Ok(())
    }
}

pub struct CanaryTriggered {
    pub key_name: String,
    pub accessed_by: String,
    pub accessed_from: Option<String>,
    pub accessed_at: DateTime<Utc>,
    pub access_method: String,
    pub alert_config: CanaryAlert,
}
```

### MCP Tools

```rust
#[tool(description = "Get canary key status and recent triggers")]
async fn canary_status() -> Result<CallToolResult> {
    let canaries = load_canary_configs().await?;
    let mut status = Vec::new();

    for canary in &canaries {
        status.push(format!(
            "{}: {} triggers (last: {})",
            canary.key_name,
            canary.trigger_count,
            canary.last_triggered.map_or("never".to_string(), |t| t.to_rfc3339()),
        ));
    }

    Ok(CallToolResult::text(status.join("\n")))
}
```

### CLI Commands

```bash
# Create a canary key that looks like AWS credentials
pqvault canary create AWS_BACKUP_ACCESS_KEY --template aws --alert critical

# Create a canary with custom name and webhook alert
pqvault canary create ADMIN_MASTER_KEY \
  --template stripe \
  --webhook https://hooks.slack.com/xxx \
  --auto-lock

# List all canary keys
pqvault canary list

# Show canary trigger history
pqvault canary history

# Remove a canary key
pqvault canary remove AWS_BACKUP_ACCESS_KEY
```

### Web UI Changes

None. Canary management is CLI-only; alerts feed into health dashboard.

## Dependencies

No new crate dependencies. Uses existing `reqwest` for webhook notifications.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_canary_format() {
        let value = CanaryGenerator::generate(&CanaryTemplate::AwsAccessKey);
        assert!(value.starts_with("AKIA"));
        assert_eq!(value.len(), 20); // AKIA + 16 chars
    }

    #[test]
    fn test_stripe_canary_format() {
        let value = CanaryGenerator::generate(&CanaryTemplate::StripeSecretKey);
        assert!(value.starts_with("sk_live_"));
        assert_eq!(value.len(), 32); // sk_live_ + 24 chars
    }

    #[test]
    fn test_canary_detection() {
        let detector = CanaryDetector {
            canaries: vec![CanaryConfig {
                key_name: "HONEYPOT_KEY".into(),
                template: CanaryTemplate::GenericApiKey { prefix: "hp_".into(), length: 16 },
                alert: CanaryAlert {
                    severity: AlertSeverity::Critical,
                    channels: vec![AlertChannel::AuditLog],
                    message: None,
                    auto_lock: false,
                },
                visible_in_list: true,
                created_at: Utc::now(),
                trigger_count: 0,
                last_triggered: None,
            }],
        };
        let ctx = AccessContext { actor: "attacker".into(), ip_address: Some("1.2.3.4".into()), source: "cli".into() };
        let result = tokio_test::block_on(detector.check_access("HONEYPOT_KEY", &ctx));
        assert!(result.is_some());
    }

    #[test]
    fn test_non_canary_not_detected() {
        let detector = CanaryDetector { canaries: vec![] };
        let ctx = AccessContext { actor: "user".into(), ip_address: None, source: "cli".into() };
        let result = tokio_test::block_on(detector.check_access("REAL_API_KEY", &ctx));
        assert!(result.is_none());
    }

    #[test]
    fn test_github_token_format() {
        let value = CanaryGenerator::generate(&CanaryTemplate::GitHubToken);
        assert!(value.starts_with("ghp_"));
        assert_eq!(value.len(), 40); // ghp_ + 36 chars
    }

    #[test]
    fn test_database_url_format() {
        let value = CanaryGenerator::generate(&CanaryTemplate::DatabaseUrl);
        assert!(value.starts_with("postgres://canary_user:"));
        assert!(value.contains("canary-db.internal"));
    }
}
```

## Example Usage

```
$ pqvault canary create LEGACY_ADMIN_TOKEN \
    --template github \
    --alert critical \
    --webhook https://hooks.slack.com/services/xxx \
    --auto-lock

  Canary key created: LEGACY_ADMIN_TOKEN
    Template: GitHub Token (ghp_████████████████)
    Alert: CRITICAL
    Channels: audit_log, webhook
    Auto-lock: Yes (vault locks on trigger)
    Visible in list: Yes (to attract access)

$ pqvault canary list

  Canary Keys (3)
  ────────────────────────────────────────────────

  Key                     Template    Severity   Triggers  Last
  ──────────────────────  ──────────  ─────────  ────────  ──────
  AWS_BACKUP_ACCESS_KEY   aws         Critical   0         never
  LEGACY_ADMIN_TOKEN      github      Critical   0         never
  OLD_STRIPE_KEY          stripe      Warning    2         3d ago

# When an attacker accesses a canary:
$ pqvault get LEGACY_ADMIN_TOKEN

  ALERT: Canary key LEGACY_ADMIN_TOKEN accessed!
  Actor: unknown_session
  Source: cli
  Time: 2025-03-15 02:14:33 UTC

  Vault has been LOCKED. Re-authenticate to continue.
  Webhook notification sent to Slack.
```
