# Feature 056: AWS Secrets Manager Sync

## Status: Planned
## Phase: 6 (v2.6)
## Priority: Medium

## Problem

Some keys live in AWS Secrets Manager and are duplicated manually into PQVault, or vice versa. When a key is rotated in one system, the other becomes stale. Teams using AWS services need their PQVault keys available in AWS SM for Lambda functions, ECS tasks, and RDS proxy authentication. Managing two separate secret stores with no synchronization creates drift, inconsistency, and operational overhead.

## Solution

Implement bi-directional sync between PQVault and AWS Secrets Manager. Keys can be configured for one-way push (PQVault is source of truth), one-way pull (AWS SM is source of truth), or bi-directional sync with conflict resolution. The sync runs on a configurable interval, detects changes via version comparison, and logs all sync operations to the audit trail. Supports AWS Secrets Manager's automatic rotation integration.

## Implementation

### Files to Create/Modify

- `crates/pqvault-sync-mcp/src/aws.rs` — AWS Secrets Manager sync logic
- `crates/pqvault-sync-mcp/src/aws_client.rs` — AWS SDK wrapper
- `crates/pqvault-sync-mcp/src/sync_engine.rs` — Generic sync engine
- `crates/pqvault-sync-mcp/src/lib.rs` — Register AWS sync tools

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Sync configuration for a key pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMapping {
    pub id: String,
    pub pqvault_key: String,
    pub aws_secret_name: String,
    pub aws_region: String,
    pub direction: SyncDirection,
    pub interval_seconds: u64,
    pub last_synced: Option<DateTime<Utc>>,
    pub pqvault_version: Option<u64>,
    pub aws_version_id: Option<String>,
    pub status: SyncStatus,
    pub conflict_strategy: ConflictStrategy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SyncDirection {
    Push,         // PQVault → AWS (PQVault is source of truth)
    Pull,         // AWS → PQVault (AWS is source of truth)
    Bidirectional, // Two-way sync with conflict resolution
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SyncStatus {
    InSync,
    Pending,
    Conflict,
    Error,
    Disabled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConflictStrategy {
    PQVaultWins,   // PQVault version takes precedence
    AwsWins,       // AWS version takes precedence
    NewerWins,     // Most recently modified wins
    Manual,        // Flag for manual resolution
}

/// Sync result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub mapping_id: String,
    pub direction: String,
    pub action: SyncAction,
    pub timestamp: DateTime<Utc>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncAction {
    Pushed,     // PQVault → AWS
    Pulled,     // AWS → PQVault
    NoChange,   // Already in sync
    Conflict,   // Conflict detected
    Error(String),
}

/// AWS Secrets Manager client wrapper
pub struct AwsSecretsClient {
    client: aws_sdk_secretsmanager::Client,
    region: String,
}

impl AwsSecretsClient {
    pub async fn get_secret(&self, name: &str) -> Result<(String, String)> {
        let output = self.client.get_secret_value()
            .secret_id(name)
            .send()
            .await?;
        let value = output.secret_string().unwrap_or_default().to_string();
        let version = output.version_id().unwrap_or_default().to_string();
        Ok((value, version))
    }

    pub async fn put_secret(&self, name: &str, value: &str) -> Result<String> {
        let output = self.client.put_secret_value()
            .secret_id(name)
            .secret_string(value)
            .send()
            .await?;
        Ok(output.version_id().unwrap_or_default().to_string())
    }

    pub async fn create_secret(&self, name: &str, value: &str) -> Result<String> {
        let output = self.client.create_secret()
            .name(name)
            .secret_string(value)
            .send()
            .await?;
        Ok(output.version_id().unwrap_or_default().to_string())
    }
}

/// Sync engine
pub struct SyncEngine {
    vault: VaultRef,
    aws: AwsSecretsClient,
    mappings: Vec<SyncMapping>,
}

impl SyncEngine {
    pub async fn sync_mapping(&mut self, mapping: &mut SyncMapping) -> SyncResult {
        match mapping.direction {
            SyncDirection::Push => self.push(mapping).await,
            SyncDirection::Pull => self.pull(mapping).await,
            SyncDirection::Bidirectional => self.bidirectional(mapping).await,
        }
    }

    async fn push(&self, mapping: &mut SyncMapping) -> SyncResult {
        let pqvault_value = self.vault.get(&mapping.pqvault_key).await.unwrap();
        let pqvault_version = self.vault.version(&mapping.pqvault_key).await.unwrap();

        if Some(pqvault_version) == mapping.pqvault_version {
            return SyncResult::no_change(mapping);
        }

        match self.aws.put_secret(&mapping.aws_secret_name, &pqvault_value).await {
            Ok(aws_version) => {
                mapping.pqvault_version = Some(pqvault_version);
                mapping.aws_version_id = Some(aws_version);
                mapping.last_synced = Some(Utc::now());
                mapping.status = SyncStatus::InSync;
                SyncResult::pushed(mapping)
            }
            Err(e) => SyncResult::error(mapping, e.to_string()),
        }
    }
}
```

### MCP Tools

```rust
/// Configure AWS sync for a key
#[tool(name = "aws_sync_configure")]
async fn aws_sync_configure(
    &self,
    #[arg(description = "PQVault key name")] pqvault_key: String,
    #[arg(description = "AWS Secrets Manager name")] aws_name: String,
    #[arg(description = "AWS region")] region: Option<String>,
    #[arg(description = "Direction: push, pull, bidirectional")] direction: Option<String>,
    #[arg(description = "Sync interval in minutes")] interval_minutes: Option<u64>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Trigger manual sync
#[tool(name = "aws_sync_now")]
async fn aws_sync_now(
    &self,
    #[arg(description = "PQVault key to sync (all if omitted)")] key_name: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// List sync mappings
#[tool(name = "aws_sync_status")]
async fn aws_sync_status(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Resolve a sync conflict
#[tool(name = "aws_sync_resolve")]
async fn aws_sync_resolve(
    &self,
    #[arg(description = "Mapping ID")] mapping_id: String,
    #[arg(description = "Resolution: pqvault_wins, aws_wins")] resolution: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Configure push sync (PQVault → AWS)
pqvault sync aws configure \
  --key PROD_DATABASE_URL \
  --aws-name prod/database-url \
  --region us-east-1 \
  --direction push \
  --interval 5m

# Configure pull sync (AWS → PQVault)
pqvault sync aws configure \
  --key AWS_RDS_PASSWORD \
  --aws-name rds/prod-password \
  --direction pull

# Sync now
pqvault sync aws now
# Syncing 5 mappings...
# PROD_DATABASE_URL → prod/database-url: Pushed (v3 → v4)
# AWS_RDS_PASSWORD ← rds/prod-password: Pulled (v7)
# STRIPE_KEY → stripe/api-key: No change
# REDIS_URL → prod/redis-url: Pushed (v2 → v3)
# API_TOKEN ↔ shared/api-token: Conflict (manual resolution required)

# Check status
pqvault sync aws status

# Resolve conflict
pqvault sync aws resolve --mapping m-123 --resolution pqvault_wins
```

### Web UI Changes

- AWS sync configuration page
- Sync status dashboard with real-time indicators
- Conflict resolution interface
- Sync history timeline

## Dependencies

- `aws-sdk-secretsmanager = "1"` — AWS Secrets Manager SDK (new dependency)
- `aws-config = "1"` — AWS configuration and credentials (new dependency)
- `tokio = "1"` (existing) — Async runtime
- `pqvault-core` (existing) — Vault access

## Testing

### Unit Tests

```rust
#[test]
fn sync_direction_variants() {
    let push = SyncDirection::Push;
    let pull = SyncDirection::Pull;
    assert_ne!(push, pull);
}

#[test]
fn conflict_strategy_newer_wins() {
    let pqvault_ts = Utc::now() - chrono::Duration::hours(1);
    let aws_ts = Utc::now();
    let winner = resolve_conflict(ConflictStrategy::NewerWins, pqvault_ts, aws_ts);
    assert_eq!(winner, "aws");
}

#[test]
fn mapping_serialization() {
    let mapping = SyncMapping {
        id: "m-1".into(),
        pqvault_key: "KEY".into(),
        aws_secret_name: "aws/key".into(),
        aws_region: "us-east-1".into(),
        direction: SyncDirection::Push,
        ..Default::default()
    };
    let json = serde_json::to_string(&mapping).unwrap();
    let back: SyncMapping = serde_json::from_str(&json).unwrap();
    assert_eq!(back.direction, SyncDirection::Push);
}
```

### Integration Tests

```rust
#[tokio::test]
async fn push_sync_updates_aws() {
    let mut engine = test_sync_engine().await;
    engine.vault.store("KEY", "new_value").await.unwrap();

    let mut mapping = SyncMapping::new("KEY", "aws/key", SyncDirection::Push);
    let result = engine.sync_mapping(&mut mapping).await;

    assert!(matches!(result.action, SyncAction::Pushed));
    assert_eq!(mapping.status, SyncStatus::InSync);
}

#[tokio::test]
async fn no_change_skips_sync() {
    let mut engine = test_sync_engine().await;
    let mut mapping = SyncMapping::new("KEY", "aws/key", SyncDirection::Push);
    mapping.pqvault_version = Some(engine.vault.version("KEY").await.unwrap());

    let result = engine.sync_mapping(&mut mapping).await;
    assert!(matches!(result.action, SyncAction::NoChange));
}
```

### Manual Verification

1. Configure push sync for a key
2. Update the key in PQVault
3. Trigger sync, verify AWS SM is updated
4. Configure pull sync for another key
5. Update the key in AWS SM
6. Trigger sync, verify PQVault is updated
7. Create a bi-directional conflict, test resolution

## Example Usage

```bash
# Scenario: PQVault manages keys, AWS services consume them
pqvault sync aws configure --key PROD_DB_URL --aws-name prod/db-url --direction push
pqvault sync aws configure --key STRIPE_KEY --aws-name prod/stripe --direction push

# When key is rotated in PQVault:
pqvault rotate PROD_DB_URL
# → Auto-sync pushes new value to AWS SM
# → AWS Lambda/ECS automatically picks up new secret on next rotation

# Scenario: AWS manages RDS password rotation
pqvault sync aws configure --key RDS_PASSWORD --aws-name rds/password --direction pull
# → When AWS rotates the RDS password, PQVault pulls the new value
```
