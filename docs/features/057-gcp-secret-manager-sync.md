# Feature 057: GCP Secret Manager Sync

## Status: Planned
## Phase: 6 (v2.6)
## Priority: Medium

## Problem

The same secret duplication problem exists with Google Cloud Platform. Teams using Cloud Run, Cloud Functions, or GKE need secrets in GCP Secret Manager, but maintaining both PQVault and GCP SM manually leads to drift. When a PQVault key is rotated, the GCP version becomes stale. When GCP rotates a service account key, PQVault does not know about it. This is the GCP-specific variant of the problem solved for AWS in Feature 056.

## Solution

Implement bi-directional sync between PQVault and GCP Secret Manager, following the same architecture as the AWS sync (Feature 056). The sync uses GCP service account credentials for authentication, supports push/pull/bidirectional modes, and handles GCP's version-based secret management. Integrates with GCP's automatic secret rotation for Cloud SQL and other managed services.

## Implementation

### Files to Create/Modify

- `crates/pqvault-sync-mcp/src/gcp.rs` — GCP Secret Manager sync logic
- `crates/pqvault-sync-mcp/src/gcp_client.rs` — GCP API wrapper
- `crates/pqvault-sync-mcp/src/lib.rs` — Register GCP sync tools

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// GCP sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpSyncMapping {
    pub id: String,
    pub pqvault_key: String,
    pub gcp_secret_name: String,      // projects/PROJECT/secrets/SECRET
    pub gcp_project: String,
    pub direction: SyncDirection,
    pub interval_seconds: u64,
    pub last_synced: Option<DateTime<Utc>>,
    pub pqvault_version: Option<u64>,
    pub gcp_version: Option<String>,
    pub status: SyncStatus,
    pub conflict_strategy: ConflictStrategy,
}

/// GCP Secret Manager client wrapper
pub struct GcpSecretsClient {
    project: String,
    token: String,
    http_client: reqwest::Client,
}

impl GcpSecretsClient {
    /// Access a secret version
    pub async fn get_secret(&self, name: &str) -> Result<(String, String)> {
        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}/versions/latest:access",
            self.project, name
        );
        let response = self.http_client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await?;

        let body: GcpAccessResponse = response.json().await?;
        let value = String::from_utf8(
            base64::decode(&body.payload.data)?
        )?;
        Ok((value, body.name))
    }

    /// Add a new secret version
    pub async fn add_version(&self, name: &str, value: &str) -> Result<String> {
        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}:addVersion",
            self.project, name
        );
        let payload = serde_json::json!({
            "payload": {
                "data": base64::encode(value)
            }
        });
        let response = self.http_client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&payload)
            .send()
            .await?;

        let body: GcpVersionResponse = response.json().await?;
        Ok(body.name)
    }

    /// Create a new secret
    pub async fn create_secret(&self, name: &str) -> Result<()> {
        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets",
            self.project
        );
        let payload = serde_json::json!({
            "replication": { "automatic": {} }
        });
        self.http_client
            .post(&url)
            .bearer_auth(&self.token)
            .query(&[("secretId", name)])
            .json(&payload)
            .send()
            .await?;
        Ok(())
    }

    /// List all secrets
    pub async fn list_secrets(&self) -> Result<Vec<String>> {
        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets",
            self.project
        );
        let response = self.http_client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await?;

        let body: GcpListResponse = response.json().await?;
        Ok(body.secrets.into_iter().map(|s| s.name).collect())
    }
}

#[derive(Debug, Deserialize)]
struct GcpAccessResponse {
    name: String,
    payload: GcpPayload,
}

#[derive(Debug, Deserialize)]
struct GcpPayload {
    data: String, // base64 encoded
}
```

### MCP Tools

```rust
/// Configure GCP sync for a key
#[tool(name = "gcp_sync_configure")]
async fn gcp_sync_configure(
    &self,
    #[arg(description = "PQVault key name")] pqvault_key: String,
    #[arg(description = "GCP secret name")] gcp_name: String,
    #[arg(description = "GCP project ID")] project: String,
    #[arg(description = "Direction: push, pull, bidirectional")] direction: Option<String>,
    #[arg(description = "Sync interval in minutes")] interval_minutes: Option<u64>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Trigger manual sync
#[tool(name = "gcp_sync_now")]
async fn gcp_sync_now(
    &self,
    #[arg(description = "PQVault key to sync (all if omitted)")] key_name: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// List GCP sync mappings
#[tool(name = "gcp_sync_status")]
async fn gcp_sync_status(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Import all secrets from a GCP project
#[tool(name = "gcp_import")]
async fn gcp_import(
    &self,
    #[arg(description = "GCP project ID")] project: String,
    #[arg(description = "Key name prefix")] prefix: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Configure push sync
pqvault sync gcp configure \
  --key PROD_DATABASE_URL \
  --gcp-name prod-database-url \
  --project my-project-123 \
  --direction push

# Configure with service account
pqvault sync gcp auth --key-file /path/to/sa-key.json

# Sync now
pqvault sync gcp now

# Import all secrets from GCP project
pqvault sync gcp import --project my-project-123 --prefix GCP_

# Check status
pqvault sync gcp status

# List GCP secrets
pqvault sync gcp list --project my-project-123
```

### Web UI Changes

- GCP sync configuration page (parallel to AWS sync page)
- GCP project selector
- Service account key upload
- Sync status and history

## Dependencies

- `reqwest = "0.12"` (existing) — HTTP client for GCP API
- `base64 = "0.22"` — Base64 encoding for GCP secret payloads
- `serde_json = "1"` (existing) — JSON serialization
- Feature 056 (AWS Sync) — Shared sync engine architecture

## Testing

### Unit Tests

```rust
#[test]
fn gcp_secret_name_format() {
    let name = format_gcp_secret_name("my-project", "my-secret");
    assert_eq!(name, "projects/my-project/secrets/my-secret");
}

#[test]
fn base64_payload_roundtrip() {
    let value = "postgres://user:pass@host:5432/db";
    let encoded = base64::encode(value);
    let decoded = String::from_utf8(base64::decode(&encoded).unwrap()).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn gcp_mapping_serialization() {
    let mapping = GcpSyncMapping {
        pqvault_key: "DB_URL".into(),
        gcp_secret_name: "prod-db-url".into(),
        gcp_project: "my-project".into(),
        direction: SyncDirection::Push,
        ..Default::default()
    };
    let json = serde_json::to_string(&mapping).unwrap();
    assert!(json.contains("my-project"));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn push_sync_to_gcp() {
    let engine = test_gcp_sync_engine().await;
    engine.vault.store("KEY", "value").await.unwrap();

    let mut mapping = GcpSyncMapping::new("KEY", "test-key", "test-project", SyncDirection::Push);
    let result = engine.sync_mapping(&mut mapping).await;
    assert!(matches!(result.action, SyncAction::Pushed));
}

#[tokio::test]
async fn import_from_gcp() {
    let engine = test_gcp_sync_engine().await;
    let imported = engine.import_all("test-project", Some("GCP_")).await.unwrap();
    assert!(imported > 0);
}
```

### Manual Verification

1. Configure GCP service account credentials
2. Create push sync for a PQVault key
3. Verify secret appears in GCP Secret Manager console
4. Rotate key in PQVault, verify GCP SM is updated
5. Configure pull sync, update in GCP, verify PQVault updated
6. Test import of all secrets from a GCP project

## Example Usage

```bash
# Sync PQVault keys to GCP for Cloud Run services:
pqvault sync gcp configure --key PROD_DB_URL --gcp-name prod-db-url \
  --project dataxlr8-prod --direction push

pqvault sync gcp configure --key STRIPE_KEY --gcp-name stripe-key \
  --project dataxlr8-prod --direction push

# Cloud Run service references GCP SM secret:
# gcloud run services update myapp \
#   --update-secrets=DATABASE_URL=prod-db-url:latest
# PQVault rotation → GCP SM update → Cloud Run picks up new version
```
