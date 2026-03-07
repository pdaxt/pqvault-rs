# Feature 059: HashiCorp Vault Migration

## Status: Planned
## Phase: 6 (v2.6)
## Priority: Low

## Problem

Enterprises migrating from HashiCorp Vault (HCV) to PQVault must do so manually, secret by secret. HCV installations can contain thousands of secrets across multiple secret engines (KV v1, KV v2, database, AWS, PKI). Manual migration is error-prone, slow, and risks missing secrets in nested paths. There is no automated tool to read from HCV and write to PQVault while preserving metadata, versioning, and organizational structure.

## Solution

Implement a `pqvault migrate --from hcv` command that connects to a HashiCorp Vault instance, enumerates all secrets in configured mount paths, reads their values, and stores them in PQVault with mapped categories and metadata. The migration supports KV v1, KV v2 (with version history), and can handle nested paths. A dry-run mode previews the migration before executing. Supports incremental migration for large vaults.

## Implementation

### Files to Create/Modify

- `crates/pqvault-cli/src/migrate/mod.rs` — Migration command framework
- `crates/pqvault-cli/src/migrate/hcv.rs` — HashiCorp Vault migration logic
- `crates/pqvault-cli/src/migrate/hcv_client.rs` — HCV API client
- `crates/pqvault-cli/src/migrate/mapper.rs` — Path-to-key mapping

### Data Model Changes

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// HCV connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HcvConfig {
    pub addr: String,           // e.g., https://vault.example.com
    pub token: String,          // HCV auth token
    pub namespace: Option<String>, // Enterprise namespace
    pub mount_paths: Vec<String>, // e.g., ["secret/", "kv/", "database/"]
    pub kv_version: u8,         // 1 or 2
}

/// HCV secret entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HcvSecret {
    pub path: String,           // Full path in HCV
    pub key: String,            // Field name within the secret
    pub value: String,
    pub metadata: HcvMetadata,
    pub version: Option<u64>,   // KV v2 version
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HcvMetadata {
    pub created_time: Option<String>,
    pub deletion_time: Option<String>,
    pub destroyed: Option<bool>,
    pub version: Option<u64>,
    pub custom_metadata: HashMap<String, String>,
}

/// Migration plan entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationEntry {
    pub hcv_path: String,
    pub hcv_key: String,
    pub pqvault_name: String,
    pub pqvault_category: String,
    pub pqvault_tags: Vec<String>,
    pub action: MigrationAction,
    pub conflict: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MigrationAction {
    Create,     // New key in PQVault
    Update,     // Key exists, will overwrite
    Skip,       // Key exists, skip
    Conflict,   // Key exists with different value
}

/// HCV API client
pub struct HcvClient {
    addr: String,
    token: String,
    namespace: Option<String>,
    http: reqwest::Client,
}

impl HcvClient {
    /// List all secret paths under a mount
    pub async fn list_paths(&self, mount: &str, prefix: &str) -> Result<Vec<String>> {
        let url = format!("{}/v1/{}/metadata/{}", self.addr, mount, prefix);
        let response = self.http
            .request(reqwest::Method::from_bytes(b"LIST").unwrap(), &url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        if response.status() == 404 {
            return Ok(vec![]);
        }

        let body: HcvListResponse = response.json().await?;
        let mut all_paths = Vec::new();
        for key in &body.data.keys {
            if key.ends_with('/') {
                // Recursive directory
                let sub = self.list_paths(mount, &format!("{}{}", prefix, key)).await?;
                all_paths.extend(sub);
            } else {
                all_paths.push(format!("{}{}", prefix, key));
            }
        }
        Ok(all_paths)
    }

    /// Read a secret at a path (KV v2)
    pub async fn read_secret_v2(&self, mount: &str, path: &str) -> Result<HashMap<String, String>> {
        let url = format!("{}/v1/{}/data/{}", self.addr, mount, path);
        let response = self.http
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        let body: HcvReadV2Response = response.json().await?;
        Ok(body.data.data)
    }

    /// Read a secret at a path (KV v1)
    pub async fn read_secret_v1(&self, mount: &str, path: &str) -> Result<HashMap<String, String>> {
        let url = format!("{}/v1/{}/{}", self.addr, mount, path);
        let response = self.http
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        let body: HcvReadV1Response = response.json().await?;
        Ok(body.data)
    }
}

#[derive(Debug, Deserialize)]
struct HcvListResponse {
    data: HcvListData,
}

#[derive(Debug, Deserialize)]
struct HcvListData {
    keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HcvReadV2Response {
    data: HcvReadV2Data,
}

#[derive(Debug, Deserialize)]
struct HcvReadV2Data {
    data: HashMap<String, String>,
    metadata: HcvMetadata,
}

/// Path-to-key name mapper
pub struct PathMapper;

impl PathMapper {
    /// Convert HCV path to PQVault key name
    /// "secret/data/production/database" → "PRODUCTION_DATABASE"
    pub fn to_key_name(path: &str, field: &str) -> String {
        let clean_path = path
            .replace("secret/data/", "")
            .replace("secret/", "")
            .replace('/', "_")
            .to_uppercase();

        if field == "value" || field == "data" {
            clean_path
        } else {
            format!("{}_{}", clean_path, field.to_uppercase())
        }
    }

    /// Infer category from HCV path
    pub fn infer_category(path: &str) -> String {
        if path.contains("database") || path.contains("db") { "database".into() }
        else if path.contains("api") || path.contains("key") { "api-keys".into() }
        else if path.contains("cloud") || path.contains("aws") || path.contains("gcp") { "cloud".into() }
        else { "general".into() }
    }
}
```

### CLI Commands

```bash
# Dry-run migration (preview only)
pqvault migrate --from hcv \
  --addr https://vault.example.com \
  --token hvs.abc123... \
  --mount secret \
  --dry-run
# Migration Plan:
#   secret/production/database → PRODUCTION_DATABASE (create)
#   secret/production/stripe → PRODUCTION_STRIPE (create)
#   secret/staging/database → STAGING_DATABASE (create)
#   ...
# Total: 145 secrets, 0 conflicts

# Execute migration
pqvault migrate --from hcv \
  --addr https://vault.example.com \
  --token hvs.abc123... \
  --mount secret
# Migrating 145 secrets...
# [  1/145] PRODUCTION_DATABASE ✓
# [  2/145] PRODUCTION_STRIPE ✓
# ...
# [145/145] DEV_WEBHOOK_SECRET ✓
# Migration complete: 145 created, 0 updated, 0 skipped, 0 errors

# Migrate specific path
pqvault migrate --from hcv \
  --addr https://vault.example.com \
  --token hvs.abc123... \
  --mount secret \
  --path "production/"

# Migrate with KV v1
pqvault migrate --from hcv \
  --addr https://vault.example.com \
  --token hvs.abc123... \
  --mount secret \
  --kv-version 1

# Migrate with custom key prefix
pqvault migrate --from hcv ... --prefix "HCV_"

# Handle conflicts
pqvault migrate --from hcv ... --on-conflict skip  # or: overwrite, error

# Enterprise namespace
pqvault migrate --from hcv ... --namespace admin/team1
```

### MCP Tools

```rust
/// Migrate from HashiCorp Vault
#[tool(name = "migrate_hcv")]
async fn migrate_hcv(
    &self,
    #[arg(description = "HCV server address")] addr: String,
    #[arg(description = "HCV token")] token: String,
    #[arg(description = "Mount path (default: secret)")] mount: Option<String>,
    #[arg(description = "Dry run only")] dry_run: Option<bool>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### Web UI Changes

- Migration wizard with HCV connection form
- Progress bar during migration
- Conflict resolution interface
- Migration report with before/after comparison

## Dependencies

- `reqwest = "0.12"` (existing) — HTTP client for HCV API
- `serde_json = "1"` (existing) — JSON parsing
- `clap = "4"` (existing) — CLI arguments
- HashiCorp Vault instance (external)

## Testing

### Unit Tests

```rust
#[test]
fn path_to_key_name() {
    assert_eq!(
        PathMapper::to_key_name("secret/data/production/database", "password"),
        "PRODUCTION_DATABASE_PASSWORD"
    );
    assert_eq!(
        PathMapper::to_key_name("secret/data/api/stripe", "value"),
        "API_STRIPE"
    );
    assert_eq!(
        PathMapper::to_key_name("kv/myapp/config", "api_key"),
        "MYAPP_CONFIG_API_KEY"
    );
}

#[test]
fn category_inference() {
    assert_eq!(PathMapper::infer_category("secret/production/database"), "database");
    assert_eq!(PathMapper::infer_category("secret/api/stripe"), "api-keys");
    assert_eq!(PathMapper::infer_category("secret/aws/credentials"), "cloud");
    assert_eq!(PathMapper::infer_category("secret/misc/other"), "general");
}

#[test]
fn migration_entry_conflict_detection() {
    let existing_keys = vec!["PROD_DB".to_string()];
    let entry = MigrationEntry::new("secret/prod/db", "value", &existing_keys);
    assert!(matches!(entry.action, MigrationAction::Conflict));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn list_hcv_paths_recursive() {
    let mut server = mockito::Server::new_async().await;
    let mock_list = server.mock("LIST", "/v1/secret/metadata/")
        .with_body(r#"{"data":{"keys":["prod/","staging/"]}}"#)
        .create_async().await;

    let mock_prod = server.mock("LIST", "/v1/secret/metadata/prod/")
        .with_body(r#"{"data":{"keys":["db","redis"]}}"#)
        .create_async().await;

    let client = HcvClient::new(&server.url(), "token");
    let paths = client.list_paths("secret", "").await.unwrap();
    assert!(paths.contains(&"prod/db".to_string()));
    assert!(paths.contains(&"prod/redis".to_string()));
}

#[tokio::test]
async fn dry_run_produces_plan() {
    let cli = test_cli().await;
    let result = cli.migrate_hcv("http://localhost:8200", "token", None, Some(true)).await;
    assert!(result.is_ok());
    // Vault should have no new keys
    assert!(cli.vault.list_key_names().await.unwrap().is_empty());
}
```

### Manual Verification

1. Set up a HashiCorp Vault dev server (`vault server -dev`)
2. Populate with test secrets at various paths
3. Run dry-run migration, verify plan is correct
4. Execute migration, verify all secrets are imported
5. Compare values between HCV and PQVault
6. Test with KV v1 and KV v2 engines

## Example Usage

```bash
# Full enterprise migration:
# 1. Audit HCV secrets
pqvault migrate --from hcv --addr https://vault.corp.com \
  --token hvs.abc123 --mount secret --dry-run \
  --namespace admin/engineering
# Found 2,347 secrets across 12 paths

# 2. Migrate in batches
pqvault migrate --from hcv --addr https://vault.corp.com \
  --token hvs.abc123 --mount secret \
  --path "production/" --prefix "PROD_"
# Migrated 456 production secrets

pqvault migrate --from hcv --addr https://vault.corp.com \
  --token hvs.abc123 --mount secret \
  --path "staging/" --prefix "STG_"
# Migrated 312 staging secrets

# 3. Verify
pqvault list --category all | wc -l
# 768 keys imported
```
