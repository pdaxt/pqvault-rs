# Feature 058: 1Password Import/Export

## Status: Done
## Phase: 6 (v2.6)
## Priority: Medium

## Problem

Many developers use 1Password to store API keys and credentials in personal or team vaults. Migrating from 1Password to PQVault is entirely manual — each key must be copied individually. There is no bulk import, no export for backup, and no way to keep 1Password in sync as a secondary vault. This makes adoption of PQVault painful for teams already invested in 1Password.

## Solution

Implement import and export functionality using the 1Password CLI (`op`) integration. The `pqvault import --from 1password` command reads items from a 1Password vault (via `op item list` and `op item get`), maps them to PQVault keys with appropriate categories and tags, and stores them encrypted. Export creates 1Password-compatible JSON that can be imported via `op item create`. Supports filtering by vault, category, and tag.

## Implementation

### Files to Create/Modify

- `crates/pqvault-cli/src/import/mod.rs` — Import command framework
- `crates/pqvault-cli/src/import/onepassword.rs` — 1Password-specific import logic
- `crates/pqvault-cli/src/export/onepassword.rs` — 1Password-compatible export
- `crates/pqvault-cli/src/import/mapper.rs` — Field mapping between 1Password and PQVault

### Data Model Changes

```rust
use serde::{Deserialize, Serialize};

/// 1Password item structure (from `op item list --format=json`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpItem {
    pub id: String,
    pub title: String,
    pub category: String, // "API_CREDENTIAL", "PASSWORD", "DATABASE", etc.
    pub vault: OpVault,
    pub fields: Vec<OpField>,
    pub tags: Vec<String>,
    pub urls: Vec<OpUrl>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpVault {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpField {
    pub id: String,
    pub label: String,
    pub value: Option<String>,
    pub r#type: String, // "CONCEALED", "STRING", "URL", etc.
    pub purpose: Option<String>, // "USERNAME", "PASSWORD", "NOTES"
    pub section: Option<OpSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpSection {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpUrl {
    pub href: String,
    pub primary: bool,
}

/// Mapping result from 1Password to PQVault
#[derive(Debug, Clone)]
pub struct ImportMapping {
    pub op_item: OpItem,
    pub pqvault_key_name: String,
    pub pqvault_value: String,
    pub pqvault_category: String,
    pub pqvault_tags: Vec<String>,
    pub pqvault_description: String,
    pub skip: bool,
    pub skip_reason: Option<String>,
}

/// Import mapper
pub struct OnePasswordMapper;

impl OnePasswordMapper {
    /// Map 1Password item to PQVault key
    pub fn map_item(item: &OpItem) -> ImportMapping {
        let key_name = Self::generate_key_name(&item.title, &item.category);
        let value = Self::extract_primary_value(item);
        let category = Self::map_category(&item.category);

        ImportMapping {
            op_item: item.clone(),
            pqvault_key_name: key_name,
            pqvault_value: value.unwrap_or_default(),
            pqvault_category: category,
            pqvault_tags: item.tags.clone(),
            pqvault_description: format!("Imported from 1Password: {}", item.title),
            skip: value.is_none(),
            skip_reason: if value.is_none() { Some("No concealed field found".into()) } else { None },
        }
    }

    fn generate_key_name(title: &str, category: &str) -> String {
        let name = title
            .to_uppercase()
            .replace(' ', "_")
            .replace('-', "_")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect::<String>();

        // Deduplicate underscores
        let mut result = String::new();
        let mut last_underscore = false;
        for c in name.chars() {
            if c == '_' {
                if !last_underscore { result.push(c); }
                last_underscore = true;
            } else {
                result.push(c);
                last_underscore = false;
            }
        }
        result
    }

    fn extract_primary_value(item: &OpItem) -> Option<String> {
        // First try: password/concealed field
        item.fields.iter()
            .find(|f| f.r#type == "CONCEALED" || f.purpose.as_deref() == Some("PASSWORD"))
            .and_then(|f| f.value.clone())
            // Second try: credential field
            .or_else(|| item.fields.iter()
                .find(|f| f.label.to_lowercase().contains("key") || f.label.to_lowercase().contains("token"))
                .and_then(|f| f.value.clone()))
    }

    fn map_category(op_category: &str) -> String {
        match op_category {
            "API_CREDENTIAL" => "api-keys",
            "DATABASE" => "database",
            "PASSWORD" => "passwords",
            "SERVER" => "infrastructure",
            "SECURE_NOTE" => "notes",
            _ => "general",
        }.to_string()
    }
}
```

### CLI Commands

```bash
# Prerequisites: 1Password CLI must be installed and signed in
# brew install 1password-cli
# op signin

# Import all items from 1Password
pqvault import --from 1password
# Found 45 items in 1Password
# Mapping:
#   STRIPE_API_KEY → STRIPE_API_KEY (api-keys)
#   OpenAI API Key → OPENAI_API_KEY (api-keys)
#   Production DB → PRODUCTION_DB (database)
#   ...
# Import 45 keys? [y/N]

# Import from specific vault
pqvault import --from 1password --vault "Development"

# Import with category filter
pqvault import --from 1password --category API_CREDENTIAL

# Import with tag filter
pqvault import --from 1password --tag production

# Dry run (preview without importing)
pqvault import --from 1password --dry-run
# Shows mapping table without importing

# Import with custom key name prefix
pqvault import --from 1password --prefix "OP_"

# Export from PQVault to 1Password-compatible format
pqvault export --to 1password --output pqvault-export.json

# Export specific keys
pqvault export --to 1password --keys "STRIPE_KEY,OPENAI_KEY" --output export.json

# Then import into 1Password:
# cat export.json | op item create --format=json
```

### MCP Tools

```rust
/// Import from 1Password
#[tool(name = "import_1password")]
async fn import_1password(
    &self,
    #[arg(description = "1Password vault name (all if omitted)")] vault: Option<String>,
    #[arg(description = "Category filter")] category: Option<String>,
    #[arg(description = "Tag filter")] tag: Option<String>,
    #[arg(description = "Dry run only")] dry_run: Option<bool>,
) -> Result<CallToolResult, McpError> {
    // Implementation using `op` CLI
}

/// Export to 1Password format
#[tool(name = "export_1password")]
async fn export_1password(
    &self,
    #[arg(description = "Keys to export (comma-separated, all if omitted)")] keys: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### Web UI Changes

- Import wizard with 1Password connection setup
- Preview mapping table before import
- Import progress with success/skip/error counts
- Export dialog for 1Password-compatible JSON

## Dependencies

- `serde_json = "1"` (existing) — JSON parsing for `op` CLI output
- `tokio::process` (existing) — Running `op` CLI commands
- 1Password CLI (`op`) must be installed separately
- `clap = "4"` (existing) — CLI argument parsing

## Testing

### Unit Tests

```rust
#[test]
fn key_name_generation() {
    assert_eq!(
        OnePasswordMapper::generate_key_name("Stripe API Key", "API_CREDENTIAL"),
        "STRIPE_API_KEY"
    );
    assert_eq!(
        OnePasswordMapper::generate_key_name("my-database-url", "DATABASE"),
        "MY_DATABASE_URL"
    );
    assert_eq!(
        OnePasswordMapper::generate_key_name("Key with   spaces", "PASSWORD"),
        "KEY_WITH_SPACES"
    );
}

#[test]
fn category_mapping() {
    assert_eq!(OnePasswordMapper::map_category("API_CREDENTIAL"), "api-keys");
    assert_eq!(OnePasswordMapper::map_category("DATABASE"), "database");
    assert_eq!(OnePasswordMapper::map_category("UNKNOWN"), "general");
}

#[test]
fn extract_concealed_field() {
    let item = OpItem {
        fields: vec![
            OpField { label: "username".into(), value: Some("user".into()), r#type: "STRING".into(), ..Default::default() },
            OpField { label: "password".into(), value: Some("secret".into()), r#type: "CONCEALED".into(), ..Default::default() },
        ],
        ..Default::default()
    };
    let mapping = OnePasswordMapper::map_item(&item);
    assert_eq!(mapping.pqvault_value, "secret");
    assert!(!mapping.skip);
}

#[test]
fn skip_items_without_secrets() {
    let item = OpItem {
        fields: vec![
            OpField { label: "notes".into(), value: Some("just a note".into()), r#type: "STRING".into(), ..Default::default() },
        ],
        ..Default::default()
    };
    let mapping = OnePasswordMapper::map_item(&item);
    assert!(mapping.skip);
}
```

### Integration Tests

```rust
#[tokio::test]
async fn import_dry_run_previews() {
    let cli = test_cli().await;
    let result = cli.import_1password(None, None, None, Some(true)).await.unwrap();
    assert!(result.contains("Dry run"));
    // Vault should have no new keys
}
```

### Manual Verification

1. Install and sign in to `op` CLI
2. Run dry-run import to preview mappings
3. Run actual import, verify all keys are stored
4. Export keys and verify JSON format is valid
5. Import exported JSON into 1Password test vault
6. Verify round-trip preserves all values

## Example Usage

```bash
# Migration workflow:
# 1. Sign in to 1Password CLI
eval $(op signin)

# 2. Preview what will be imported
pqvault import --from 1password --dry-run
# 23 API credentials
# 5 database connections
# 12 passwords (will be skipped — no key name mapping)
# Total: 28 keys to import, 12 skipped

# 3. Import
pqvault import --from 1password --category API_CREDENTIAL
# Imported 23 keys successfully

# 4. Verify
pqvault list
# Shows all imported keys with categories and tags from 1Password
```
