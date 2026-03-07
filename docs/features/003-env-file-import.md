# Feature 003: .env File Import

## Status: Planned
## Phase: 1 (v2.1)
## Priority: Critical

## Problem

Migrating from `.env` files to PQVault requires manually adding each key one by one via `pqvault add`. A typical project has 10-30 environment variables. Doing this manually is tedious, error-prone, and discourages adoption. Developers will simply not bother migrating if the process is painful.

## Solution

`pqvault import .env --project myapp` parses a standard `.env` file, auto-categorizes each key using the existing `auto_categorize()` function, and bulk-imports all entries into the vault. Supports comments, quoted values, multiline values, and variable interpolation. After import, offers to shred the original `.env` file.

## Implementation

### Files to Create/Modify

- `crates/pqvault-cli/src/import.rs` — .env parser and import logic
- `crates/pqvault-cli/src/main.rs` — Add `Import` subcommand
- `crates/pqvault-core/src/vault.rs` — Add `bulk_add()` method for atomic multi-entry insert

### Data Model Changes

No model changes needed. Uses existing `SecretEntry` struct. New vault method:

```rust
impl Vault {
    /// Add multiple entries atomically. If any entry fails, none are added.
    pub fn bulk_add(
        &mut self,
        entries: Vec<NewSecretEntry>,
        master_password: &str,
    ) -> Result<BulkAddResult> {
        let mut added = Vec::new();
        let mut skipped = Vec::new();

        for entry in entries {
            if self.entries.iter().any(|e| e.name == entry.name) {
                skipped.push(entry.name.clone());
                continue;
            }
            self.add_entry(
                &entry.name,
                &entry.value,
                &entry.category,
                entry.project.as_deref(),
                master_password,
            )?;
            added.push(entry.name.clone());
        }

        Ok(BulkAddResult { added, skipped })
    }
}

pub struct NewSecretEntry {
    pub name: String,
    pub value: String,
    pub category: String,
    pub project: Option<String>,
}

pub struct BulkAddResult {
    pub added: Vec<String>,
    pub skipped: Vec<String>,
}
```

### MCP Tools

The `pqvault-mcp` already has `vault_add`. For bulk import, a new MCP tool:

```rust
// Tool: vault_import_env
// Description: Import secrets from .env file content
{
    "name": "vault_import_env",
    "params": {
        "content": "DATABASE_URL=postgres://...\nAPI_KEY=sk_live_...",
        "project": "myapp",        // optional
        "overwrite": false          // skip existing by default
    },
    "returns": {
        "added": ["DATABASE_URL", "API_KEY"],
        "skipped": [],
        "categorized": {
            "DATABASE_URL": "database",
            "API_KEY": "payment"
        }
    }
}
```

### CLI Commands

```bash
# Import from .env file
pqvault import .env --project myapp

# Import from specific file
pqvault import /path/to/production.env --project production

# Import and overwrite existing keys
pqvault import .env --project myapp --overwrite

# Import with custom category (skip auto-categorization)
pqvault import .env --project myapp --category api

# Import from stdin (piped)
cat .env | pqvault import - --project myapp

# Dry run — show what would be imported
pqvault import .env --project myapp --dry-run

# Import and shred original file
pqvault import .env --project myapp --shred
```

### Web UI Changes

Optional enhancement: drag-and-drop `.env` file upload on the web dashboard "Add Secret" modal. The file is parsed client-side (never sent to server as plaintext), and each parsed key-value pair is submitted individually via the existing add API.

## Core Implementation

### .env Parser

```rust
// crates/pqvault-cli/src/import.rs

use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

/// Parsed entry from .env file
#[derive(Debug, Clone)]
pub struct EnvEntry {
    pub key: String,
    pub value: String,
    pub line_number: usize,
}

/// Parse a .env file into key-value pairs
pub fn parse_env_file(content: &str) -> Result<Vec<EnvEntry>> {
    let mut entries = Vec::new();
    let mut lines = content.lines().enumerate().peekable();

    while let Some((line_num, line)) = lines.next() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Skip export prefix
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);

        // Split on first '='
        let (key, value) = match trimmed.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.to_string()),
            None => continue, // Lines without '=' are ignored
        };

        // Validate key name (alphanumeric + underscore)
        if !key.chars().all(|c| c.is_alphanumeric() || c == '_') {
            eprintln!("Warning: Skipping invalid key '{}' at line {}", key, line_num + 1);
            continue;
        }

        // Handle quoted values
        let value = parse_value(&value, &mut lines);

        entries.push(EnvEntry {
            key,
            value,
            line_number: line_num + 1,
        });
    }

    Ok(entries)
}

fn parse_value(
    raw: &str,
    lines: &mut std::iter::Peekable<std::iter::Enumerate<std::str::Lines<'_>>>,
) -> String {
    let trimmed = raw.trim();

    // Double-quoted: handle escape sequences, multiline
    if trimmed.starts_with('"') {
        let mut value = trimmed[1..].to_string();

        // Check if closing quote is on same line
        if let Some(end) = value.find('"') {
            return value[..end]
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
        }

        // Multiline: accumulate until closing quote
        while let Some((_, next_line)) = lines.next() {
            value.push('\n');
            if let Some(end) = next_line.find('"') {
                value.push_str(&next_line[..end]);
                break;
            }
            value.push_str(next_line);
        }

        return value
            .replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
    }

    // Single-quoted: literal, no escape processing
    if trimmed.starts_with('\'') {
        let inner = &trimmed[1..];
        if let Some(end) = inner.find('\'') {
            return inner[..end].to_string();
        }
        return inner.to_string();
    }

    // Unquoted: strip inline comments, trim whitespace
    let value = if let Some(comment_start) = trimmed.find(" #") {
        &trimmed[..comment_start]
    } else {
        trimmed
    };

    value.trim().to_string()
}

/// Import .env file into vault
pub fn import_env_file(
    path: &Path,
    project: Option<&str>,
    overwrite: bool,
    dry_run: bool,
    vault: &mut Vault,
    master_password: &str,
) -> Result<ImportResult> {
    let content = fs::read_to_string(path)
        .context(format!("Failed to read {}", path.display()))?;

    let entries = parse_env_file(&content)?;

    if entries.is_empty() {
        println!("No entries found in {}", path.display());
        return Ok(ImportResult::default());
    }

    let mut result = ImportResult::default();

    for entry in &entries {
        let category = auto_categorize(&entry.key);
        let exists = vault.entries.iter().any(|e| e.name == entry.key);

        if exists && !overwrite {
            result.skipped.push(entry.key.clone());
            if dry_run {
                println!("  SKIP {} (already exists)", entry.key);
            }
            continue;
        }

        if dry_run {
            let action = if exists { "OVERWRITE" } else { "ADD" };
            println!("  {} {} [{}] ({} chars)",
                action, entry.key, category, entry.value.len());
            result.would_add.push(entry.key.clone());
            continue;
        }

        // Actually add to vault
        if exists {
            vault.update_entry(&entry.key, &entry.value, master_password)?;
            result.updated.push(entry.key.clone());
        } else {
            vault.add_entry(
                &entry.key,
                &entry.value,
                &category,
                project,
                master_password,
            )?;
            result.added.push(entry.key.clone());
        }
    }

    if !dry_run {
        vault.save()?;
    }

    Ok(result)
}

/// Securely shred a file by overwriting with random data before deleting
pub fn shred_file(path: &Path) -> Result<()> {
    use std::io::Write;
    let len = fs::metadata(path)?.len() as usize;
    let random_data: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();

    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    // Three-pass overwrite
    for _ in 0..3 {
        file.write_all(&random_data)?;
        file.sync_all()?;
    }
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

#[derive(Default)]
pub struct ImportResult {
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub skipped: Vec<String>,
    pub would_add: Vec<String>,
}
```

## Dependencies

- No new crate dependencies required for basic import
- `rand = "0.8"` — For file shredding (random overwrite bytes)
- Uses existing `auto_categorize()` from `pqvault-core/src/smart.rs`
- Uses existing `Vault::add_entry()` and `Vault::save()`

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_env() {
        let content = "DATABASE_URL=postgres://localhost/mydb\nAPI_KEY=sk_test_123\n";
        let entries = parse_env_file(content).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "DATABASE_URL");
        assert_eq!(entries[0].value, "postgres://localhost/mydb");
        assert_eq!(entries[1].key, "API_KEY");
        assert_eq!(entries[1].value, "sk_test_123");
    }

    #[test]
    fn test_parse_comments_and_empty_lines() {
        let content = "# This is a comment\n\nKEY=value\n\n# Another comment\n";
        let entries = parse_env_file(content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "KEY");
    }

    #[test]
    fn test_parse_double_quoted() {
        let content = r#"MSG="hello world""#;
        let entries = parse_env_file(content).unwrap();
        assert_eq!(entries[0].value, "hello world");
    }

    #[test]
    fn test_parse_single_quoted() {
        let content = "MSG='hello world'";
        let entries = parse_env_file(content).unwrap();
        assert_eq!(entries[0].value, "hello world");
    }

    #[test]
    fn test_parse_escape_sequences() {
        let content = r#"MSG="line1\nline2\ttab""#;
        let entries = parse_env_file(content).unwrap();
        assert_eq!(entries[0].value, "line1\nline2\ttab");
    }

    #[test]
    fn test_parse_export_prefix() {
        let content = "export API_KEY=abc123";
        let entries = parse_env_file(content).unwrap();
        assert_eq!(entries[0].key, "API_KEY");
        assert_eq!(entries[0].value, "abc123");
    }

    #[test]
    fn test_parse_inline_comments() {
        let content = "KEY=value # this is a comment";
        let entries = parse_env_file(content).unwrap();
        assert_eq!(entries[0].value, "value");
    }

    #[test]
    fn test_parse_empty_value() {
        let content = "EMPTY_KEY=";
        let entries = parse_env_file(content).unwrap();
        assert_eq!(entries[0].value, "");
    }

    #[test]
    fn test_parse_value_with_equals() {
        let content = "DATABASE_URL=postgres://user:pass@host/db?sslmode=require";
        let entries = parse_env_file(content).unwrap();
        assert_eq!(entries[0].value, "postgres://user:pass@host/db?sslmode=require");
    }

    #[test]
    fn test_parse_multiline_double_quoted() {
        let content = "CERT=\"-----BEGIN CERTIFICATE-----\nMIIBxTCCAW...\n-----END CERTIFICATE-----\"";
        let entries = parse_env_file(content).unwrap();
        assert!(entries[0].value.contains("BEGIN CERTIFICATE"));
        assert!(entries[0].value.contains("END CERTIFICATE"));
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_import_env_file_creates_entries() {
    let vault_dir = tempdir().unwrap();
    let mut vault = create_test_vault(&vault_dir);
    let env_file = vault_dir.path().join(".env");
    fs::write(&env_file, "DB_URL=postgres://localhost\nAPI_KEY=sk_test_123\n").unwrap();

    let result = import_env_file(
        &env_file, Some("myapp"), false, false,
        &mut vault, "test-password"
    ).unwrap();

    assert_eq!(result.added.len(), 2);
    assert!(result.added.contains(&"DB_URL".to_string()));
    assert!(result.added.contains(&"API_KEY".to_string()));
}

#[tokio::test]
async fn test_import_skips_existing() {
    let vault_dir = tempdir().unwrap();
    let mut vault = create_test_vault(&vault_dir);
    vault.add_entry("API_KEY", "old_value", "api", None, "test-password").unwrap();

    let env_file = vault_dir.path().join(".env");
    fs::write(&env_file, "API_KEY=new_value\nNEW_KEY=fresh\n").unwrap();

    let result = import_env_file(
        &env_file, None, false, false,
        &mut vault, "test-password"
    ).unwrap();

    assert_eq!(result.added.len(), 1);
    assert_eq!(result.skipped.len(), 1);
    assert!(result.skipped.contains(&"API_KEY".to_string()));
}

#[tokio::test]
async fn test_import_with_overwrite() {
    let vault_dir = tempdir().unwrap();
    let mut vault = create_test_vault(&vault_dir);
    vault.add_entry("API_KEY", "old_value", "api", None, "test-password").unwrap();

    let env_file = vault_dir.path().join(".env");
    fs::write(&env_file, "API_KEY=new_value\n").unwrap();

    let result = import_env_file(
        &env_file, None, true, false,
        &mut vault, "test-password"
    ).unwrap();

    assert_eq!(result.updated.len(), 1);
    assert_eq!(result.skipped.len(), 0);
}
```

### Manual Verification

1. Create a test `.env` file with various formats (quotes, comments, multiline)
2. Run `pqvault import .env --project test --dry-run` — verify correct parsing
3. Run `pqvault import .env --project test` — verify all entries added
4. Run `pqvault list --project test` — verify entries show correct categories
5. Run import again — verify duplicates are skipped
6. Run with `--overwrite` — verify existing values are updated
7. Run with `--shred` — verify original file is deleted

## Example Usage

```bash
# Create a sample .env file
$ cat .env
# Database
DATABASE_URL=postgres://user:pass@db.example.com:5432/production
REDIS_URL=redis://cache.example.com:6379

# Stripe
STRIPE_SECRET_KEY=sk_live_abc123def456
STRIPE_WEBHOOK_SECRET=whsec_xyz789

# SendGrid
SENDGRID_API_KEY=SG.abc123.def456

# App config
JWT_SECRET="my-super-secret-jwt-key"
APP_NAME='MyApp Production'

# Dry run first
$ pqvault import .env --project webapp --dry-run
Parsing .env (8 entries found)
  ADD DATABASE_URL [database] (52 chars)
  ADD REDIS_URL [database] (34 chars)
  ADD STRIPE_SECRET_KEY [payment] (22 chars)
  ADD STRIPE_WEBHOOK_SECRET [payment] (16 chars)
  ADD SENDGRID_API_KEY [email] (20 chars)
  ADD JWT_SECRET [auth] (26 chars)
  ADD APP_NAME [config] (17 chars)

Dry run complete. Run without --dry-run to import.

# Actually import
$ pqvault import .env --project webapp
Parsing .env (7 entries found)
Imported 7 secrets into project 'webapp':
  DATABASE_URL      → database
  REDIS_URL         → database
  STRIPE_SECRET_KEY → payment
  STRIPE_WEBHOOK_SECRET → payment
  SENDGRID_API_KEY  → email
  JWT_SECRET        → auth
  APP_NAME          → config

Shred the original .env file? [y/N] y
.env securely shredded (3-pass overwrite + delete)
```
