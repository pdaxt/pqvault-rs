# Feature 005: Encrypted Usage Data

## Status: Done
## Phase: 1 (v2.1)
## Priority: High

## Problem

The file `~/.pqvault/usage.json` stores detailed usage statistics in plaintext: key names, access counts, cost estimations, recent callers, and timestamps. This is a metadata goldmine for attackers — even without vault access, they can determine which API services are in use, how frequently they are called, and which agents have access. The file also reveals organizational information about API spending patterns.

## Solution

Encrypt `usage.json` at rest using the existing `password_encrypt`/`password_decrypt` functions from `pqvault-core/src/crypto.rs`. The file is decrypted into memory on load, modified in-place, and re-encrypted on save. This is a simpler approach than per-entry encryption (used for audit logs) because usage data is read and written as a complete unit, not appended line-by-line.

## Implementation

### Files to Create/Modify

- `crates/pqvault-health-mcp/src/usage.rs` — Replace plaintext read/write with encrypted versions
- `crates/pqvault-core/src/crypto.rs` — Ensure `password_encrypt`/`password_decrypt` are public and well-documented
- `crates/pqvault-health-mcp/src/lib.rs` — Pass master password through to usage functions

### Data Model Changes

No changes to the `UsageData` or `KeyUsage` structs themselves. The data model remains identical — only the serialization layer changes.

```rust
/// Existing usage data model (unchanged)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UsageData {
    pub keys: HashMap<String, KeyUsage>,
    pub last_updated: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyUsage {
    pub access_count: u64,
    pub last_accessed: Option<String>,
    pub estimated_cost_usd: f64,
    pub recent_callers: Vec<CallerInfo>,
    pub monthly_breakdown: HashMap<String, MonthlyUsage>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CallerInfo {
    pub agent_id: String,
    pub last_call: String,
    pub call_count: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MonthlyUsage {
    pub access_count: u64,
    pub estimated_cost_usd: f64,
}
```

On-disk format changes from raw JSON to encrypted blob:

```rust
/// On-disk format for encrypted usage file
/// File contents: version byte (1) + encrypted blob
/// The encrypted blob is the output of password_encrypt(json_bytes, master_password)
const USAGE_FILE_VERSION: u8 = 1;
```

### MCP Tools

No new MCP tools. Existing tools are modified to handle encryption transparently:

```rust
// vault_usage (existing, modified internally)
// The tool signature stays the same — encryption is transparent
{
    "name": "vault_usage",
    "params": {},
    "returns": {
        "keys": {
            "STRIPE_KEY": {
                "access_count": 1523,
                "last_accessed": "2025-01-15T10:30:00Z",
                "estimated_cost_usd": 12.50,
                "recent_callers": [...]
            }
        }
    }
}

// vault_health (existing, reads from encrypted usage)
// vault_dashboard (existing, reads from encrypted usage)
```

### CLI Commands

No new CLI commands. Existing commands that display usage data continue to work:

```bash
# These commands now transparently decrypt usage data
pqvault status          # Shows usage summary
pqvault health          # Shows health dashboard with usage stats
pqvault web             # Web dashboard reads encrypted usage
```

Migration command:
```bash
# Migrate plaintext usage.json to encrypted format
pqvault migrate-usage
```

### Web UI Changes

No UI changes. The web dashboard backend decrypts usage data before serving it to the frontend.

## Core Implementation

### Encrypted Usage Manager

```rust
// crates/pqvault-health-mcp/src/usage.rs

use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use pqvault_core::crypto::{password_encrypt, password_decrypt};

pub struct UsageManager {
    path: PathBuf,
    master_password: String,
}

impl UsageManager {
    pub fn new(pqvault_dir: &Path, master_password: &str) -> Self {
        Self {
            path: pqvault_dir.join("usage.enc"),
            master_password: master_password.to_string(),
        }
    }

    /// Load usage data from encrypted file
    pub fn load(&self) -> Result<UsageData> {
        if !self.path.exists() {
            // Check for legacy plaintext file
            let legacy_path = self.path.with_file_name("usage.json");
            if legacy_path.exists() {
                return self.migrate_from_plaintext(&legacy_path);
            }
            return Ok(UsageData::default());
        }

        let encrypted_bytes = fs::read(&self.path)
            .context("Failed to read encrypted usage file")?;

        if encrypted_bytes.is_empty() {
            return Ok(UsageData::default());
        }

        // Check version byte
        if encrypted_bytes[0] != USAGE_FILE_VERSION {
            anyhow::bail!(
                "Unsupported usage file version: {} (expected {})",
                encrypted_bytes[0],
                USAGE_FILE_VERSION
            );
        }

        // Decrypt
        let decrypted = password_decrypt(
            &encrypted_bytes[1..],
            &self.master_password,
        ).context("Failed to decrypt usage data. Wrong master password?")?;

        let usage: UsageData = serde_json::from_slice(&decrypted)
            .context("Failed to parse decrypted usage data")?;

        Ok(usage)
    }

    /// Save usage data to encrypted file
    pub fn save(&self, usage: &UsageData) -> Result<()> {
        let json = serde_json::to_vec_pretty(usage)?;

        // Encrypt
        let encrypted = password_encrypt(&json, &self.master_password)
            .context("Failed to encrypt usage data")?;

        // Write with version prefix
        let mut output = vec![USAGE_FILE_VERSION];
        output.extend_from_slice(&encrypted);

        // Atomic write: write to temp file, then rename
        let tmp_path = self.path.with_extension("enc.tmp");
        fs::write(&tmp_path, &output)
            .context("Failed to write temporary usage file")?;
        fs::rename(&tmp_path, &self.path)
            .context("Failed to rename usage file")?;

        Ok(())
    }

    /// Record an access event
    pub fn record_access(
        &self,
        key_name: &str,
        caller: &str,
        estimated_cost: f64,
    ) -> Result<()> {
        let mut usage = self.load()?;

        let key_usage = usage.keys
            .entry(key_name.to_string())
            .or_insert_with(KeyUsage::default);

        key_usage.access_count += 1;
        key_usage.last_accessed = Some(chrono::Utc::now().to_rfc3339());
        key_usage.estimated_cost_usd += estimated_cost;

        // Update caller info
        if let Some(existing) = key_usage.recent_callers
            .iter_mut()
            .find(|c| c.agent_id == caller)
        {
            existing.call_count += 1;
            existing.last_call = chrono::Utc::now().to_rfc3339();
        } else {
            key_usage.recent_callers.push(CallerInfo {
                agent_id: caller.to_string(),
                last_call: chrono::Utc::now().to_rfc3339(),
                call_count: 1,
            });
            // Keep only last 10 callers
            if key_usage.recent_callers.len() > 10 {
                key_usage.recent_callers.remove(0);
            }
        }

        // Update monthly breakdown
        let month_key = chrono::Utc::now().format("%Y-%m").to_string();
        let monthly = key_usage.monthly_breakdown
            .entry(month_key)
            .or_insert_with(MonthlyUsage::default);
        monthly.access_count += 1;
        monthly.estimated_cost_usd += estimated_cost;

        usage.last_updated = chrono::Utc::now().to_rfc3339();
        self.save(&usage)?;

        Ok(())
    }

    /// Migrate from plaintext usage.json
    fn migrate_from_plaintext(&self, legacy_path: &Path) -> Result<UsageData> {
        let content = fs::read_to_string(legacy_path)
            .context("Failed to read legacy usage.json")?;

        let usage: UsageData = serde_json::from_str(&content)
            .context("Failed to parse legacy usage.json")?;

        // Save as encrypted
        self.save(&usage)?;

        // Rename old file
        let backup_path = legacy_path.with_extension("json.migrated");
        fs::rename(legacy_path, &backup_path)
            .context("Failed to rename legacy usage file")?;

        eprintln!("Migrated usage.json to encrypted format. Old file: {}", backup_path.display());

        Ok(usage)
    }
}

impl Default for UsageData {
    fn default() -> Self {
        Self {
            keys: HashMap::new(),
            last_updated: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self {
            access_count: 0,
            last_accessed: None,
            estimated_cost_usd: 0.0,
            recent_callers: Vec::new(),
            monthly_breakdown: HashMap::new(),
        }
    }
}

impl Default for MonthlyUsage {
    fn default() -> Self {
        Self {
            access_count: 0,
            estimated_cost_usd: 0.0,
        }
    }
}
```

## Dependencies

- No new crate dependencies
- Uses existing `pqvault-core::crypto::password_encrypt` and `password_decrypt`
- Uses existing `chrono` for timestamps
- Uses existing `serde_json` for serialization

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let manager = UsageManager::new(dir.path(), "test-password");

        let mut usage = UsageData::default();
        usage.keys.insert("STRIPE_KEY".into(), KeyUsage {
            access_count: 42,
            last_accessed: Some("2025-01-15T10:00:00Z".into()),
            estimated_cost_usd: 5.50,
            recent_callers: vec![],
            monthly_breakdown: HashMap::new(),
        });

        manager.save(&usage).unwrap();
        let loaded = manager.load().unwrap();

        assert_eq!(loaded.keys.len(), 1);
        assert_eq!(loaded.keys["STRIPE_KEY"].access_count, 42);
        assert_eq!(loaded.keys["STRIPE_KEY"].estimated_cost_usd, 5.50);
    }

    #[test]
    fn test_wrong_password_fails_load() {
        let dir = tempdir().unwrap();
        let manager1 = UsageManager::new(dir.path(), "password1");
        let usage = UsageData::default();
        manager1.save(&usage).unwrap();

        let manager2 = UsageManager::new(dir.path(), "wrong-password");
        let result = manager2.load();
        assert!(result.is_err());
    }

    #[test]
    fn test_record_access_increments() {
        let dir = tempdir().unwrap();
        let manager = UsageManager::new(dir.path(), "test-password");

        manager.record_access("API_KEY", "agent-1", 0.01).unwrap();
        manager.record_access("API_KEY", "agent-1", 0.02).unwrap();
        manager.record_access("API_KEY", "agent-2", 0.01).unwrap();

        let usage = manager.load().unwrap();
        assert_eq!(usage.keys["API_KEY"].access_count, 3);
        assert!((usage.keys["API_KEY"].estimated_cost_usd - 0.04).abs() < 0.001);
        assert_eq!(usage.keys["API_KEY"].recent_callers.len(), 2);
    }

    #[test]
    fn test_empty_file_returns_default() {
        let dir = tempdir().unwrap();
        let manager = UsageManager::new(dir.path(), "test-password");
        let usage = manager.load().unwrap();
        assert!(usage.keys.is_empty());
    }

    #[test]
    fn test_encrypted_file_is_not_readable_as_json() {
        let dir = tempdir().unwrap();
        let manager = UsageManager::new(dir.path(), "test-password");
        let mut usage = UsageData::default();
        usage.keys.insert("SECRET_KEY".into(), KeyUsage::default());
        manager.save(&usage).unwrap();

        // The encrypted file should not be parseable as JSON
        let bytes = fs::read(dir.path().join("usage.enc")).unwrap();
        let json_result = serde_json::from_slice::<serde_json::Value>(&bytes);
        assert!(json_result.is_err());

        // The file should not contain "SECRET_KEY" in plaintext
        let content = String::from_utf8_lossy(&bytes);
        assert!(!content.contains("SECRET_KEY"));
    }

    #[test]
    fn test_auto_migrate_from_plaintext() {
        let dir = tempdir().unwrap();
        let legacy_path = dir.path().join("usage.json");
        fs::write(&legacy_path, r#"{"keys":{"OLD_KEY":{"access_count":10,"last_accessed":null,"estimated_cost_usd":0.0,"recent_callers":[],"monthly_breakdown":{}}},"last_updated":"2025-01-01T00:00:00Z"}"#).unwrap();

        let manager = UsageManager::new(dir.path(), "test-password");
        let usage = manager.load().unwrap();

        assert_eq!(usage.keys.len(), 1);
        assert_eq!(usage.keys["OLD_KEY"].access_count, 10);

        // Legacy file should be renamed
        assert!(!legacy_path.exists());
        assert!(dir.path().join("usage.json.migrated").exists());

        // Encrypted file should exist
        assert!(dir.path().join("usage.enc").exists());
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_usage_survives_restart() {
    let dir = tempdir().unwrap();

    // First session: record some usage
    {
        let manager = UsageManager::new(dir.path(), "password");
        manager.record_access("KEY_A", "agent-1", 0.05).unwrap();
        manager.record_access("KEY_B", "agent-2", 0.10).unwrap();
    }

    // Second session: verify data persisted
    {
        let manager = UsageManager::new(dir.path(), "password");
        let usage = manager.load().unwrap();
        assert_eq!(usage.keys.len(), 2);
        assert_eq!(usage.keys["KEY_A"].access_count, 1);
        assert_eq!(usage.keys["KEY_B"].access_count, 1);
    }
}

#[tokio::test]
async fn test_concurrent_access_safety() {
    // Usage file should handle rapid sequential writes without corruption
    let dir = tempdir().unwrap();
    let manager = UsageManager::new(dir.path(), "password");

    for i in 0..50 {
        manager.record_access(&format!("KEY_{}", i % 5), "agent-1", 0.01).unwrap();
    }

    let usage = manager.load().unwrap();
    let total: u64 = usage.keys.values().map(|k| k.access_count).sum();
    assert_eq!(total, 50);
}
```

### Manual Verification

1. Run some vault operations to generate usage data
2. Check `~/.pqvault/usage.enc` — should be binary/encrypted, not readable JSON
3. Run `pqvault status` — should display decrypted usage stats correctly
4. Open web dashboard — usage data should render normally
5. Try to `cat ~/.pqvault/usage.enc` — should show binary garbage, no key names visible

## Example Usage

```bash
# Generate some usage (normal operations)
$ pqvault get STRIPE_KEY
sk_live_abc123...

$ pqvault get DATABASE_URL
postgres://...

# Check that usage file is encrypted
$ file ~/.pqvault/usage.enc
/home/user/.pqvault/usage.enc: data

$ strings ~/.pqvault/usage.enc | grep -i stripe
# (no output — key names are not visible in encrypted file)

# But usage stats are still accessible via CLI
$ pqvault status
PQVault Status
  Secrets: 15
  Usage:
    STRIPE_KEY      | 42 accesses | $5.50 est. cost | last: 2m ago
    DATABASE_URL    | 120 accesses | $0.00 est. cost | last: 30s ago

# Migrate from plaintext (if upgrading)
$ pqvault migrate-usage
Migrating usage.json to encrypted format...
  Migrated 15 key usage records
  Old file renamed to usage.json.migrated
Done.
```
