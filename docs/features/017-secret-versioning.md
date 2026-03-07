# Feature 017: Secret Versioning

## Status: Planned
## Phase: 2 (v2.2)
## Priority: Medium

## Problem

PQVault only stores the current value of each secret. There is no history of what value a key held at any given point in time. When debugging production issues ("what was the database password last Tuesday?"), when investigating security incidents ("when did this key change?"), or when auditing for compliance, there is no version trail to inspect. Rotations overwrite the previous value permanently.

## Solution

Maintain a full version history for every secret. Each time a value changes (add, update, rotate, rollback), a new version entry is appended with the value, timestamp, who changed it, and why. Versions are stored encrypted alongside the current value. Supports querying versions by date range and restoring a specific historical version.

## Implementation

### Files to Create/Modify

- `crates/pqvault-core/src/models.rs` — Add `versions: Vec<VersionEntry>` to SecretEntry
- `crates/pqvault-core/src/vault.rs` — Auto-append version on every value change
- `crates/pqvault-mcp/src/lib.rs` — Add version query MCP tools
- `crates/pqvault-cli/src/main.rs` — Add `history` and `restore` CLI commands

### Data Model Changes

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionEntry {
    /// Version number (1-indexed, monotonically increasing)
    pub version: u32,
    /// The encrypted value at this version
    pub encrypted_value: String,
    /// Who made the change
    pub changed_by: String,
    /// When the change was made
    pub changed_at: String,
    /// Why the change was made
    pub reason: ChangeReason,
    /// Optional description
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ChangeReason {
    Created,
    ManualUpdate,
    Rotation,
    Rollback,
    Import,
    BulkUpdate,
}

/// Add to SecretEntry
pub struct SecretEntry {
    // ... existing fields ...
    /// Full version history (newest last)
    pub versions: Vec<VersionEntry>,
}

/// Configuration for version retention
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionConfig {
    /// Maximum versions to keep per key (0 = unlimited, default: 50)
    pub max_versions: usize,
    /// Maximum age of versions to keep in days (0 = unlimited, default: 365)
    pub max_age_days: u32,
}
```

### MCP Tools

```rust
// Tool: vault_history
{
    "name": "vault_history",
    "params": {
        "key_name": "STRIPE_SECRET_KEY",
        "limit": 10
    },
    "returns": {
        "key_name": "STRIPE_SECRET_KEY",
        "current_version": 5,
        "versions": [
            { "version": 5, "changed_by": "auto-rotate", "changed_at": "2025-01-15T10:00:00Z", "reason": "Rotation" },
            { "version": 4, "changed_by": "cli", "changed_at": "2024-10-01T08:00:00Z", "reason": "ManualUpdate" }
        ]
    }
}

// Tool: vault_restore_version
{
    "name": "vault_restore_version",
    "params": {
        "key_name": "STRIPE_SECRET_KEY",
        "version": 3
    },
    "returns": {
        "restored_version": 3,
        "new_version": 6,
        "changed_at": "2024-07-01T12:00:00Z"
    }
}
```

### CLI Commands

```bash
# View version history
pqvault history STRIPE_SECRET_KEY

# View specific version
pqvault history STRIPE_SECRET_KEY --version 3

# Restore to a specific version
pqvault restore STRIPE_SECRET_KEY --version 3

# Diff between versions
pqvault history STRIPE_SECRET_KEY --diff 3..5

# Prune old versions
pqvault history --prune --older-than 365d
```

## Core Implementation

```rust
// Modified vault.rs methods to auto-version

impl Vault {
    pub fn update_entry(
        &mut self,
        key_name: &str,
        new_value: &str,
        master_password: &str,
        changed_by: &str,
        reason: ChangeReason,
    ) -> Result<()> {
        let entry = self.entries.iter_mut()
            .find(|e| e.name == key_name)
            .ok_or_else(|| anyhow::anyhow!("Key not found: {}", key_name))?;

        // Save current value as a version
        let next_version = entry.versions.last()
            .map(|v| v.version + 1)
            .unwrap_or(1);

        entry.versions.push(VersionEntry {
            version: next_version,
            encrypted_value: entry.encrypted_value.clone(),
            changed_by: changed_by.to_string(),
            changed_at: chrono::Utc::now().to_rfc3339(),
            reason,
            description: None,
        });

        // Update to new value
        entry.encrypted_value = self.encrypt_value(new_value, master_password)?;
        entry.updated = Some(chrono::Utc::now().to_rfc3339());

        // Prune old versions if needed
        self.prune_versions(&key_name.to_string());

        self.save()?;
        Ok(())
    }

    fn prune_versions(&mut self, key_name: &str) {
        let config = self.metadata.version_config.clone().unwrap_or_default();
        if let Some(entry) = self.entries.iter_mut().find(|e| &e.name == key_name) {
            // Prune by count
            if config.max_versions > 0 && entry.versions.len() > config.max_versions {
                let excess = entry.versions.len() - config.max_versions;
                entry.versions.drain(0..excess);
            }

            // Prune by age
            if config.max_age_days > 0 {
                let cutoff = (chrono::Utc::now() - chrono::Duration::days(config.max_age_days as i64)).to_rfc3339();
                entry.versions.retain(|v| v.changed_at >= cutoff);
            }
        }
    }

    pub fn get_version(
        &self,
        key_name: &str,
        version: u32,
        master_password: &str,
    ) -> Result<String> {
        let entry = self.entries.iter()
            .find(|e| e.name == key_name)
            .ok_or_else(|| anyhow::anyhow!("Key not found: {}", key_name))?;

        let ver = entry.versions.iter()
            .find(|v| v.version == version)
            .ok_or_else(|| anyhow::anyhow!("Version {} not found for {}", version, key_name))?;

        self.decrypt_value(&ver.encrypted_value, master_password)
    }

    pub fn restore_version(
        &mut self,
        key_name: &str,
        version: u32,
        master_password: &str,
    ) -> Result<()> {
        let old_value = self.get_version(key_name, version, master_password)?;
        self.update_entry(key_name, &old_value, master_password, "cli/restore", ChangeReason::Rollback)
    }
}
```

## Dependencies

- No new dependencies

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_created_on_update() {
        let mut vault = create_test_vault();
        vault.add_entry("KEY", "value1", "api", None, "pass").unwrap();
        vault.update_entry("KEY", "value2", "pass", "test", ChangeReason::ManualUpdate).unwrap();

        let entry = vault.get_entry("KEY").unwrap();
        assert_eq!(entry.versions.len(), 1);
        assert_eq!(entry.versions[0].version, 1);
    }

    #[test]
    fn test_version_chain() {
        let mut vault = create_test_vault();
        vault.add_entry("KEY", "v1", "api", None, "pass").unwrap();

        for i in 2..=5 {
            vault.update_entry("KEY", &format!("v{}", i), "pass", "test", ChangeReason::ManualUpdate).unwrap();
        }

        let entry = vault.get_entry("KEY").unwrap();
        assert_eq!(entry.versions.len(), 4);
        assert_eq!(entry.versions[3].version, 4);
    }

    #[test]
    fn test_restore_version() {
        let mut vault = create_test_vault();
        vault.add_entry("KEY", "original", "api", None, "pass").unwrap();
        vault.update_entry("KEY", "modified", "pass", "test", ChangeReason::ManualUpdate).unwrap();
        vault.restore_version("KEY", 1, "pass").unwrap();

        let current = vault.decrypt_value(&vault.get_entry("KEY").unwrap().encrypted_value, "pass").unwrap();
        assert_eq!(current, "original");
    }

    #[test]
    fn test_prune_by_count() {
        let mut vault = create_test_vault();
        vault.metadata.version_config = Some(VersionConfig { max_versions: 3, max_age_days: 0 });
        vault.add_entry("KEY", "v0", "api", None, "pass").unwrap();

        for i in 1..=10 {
            vault.update_entry("KEY", &format!("v{}", i), "pass", "test", ChangeReason::ManualUpdate).unwrap();
        }

        let entry = vault.get_entry("KEY").unwrap();
        assert!(entry.versions.len() <= 3);
    }
}
```

### Manual Verification

1. Add a key, update it 3 times
2. Run `pqvault history KEY` — should show version history
3. Restore version 1 — verify old value is active
4. Verify new version entry was created for the restore operation

## Example Usage

```bash
$ pqvault history STRIPE_SECRET_KEY
Version history for STRIPE_SECRET_KEY (5 versions):

  v5  2025-01-15 10:00  auto-rotate  Rotation      sk_l...abc (current)
  v4  2024-10-01 08:00  cli          ManualUpdate  sk_l...xyz
  v3  2024-07-01 12:00  cli          ManualUpdate  sk_l...def
  v2  2024-04-15 09:30  auto-rotate  Rotation      sk_l...ghi
  v1  2024-01-01 00:00  cli          Created       sk_l...jkl

$ pqvault restore STRIPE_SECRET_KEY --version 4
Restoring STRIPE_SECRET_KEY to version 4 (from 2024-10-01)...
  Current value (v5) will be saved as v6
  Version 4 value will become active
Confirm? [y/N] y
Restored. Current version: v6 (restored from v4)
```
