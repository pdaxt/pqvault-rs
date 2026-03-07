# Feature 004: Encrypted Audit Log

## Status: Planned
## Phase: 1 (v2.1)
## Priority: High

## Problem

The audit log at `~/.pqvault/audit.log` is stored as plaintext JSONL. Each line contains sensitive metadata: key names accessed, timestamps, agent identities, operations performed, and IP addresses. An attacker who gains read access to the filesystem can reconstruct exactly which secrets exist, who accessed them, and when — even without decrypting the vault itself. This metadata leakage is a significant security gap.

## Solution

Encrypt each audit log entry individually with AES-256-GCM using a key derived from the master password before writing to disk. Each line in the audit log becomes an encrypted blob (base64-encoded ciphertext + nonce). On read, entries are decrypted on-the-fly. This reuses the existing `password_encrypt`/`password_decrypt` functions from `pqvault-core/src/crypto.rs`, maintaining a single cryptographic implementation.

## Implementation

### Files to Create/Modify

- `crates/pqvault-audit-mcp/src/encrypted_audit.rs` — Encrypted audit log reader/writer
- `crates/pqvault-audit-mcp/src/lib.rs` — Replace plaintext audit calls with encrypted versions
- `crates/pqvault-core/src/crypto.rs` — Add `derive_audit_key()` for separate key derivation
- `crates/pqvault-cli/src/main.rs` — Add `audit migrate` subcommand for migrating plaintext logs

### Data Model Changes

```rust
/// A single audit log entry (same as before, but now encrypted at rest)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub operation: AuditOperation,
    pub key_name: Option<String>,
    pub agent_id: Option<String>,
    pub caller: String,
    pub success: bool,
    pub details: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AuditOperation {
    Get,
    List,
    Add,
    Delete,
    Update,
    Search,
    Rotate,
    Export,
    Import,
    Login,
    ProxyRequest,
}

/// On-disk format: each line is one of these
#[derive(Serialize, Deserialize)]
struct EncryptedAuditLine {
    /// Version marker for forward compatibility
    pub v: u8,
    /// Base64-encoded encrypted JSON
    pub data: String,
}

/// Audit log configuration
#[derive(Serialize, Deserialize, Clone)]
pub struct AuditConfig {
    /// Maximum entries per file before rotation
    pub max_entries_per_file: usize,
    /// Maximum number of rotated log files to keep
    pub max_rotated_files: usize,
    /// Whether encryption is enabled (for migration period)
    pub encrypted: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_entries_per_file: 10_000,
            max_rotated_files: 10,
            encrypted: true,
        }
    }
}
```

### MCP Tools

Existing audit MCP tools are modified to use encryption transparently:

```rust
// Tool: audit_query (modified)
// Now requires master password in AppState to decrypt entries
{
    "name": "audit_query",
    "params": {
        "key_name": "STRIPE_KEY",      // optional filter
        "operation": "Get",             // optional filter
        "since": "2025-01-01T00:00:00", // optional
        "limit": 100
    },
    "returns": {
        "entries": [...],              // Decrypted AuditEntry objects
        "total_count": 1523
    }
}

// Tool: audit_compliance_report (modified)
// Generates compliance report from encrypted log data
{
    "name": "audit_compliance_report",
    "params": {
        "period": "2025-Q1",
        "format": "summary"
    },
    "returns": {
        "total_operations": 15234,
        "unique_keys_accessed": 42,
        "unique_agents": 5,
        "operations_by_type": { "Get": 12000, "List": 2000, ... }
    }
}
```

### CLI Commands

```bash
# View audit log (decrypts on the fly)
pqvault audit --tail 20

# Search audit log
pqvault audit --key STRIPE_KEY --since 2025-01-01

# Migrate plaintext audit log to encrypted
pqvault audit migrate

# Export audit log (decrypted, for compliance)
pqvault audit export --format json --output audit-report.json

# Rotate audit log manually
pqvault audit rotate
```

### Web UI Changes

The audit log viewer on the web dashboard works the same, but decryption happens server-side. No UI changes needed, only the backend data pipeline changes.

## Core Implementation

### Key Derivation

```rust
// crates/pqvault-core/src/crypto.rs

use argon2::{Argon2, password_hash::SaltString};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

/// Derive a separate key for audit log encryption.
/// Uses a different salt context than vault encryption to ensure
/// the audit key is independent from the vault key.
pub fn derive_audit_key(master_password: &str) -> Result<[u8; 32]> {
    // Use a fixed, domain-separated salt for audit log key derivation.
    // This ensures the audit key is deterministic (same password = same key)
    // but distinct from the vault encryption key.
    let salt = b"pqvault-audit-log-encryption-v1";
    let mut key = [0u8; 32];

    let argon2 = Argon2::default();
    argon2.hash_password_into(
        master_password.as_bytes(),
        salt,
        &mut key,
    ).map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

    Ok(key)
}
```

### Encrypted Audit Writer

```rust
// crates/pqvault-audit-mcp/src/encrypted_audit.rs

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use anyhow::Result;

pub struct EncryptedAuditLog {
    path: PathBuf,
    cipher: Aes256Gcm,
    config: AuditConfig,
}

impl EncryptedAuditLog {
    pub fn new(audit_dir: &Path, master_password: &str) -> Result<Self> {
        let key = derive_audit_key(master_password)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;

        Ok(Self {
            path: audit_dir.join("audit.enc.log"),
            cipher,
            config: AuditConfig::default(),
        })
    }

    /// Append an encrypted audit entry
    pub fn append(&self, entry: &AuditEntry) -> Result<()> {
        // Check if rotation needed
        self.maybe_rotate()?;

        // Serialize entry to JSON
        let json = serde_json::to_string(entry)?;

        // Generate random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = self.cipher.encrypt(nonce, json.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Combine nonce + ciphertext, base64 encode
        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&ciphertext);
        let encoded = BASE64.encode(&combined);

        // Write as single-line JSON
        let line = EncryptedAuditLine { v: 1, data: encoded };
        let json_line = serde_json::to_string(&line)?;

        // Append to file (atomic-ish — single write call)
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", json_line)?;

        Ok(())
    }

    /// Read and decrypt all entries
    pub fn read_all(&self) -> Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = fs::File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            match self.decrypt_line(&line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    eprintln!("Warning: Failed to decrypt audit entry: {}", e);
                    continue;
                }
            }
        }

        Ok(entries)
    }

    /// Decrypt a single line
    fn decrypt_line(&self, line: &str) -> Result<AuditEntry> {
        let encrypted: EncryptedAuditLine = serde_json::from_str(line)?;

        if encrypted.v != 1 {
            anyhow::bail!("Unsupported audit log version: {}", encrypted.v);
        }

        let combined = BASE64.decode(&encrypted.data)?;
        if combined.len() < 12 {
            anyhow::bail!("Invalid encrypted data: too short");
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self.cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        let entry: AuditEntry = serde_json::from_slice(&plaintext)?;
        Ok(entry)
    }

    /// Query entries with filters
    pub fn query(
        &self,
        key_name: Option<&str>,
        operation: Option<AuditOperation>,
        since: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEntry>> {
        let all = self.read_all()?;

        let filtered: Vec<AuditEntry> = all
            .into_iter()
            .filter(|e| {
                if let Some(kn) = key_name {
                    if e.key_name.as_deref() != Some(kn) {
                        return false;
                    }
                }
                if let Some(ref op) = operation {
                    if std::mem::discriminant(&e.operation) != std::mem::discriminant(op) {
                        return false;
                    }
                }
                if let Some(since_str) = since {
                    if e.timestamp < since_str.to_string() {
                        return false;
                    }
                }
                true
            })
            .rev() // Most recent first
            .take(limit)
            .collect();

        Ok(filtered)
    }

    /// Rotate log file when it exceeds max entries
    fn maybe_rotate(&self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }

        let file = fs::File::open(&self.path)?;
        let line_count = BufReader::new(file).lines().count();

        if line_count >= self.config.max_entries_per_file {
            // Rotate: audit.enc.log -> audit.enc.log.1 -> audit.enc.log.2 ...
            for i in (1..self.config.max_rotated_files).rev() {
                let from = self.path.with_extension(format!("log.{}", i));
                let to = self.path.with_extension(format!("log.{}", i + 1));
                if from.exists() {
                    fs::rename(&from, &to)?;
                }
            }

            let rotated = self.path.with_extension("log.1");
            fs::rename(&self.path, &rotated)?;
        }

        Ok(())
    }
}
```

### Migration from Plaintext

```rust
/// Migrate plaintext audit.log to encrypted audit.enc.log
pub fn migrate_plaintext_to_encrypted(
    audit_dir: &Path,
    master_password: &str,
) -> Result<MigrationResult> {
    let plaintext_path = audit_dir.join("audit.log");
    if !plaintext_path.exists() {
        return Ok(MigrationResult { migrated: 0, errors: 0 });
    }

    let encrypted_log = EncryptedAuditLog::new(audit_dir, master_password)?;

    let file = fs::File::open(&plaintext_path)?;
    let reader = BufReader::new(file);
    let mut migrated = 0;
    let mut errors = 0;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(&line) {
            Ok(entry) => {
                encrypted_log.append(&entry)?;
                migrated += 1;
            }
            Err(e) => {
                eprintln!("Warning: Failed to parse audit entry: {}", e);
                errors += 1;
            }
        }
    }

    // Rename plaintext file (don't delete, let user verify)
    fs::rename(&plaintext_path, audit_dir.join("audit.log.migrated"))?;

    Ok(MigrationResult { migrated, errors })
}
```

## Dependencies

- `aes-gcm = "0.10"` — Already a dependency, used for AES-256-GCM encryption
- `argon2 = "0.5"` — Already a dependency, used for key derivation
- `base64 = "0.22"` — Already a dependency, for encoding encrypted data
- `rand = "0.8"` — Already a dependency, for nonce generation
- No new dependencies required

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let log = EncryptedAuditLog::new(dir.path(), "test-password").unwrap();

        let entry = AuditEntry {
            timestamp: "2025-01-15T10:30:00Z".into(),
            operation: AuditOperation::Get,
            key_name: Some("STRIPE_KEY".into()),
            agent_id: Some("agent-1".into()),
            caller: "mcp".into(),
            success: true,
            details: None,
        };

        log.append(&entry).unwrap();

        let entries = log.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key_name, Some("STRIPE_KEY".into()));
        assert_eq!(entries[0].timestamp, "2025-01-15T10:30:00Z");
    }

    #[test]
    fn test_wrong_password_fails_decrypt() {
        let dir = tempdir().unwrap();
        let log1 = EncryptedAuditLog::new(dir.path(), "password1").unwrap();
        let entry = AuditEntry {
            timestamp: "2025-01-15T10:30:00Z".into(),
            operation: AuditOperation::Get,
            key_name: Some("KEY".into()),
            agent_id: None,
            caller: "cli".into(),
            success: true,
            details: None,
        };
        log1.append(&entry).unwrap();

        let log2 = EncryptedAuditLog::new(dir.path(), "wrong-password").unwrap();
        let entries = log2.read_all().unwrap();
        // Wrong password: entries should be empty (decryption failures are skipped)
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_multiple_entries() {
        let dir = tempdir().unwrap();
        let log = EncryptedAuditLog::new(dir.path(), "test-password").unwrap();

        for i in 0..100 {
            let entry = AuditEntry {
                timestamp: format!("2025-01-15T{:02}:00:00Z", i % 24),
                operation: AuditOperation::Get,
                key_name: Some(format!("KEY_{}", i)),
                agent_id: None,
                caller: "test".into(),
                success: true,
                details: None,
            };
            log.append(&entry).unwrap();
        }

        let entries = log.read_all().unwrap();
        assert_eq!(entries.len(), 100);
    }

    #[test]
    fn test_query_by_key_name() {
        let dir = tempdir().unwrap();
        let log = EncryptedAuditLog::new(dir.path(), "test-password").unwrap();

        log.append(&make_entry("KEY_A", AuditOperation::Get)).unwrap();
        log.append(&make_entry("KEY_B", AuditOperation::Get)).unwrap();
        log.append(&make_entry("KEY_A", AuditOperation::Update)).unwrap();

        let results = log.query(Some("KEY_A"), None, None, 100).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_log_rotation() {
        let dir = tempdir().unwrap();
        let mut log = EncryptedAuditLog::new(dir.path(), "test-password").unwrap();
        log.config.max_entries_per_file = 5;

        for i in 0..10 {
            log.append(&make_entry(&format!("KEY_{}", i), AuditOperation::Get)).unwrap();
        }

        // Should have rotated: audit.enc.log + audit.enc.log.1
        assert!(dir.path().join("audit.enc.log").exists());
        assert!(dir.path().join("audit.enc.log.1").exists());
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_migration_from_plaintext() {
    let dir = tempdir().unwrap();

    // Write plaintext audit entries
    let plaintext_path = dir.path().join("audit.log");
    let mut file = fs::File::create(&plaintext_path).unwrap();
    for i in 0..5 {
        let entry = json!({
            "timestamp": format!("2025-01-{:02}T10:00:00Z", i + 1),
            "operation": "Get",
            "key_name": format!("KEY_{}", i),
            "caller": "cli",
            "success": true
        });
        writeln!(file, "{}", entry).unwrap();
    }
    drop(file);

    // Migrate
    let result = migrate_plaintext_to_encrypted(dir.path(), "test-password").unwrap();
    assert_eq!(result.migrated, 5);
    assert_eq!(result.errors, 0);

    // Verify encrypted log is readable
    let log = EncryptedAuditLog::new(dir.path(), "test-password").unwrap();
    let entries = log.read_all().unwrap();
    assert_eq!(entries.len(), 5);

    // Verify plaintext file was renamed
    assert!(!plaintext_path.exists());
    assert!(dir.path().join("audit.log.migrated").exists());
}
```

### Manual Verification

1. Generate audit entries: access several keys via CLI and MCP
2. Check `~/.pqvault/audit.enc.log` — should be unreadable (base64 blobs, not JSON)
3. Run `pqvault audit --tail 10` — should show decrypted entries
4. Copy audit file to another machine — should be undecryptable without master password
5. Migrate from plaintext: run `pqvault audit migrate`, verify old entries preserved

## Example Usage

```bash
# View recent audit entries
$ pqvault audit --tail 5
2025-01-15 10:30:00 | GET    | STRIPE_KEY      | agent-1 | success
2025-01-15 10:29:45 | LIST   | -               | cli     | success
2025-01-15 10:25:12 | ADD    | NEW_API_KEY     | cli     | success
2025-01-15 10:20:00 | GET    | DATABASE_URL    | agent-2 | success
2025-01-15 10:15:33 | SEARCH | query="stripe"  | mcp     | success

# Search for specific key access
$ pqvault audit --key STRIPE_KEY --since 2025-01-01
Found 47 entries for STRIPE_KEY since 2025-01-01:
  43 GET operations (by: agent-1, agent-3, cli)
  2 UPDATE operations (by: cli)
  1 ROTATE operation (by: cli)
  1 ADD operation (by: cli)

# Migrate existing plaintext log
$ pqvault audit migrate
Migrating plaintext audit log...
  Migrated: 1,523 entries
  Errors: 0
  Original file renamed to audit.log.migrated
Encrypted audit log is now active.

# Verify the encrypted file is opaque
$ head -1 ~/.pqvault/audit.enc.log
{"v":1,"data":"nO3kL9mXq2p1Y0gR...base64...=="}
```
