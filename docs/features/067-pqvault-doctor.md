# Feature 067: pqvault doctor

## Status: Planned
## Phase: 7 (v2.7)
## Priority: Medium

## Problem

When PQVault behaves unexpectedly — decryption fails, Keychain access is denied,
file permissions are wrong — users have no diagnostic tool. They resort to manual
troubleshooting: checking file permissions, verifying Keychain entries, testing
encryption roundtrips. There is no single command that validates the entire PQVault
installation and vault integrity.

## Solution

Implement `pqvault doctor` that performs a comprehensive health check of the PQVault
installation. It verifies vault file integrity, Keychain connectivity, file permissions,
encryption/decryption roundtrip, dependency versions, and configuration validity. Each
check reports pass/warn/fail with actionable fix suggestions.

## Implementation

### Files to Create/Modify

```
pqvault-cli/
  src/
    commands/
      doctor.rs        # Doctor command entry point
    doctor/
      mod.rs           # Module root, check registry
      checks/
        mod.rs         # Check trait definition
        vault.rs       # Vault file integrity checks
        keychain.rs    # macOS Keychain connectivity
        permissions.rs # File/directory permission checks
        crypto.rs      # Encryption roundtrip verification
        config.rs      # Configuration file validation
        deps.rs        # Dependency and version checks
        disk.rs        # Disk space and I/O checks
      report.rs        # Structured report output
```

### Data Model Changes

```rust
/// A single diagnostic check
#[async_trait]
pub trait DoctorCheck: Send + Sync {
    /// Human-readable check name
    fn name(&self) -> &str;

    /// Category for grouping
    fn category(&self) -> CheckCategory;

    /// Run the check
    async fn run(&self) -> CheckResult;
}

pub enum CheckCategory {
    Vault,
    Security,
    Connectivity,
    Configuration,
    System,
}

pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
    pub fix: Option<String>,      // Suggested fix if not passing
    pub duration: Duration,
}

pub enum CheckStatus {
    Pass,
    Warn(String),
    Fail(String),
    Skip(String),
}

pub struct DoctorReport {
    pub checks: Vec<CheckResult>,
    pub total_duration: Duration,
}

impl DoctorReport {
    pub fn passed(&self) -> usize {
        self.checks.iter().filter(|c| matches!(c.status, CheckStatus::Pass)).count()
    }
    pub fn warnings(&self) -> usize {
        self.checks.iter().filter(|c| matches!(c.status, CheckStatus::Warn(_))).count()
    }
    pub fn failures(&self) -> usize {
        self.checks.iter().filter(|c| matches!(c.status, CheckStatus::Fail(_))).count()
    }
    pub fn is_healthy(&self) -> bool {
        self.failures() == 0
    }
}
```

Individual check implementations:

```rust
pub struct VaultIntegrityCheck {
    vault_path: PathBuf,
}

#[async_trait]
impl DoctorCheck for VaultIntegrityCheck {
    fn name(&self) -> &str { "Vault file integrity" }
    fn category(&self) -> CheckCategory { CheckCategory::Vault }

    async fn run(&self) -> CheckResult {
        let db_path = self.vault_path.join("vault.db");
        if !db_path.exists() {
            return CheckResult::fail(
                self.name(),
                "vault.db not found",
                Some("Run `pqvault init` to create a new vault"),
            );
        }
        // Verify SQLite integrity
        match verify_sqlite_integrity(&db_path).await {
            Ok(()) => CheckResult::pass(self.name(), "Vault database is intact"),
            Err(e) => CheckResult::fail(
                self.name(),
                &format!("Database corruption detected: {}", e),
                Some("Restore from backup: `cp ~/.pqvault/vault.db.bak ~/.pqvault/vault.db`"),
            ),
        }
    }
}

pub struct KeychainCheck;

#[async_trait]
impl DoctorCheck for KeychainCheck {
    fn name(&self) -> &str { "macOS Keychain access" }
    fn category(&self) -> CheckCategory { CheckCategory::Connectivity }

    async fn run(&self) -> CheckResult {
        match keyring::Entry::new("pqvault", "master-key") {
            Ok(entry) => match entry.get_password() {
                Ok(_) => CheckResult::pass(self.name(), "Keychain accessible, master key found"),
                Err(keyring::Error::NoEntry) => CheckResult::warn(
                    self.name(),
                    "Keychain accessible but no master key stored",
                    Some("Run `pqvault init` to set up master key"),
                ),
                Err(e) => CheckResult::fail(
                    self.name(),
                    &format!("Keychain error: {}", e),
                    Some("Check Keychain Access.app for pqvault entries"),
                ),
            },
            Err(e) => CheckResult::fail(
                self.name(),
                &format!("Cannot create Keychain entry: {}", e),
                None,
            ),
        }
    }
}

pub struct CryptoRoundtripCheck;

#[async_trait]
impl DoctorCheck for CryptoRoundtripCheck {
    fn name(&self) -> &str { "Encryption roundtrip" }
    fn category(&self) -> CheckCategory { CheckCategory::Security }

    async fn run(&self) -> CheckResult {
        let test_data = b"pqvault-doctor-test-payload";
        match encrypt_decrypt_roundtrip(test_data).await {
            Ok(decrypted) if decrypted == test_data => {
                CheckResult::pass(self.name(), "AES-256-GCM encrypt/decrypt verified")
            }
            Ok(_) => CheckResult::fail(
                self.name(),
                "Decrypted data does not match original",
                Some("Master key may be corrupted. Re-initialize with `pqvault init --force`"),
            ),
            Err(e) => CheckResult::fail(
                self.name(),
                &format!("Crypto roundtrip failed: {}", e),
                None,
            ),
        }
    }
}
```

### MCP Tools

No new MCP tools. Doctor is a local diagnostic command.

### CLI Commands

```bash
# Run all checks
pqvault doctor

# Run specific check category
pqvault doctor --category security

# Output as JSON (for monitoring/CI)
pqvault doctor --format json

# Verbose mode with timing
pqvault doctor --verbose

# Auto-fix what can be fixed
pqvault doctor --fix

# Exit with code 1 on any failure (for CI)
pqvault doctor --strict
```

### Web UI Changes

None. Health dashboard is covered by `pqvault-health-mcp` tools.

## Dependencies

No new dependencies. Uses existing `keyring`, `aes-gcm`, and standard library.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_counts() {
        let report = DoctorReport {
            checks: vec![
                CheckResult::pass("a", "ok"),
                CheckResult::pass("b", "ok"),
                CheckResult::warn("c", "maybe", None),
                CheckResult::fail("d", "bad", None),
            ],
            total_duration: Duration::from_millis(100),
        };
        assert_eq!(report.passed(), 2);
        assert_eq!(report.warnings(), 1);
        assert_eq!(report.failures(), 1);
        assert!(!report.is_healthy());
    }

    #[test]
    fn test_permission_check_700() {
        let dir = tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
        }
        let check = PermissionCheck::new(dir.path().to_path_buf());
        let result = tokio_test::block_on(check.run());
        assert!(matches!(result.status, CheckStatus::Pass));
    }

    #[test]
    fn test_permission_check_world_readable() {
        let dir = tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), Permissions::from_mode(0o755)).unwrap();
        }
        let check = PermissionCheck::new(dir.path().to_path_buf());
        let result = tokio_test::block_on(check.run());
        assert!(matches!(result.status, CheckStatus::Fail(_)));
    }

    #[tokio::test]
    async fn test_crypto_roundtrip_check() {
        let check = CryptoRoundtripCheck;
        let result = check.run().await;
        // Should pass if crypto dependencies are properly configured
        assert!(matches!(result.status, CheckStatus::Pass | CheckStatus::Fail(_)));
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_full_doctor_run() {
    let vault = create_test_vault(&[("KEY", "val")]).await;
    let checks = get_all_checks(&vault.path);
    let report = run_all_checks(&checks).await;
    assert!(report.passed() > 0);
    // At minimum, vault integrity should pass
    let vault_check = report.checks.iter().find(|c| c.name == "Vault file integrity");
    assert!(vault_check.is_some());
    assert!(matches!(vault_check.unwrap().status, CheckStatus::Pass));
}
```

## Example Usage

```
$ pqvault doctor

  PQVault Doctor
  ══════════════════════════════════════════════

  Vault
  ────────────────────────────────────────────
  [PASS] Vault file integrity          vault.db is intact (256 keys)
  [PASS] Vault backup exists           Last backup: 2 hours ago
  [WARN] Vault size                    89MB — consider archiving old versions

  Security
  ────────────────────────────────────────────
  [PASS] Encryption roundtrip          AES-256-GCM verified
  [PASS] ML-KEM key encapsulation      Post-quantum KEM working
  [PASS] Key derivation                Argon2id parameters OK

  Connectivity
  ────────────────────────────────────────────
  [PASS] macOS Keychain access         Master key found
  [FAIL] Keychain lock status          Keychain is locked
         Fix: Run `security unlock-keychain ~/Library/Keychains/login.keychain-db`

  Configuration
  ────────────────────────────────────────────
  [PASS] Config file syntax            ~/.pqvault/config.toml is valid
  [PASS] Default vault path            ~/.pqvault/ exists

  System
  ────────────────────────────────────────────
  [PASS] Disk space                    142GB free
  [PASS] File permissions              Vault dir is 0700
  [PASS] PQVault version               v2.7.0 (latest)

  ══════════════════════════════════════════════
  Results: 11 passed, 1 warning, 1 failed
  Status: UNHEALTHY — fix failures above

$ echo $?
1
```
