# Feature 099: Vault-to-Vault Migration

## Status: Planned
## Phase: 10 (v3.0)
## Priority: Low

## Problem

When onboarding new team members, setting up new machines, or consolidating vaults
after an acquisition, there is no secure way to transfer secrets between PQVault
instances. Users resort to exporting to plaintext files or manually copying secrets
one by one. Both approaches are insecure — plaintext files can be intercepted, and
manual copying is error-prone and does not preserve metadata.

## Solution

Implement encrypted vault-to-vault migration using an export/import flow. The source
vault exports secrets into an encrypted migration bundle (using the recipient's public
key for end-to-end encryption). The recipient imports the bundle into their vault.
The bundle preserves all metadata (categories, tags, rotation policies) and is
protected against tampering via HMAC verification.

## Implementation

### Files to Create/Modify

```
pqvault-cli/
  src/
    commands/
      migrate.rs       # Migration command entry point
    migration/
      mod.rs           # Migration module root
      exporter.rs      # Export vault to encrypted bundle
      importer.rs      # Import from encrypted bundle
      bundle.rs        # Migration bundle format
      crypto.rs        # Bundle encryption using recipient's public key
```

### Data Model Changes

```rust
/// An encrypted migration bundle
#[derive(Serialize, Deserialize)]
pub struct MigrationBundle {
    /// Bundle format version
    pub version: String,
    /// Bundle identifier
    pub bundle_id: String,
    /// Source vault info (non-sensitive)
    pub source: BundleSource,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration time (bundle self-destructs)
    pub expires_at: DateTime<Utc>,
    /// Number of secrets included
    pub secret_count: usize,
    /// Encrypted payload (contains the actual secrets)
    pub encrypted_payload: Vec<u8>,
    /// HMAC of the encrypted payload for tamper detection
    pub hmac: Vec<u8>,
    /// Recipient's public key fingerprint (who can decrypt)
    pub recipient_fingerprint: String,
    /// Nonce used for encryption
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct BundleSource {
    pub vault_name: String,
    pub exported_by: String,
    pub machine_id: String,
}

/// Decrypted bundle payload
#[derive(Serialize, Deserialize)]
pub struct BundlePayload {
    pub secrets: Vec<MigrationSecret>,
    pub metadata_version: String,
}

#[derive(Serialize, Deserialize)]
pub struct MigrationSecret {
    pub key_name: String,
    pub encrypted_value: Vec<u8>,     // Re-encrypted for transport
    pub category: Option<String>,
    pub provider: Option<String>,
    pub tags: Vec<String>,
    pub rotation_days: Option<u32>,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub dependencies: Option<KeyDependency>,
}

/// Export options
pub struct ExportOptions {
    /// Keys to export (empty = all)
    pub keys: Vec<String>,
    /// Recipient's public key for encryption
    pub recipient_public_key: Vec<u8>,
    /// Bundle expiry duration
    pub ttl: Duration,
    /// Include version history
    pub include_history: bool,
    /// Passphrase for additional encryption layer
    pub passphrase: Option<String>,
}

/// Import options
pub struct ImportOptions {
    /// Override conflicts (use bundle value)
    pub overwrite: bool,
    /// Skip existing keys
    pub skip_existing: bool,
    /// Category prefix to add
    pub category_prefix: Option<String>,
    /// Key name prefix to add
    pub key_prefix: Option<String>,
}

pub struct Exporter;

impl Exporter {
    pub async fn export(vault: &Vault, options: &ExportOptions) -> Result<MigrationBundle> {
        let keys = if options.keys.is_empty() {
            vault.list_keys().await?
        } else {
            options.keys.clone()
        };

        let mut secrets = Vec::new();
        for key in &keys {
            let entry = vault.get_full(key).await?;
            secrets.push(MigrationSecret {
                key_name: key.clone(),
                encrypted_value: entry.encrypted_value,
                category: entry.category,
                provider: entry.provider,
                tags: entry.tags,
                rotation_days: entry.rotation_days,
                created_at: entry.created_at,
                rotated_at: entry.rotated_at,
                dependencies: entry.dependencies,
            });
        }

        let payload = BundlePayload {
            secrets,
            metadata_version: "1.0".into(),
        };

        let payload_bytes = serde_json::to_vec(&payload)?;

        // Encrypt payload with recipient's public key
        let (encrypted, nonce) = encrypt_for_recipient(
            &payload_bytes,
            &options.recipient_public_key,
            options.passphrase.as_deref(),
        )?;

        let hmac = compute_hmac(&encrypted)?;
        let fingerprint = key_fingerprint(&options.recipient_public_key);

        Ok(MigrationBundle {
            version: "1.0".into(),
            bundle_id: uuid::Uuid::new_v4().to_string(),
            source: BundleSource {
                vault_name: vault.name().to_string(),
                exported_by: whoami::username(),
                machine_id: machine_id()?,
            },
            created_at: Utc::now(),
            expires_at: Utc::now() + options.ttl,
            secret_count: payload.secrets.len(),
            encrypted_payload: encrypted,
            hmac,
            recipient_fingerprint: fingerprint,
            nonce,
        })
    }
}

pub struct Importer;

impl Importer {
    pub async fn import(
        vault: &mut Vault,
        bundle: &MigrationBundle,
        private_key: &[u8],
        options: &ImportOptions,
    ) -> Result<ImportResult> {
        // Check expiry
        if Utc::now() > bundle.expires_at {
            return Err(anyhow!("Migration bundle has expired"));
        }

        // Verify HMAC
        verify_hmac(&bundle.encrypted_payload, &bundle.hmac)?;

        // Decrypt payload
        let payload_bytes = decrypt_bundle(
            &bundle.encrypted_payload,
            &bundle.nonce,
            private_key,
        )?;

        let payload: BundlePayload = serde_json::from_slice(&payload_bytes)?;

        let mut result = ImportResult::default();
        for secret in &payload.secrets {
            let key_name = match &options.key_prefix {
                Some(prefix) => format!("{}_{}", prefix, secret.key_name),
                None => secret.key_name.clone(),
            };

            let exists = vault.get(&key_name).await.is_ok();
            if exists && !options.overwrite {
                if options.skip_existing {
                    result.skipped.push(key_name);
                    continue;
                }
                result.conflicts.push(key_name);
                continue;
            }

            vault.import_secret(&key_name, secret).await?;
            if exists {
                result.overwritten.push(key_name);
            } else {
                result.created.push(key_name);
            }
        }

        Ok(result)
    }
}

#[derive(Default)]
pub struct ImportResult {
    pub created: Vec<String>,
    pub overwritten: Vec<String>,
    pub skipped: Vec<String>,
    pub conflicts: Vec<String>,
}
```

### MCP Tools

No new MCP tools. Migration is a CLI-only security-sensitive operation.

### CLI Commands

```bash
# Export entire vault to encrypted bundle
pqvault migrate export --recipient-key recipient_pub.key --output bundle.pqm

# Export specific keys
pqvault migrate export --keys STRIPE_KEY,DB_URL --recipient-key pub.key --output bundle.pqm

# Export with passphrase and 24h expiry
pqvault migrate export --passphrase --ttl 24h --output bundle.pqm

# Import from bundle
pqvault migrate import bundle.pqm

# Import with options
pqvault migrate import bundle.pqm --skip-existing --key-prefix IMPORTED

# Inspect bundle metadata (without decrypting)
pqvault migrate inspect bundle.pqm

# Generate keypair for migration
pqvault migrate keygen --output migration_key
```

### Web UI Changes

None. Migration is CLI-only for security.

## Dependencies

No new dependencies. Uses existing `x25519-dalek`, `aes-gcm`, and `ml-kem` from pqvault-core.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_creation() {
        let bundle = MigrationBundle {
            version: "1.0".into(),
            bundle_id: "test-id".into(),
            source: BundleSource {
                vault_name: "test".into(),
                exported_by: "user".into(),
                machine_id: "m1".into(),
            },
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            secret_count: 5,
            encrypted_payload: vec![0x01, 0x02],
            hmac: vec![0x03, 0x04],
            recipient_fingerprint: "fp123".into(),
            nonce: vec![0x05],
        };
        assert_eq!(bundle.secret_count, 5);
        assert!(bundle.expires_at > bundle.created_at);
    }

    #[test]
    fn test_bundle_expiry_check() {
        let bundle = MigrationBundle {
            expires_at: Utc::now() - chrono::Duration::hours(1),
            ..mock_bundle()
        };
        assert!(Utc::now() > bundle.expires_at);
    }

    #[test]
    fn test_import_skip_existing() {
        let options = ImportOptions {
            overwrite: false,
            skip_existing: true,
            category_prefix: None,
            key_prefix: None,
        };
        assert!(!options.overwrite);
        assert!(options.skip_existing);
    }

    #[test]
    fn test_key_prefix_applied() {
        let prefix = Some("IMPORTED".to_string());
        let key_name = "STRIPE_KEY";
        let prefixed = match &prefix {
            Some(p) => format!("{}_{}", p, key_name),
            None => key_name.to_string(),
        };
        assert_eq!(prefixed, "IMPORTED_STRIPE_KEY");
    }

    #[test]
    fn test_hmac_verification() {
        let data = b"test payload";
        let hmac = compute_hmac(data).unwrap();
        assert!(verify_hmac(data, &hmac).is_ok());
        assert!(verify_hmac(b"tampered", &hmac).is_err());
    }
}
```

## Example Usage

```
$ pqvault migrate keygen --output ~/migration_key
  Generated X25519 keypair:
    Public:  ~/migration_key.pub
    Private: ~/migration_key (keep secret!)

# Sender exports:
$ pqvault migrate export \
    --recipient-key ~/colleague_migration_key.pub \
    --ttl 24h \
    --output vault_transfer.pqm

  Exporting 24 secrets from vault...
  Bundle encrypted for recipient: fp:a1b2c3d4
  Expires: 2025-03-16 14:30 UTC (24h)
  Output: vault_transfer.pqm (12.4 KB)

# Recipient imports:
$ pqvault migrate import vault_transfer.pqm

  Migration Bundle Info:
    Source: alice-vault (exported by alice@team.com)
    Created: 2025-03-15 14:30 UTC
    Expires: 2025-03-16 14:30 UTC
    Secrets: 24

  Importing...
    Created: 20 keys
    Skipped: 4 keys (already exist)

  Import complete: 20 new, 4 skipped, 0 conflicts.
```
