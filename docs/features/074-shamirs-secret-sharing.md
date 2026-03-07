# Feature 074: Shamir's Secret Sharing

## Status: Done
## Phase: 8 (v2.8)
## Priority: High

## Problem

PQVault's master password is a single point of failure. If the user forgets it or
becomes incapacitated, all vault contents are permanently lost. Conversely, if the
master password is written down or stored digitally, it becomes a single point of
compromise. There is no way to split custody of the master key across multiple
trusted parties while maintaining security.

## Solution

Implement Shamir's Secret Sharing to split the master password into N shares where
any M shares (threshold) can reconstruct the original. For example, split into 5
shares distributed to 5 team members, requiring any 3 to unlock. This provides
both redundancy (surviving loss of N-M shares) and security (compromising fewer
than M shares reveals nothing about the secret).

## Implementation

### Files to Create/Modify

```
pqvault-core/
  src/
    shamir/
      mod.rs           # Shamir module root
      split.rs         # Secret splitting into shares
      combine.rs       # Share combination and reconstruction
      share.rs         # Share data structure and serialization
      verify.rs        # Share verification without reconstruction
```

### Data Model Changes

```rust
use sharks::{Sharks, Share as SharkShare};

/// Configuration for a Shamir split operation
pub struct ShamirConfig {
    /// Total number of shares to create
    pub total_shares: u8,
    /// Minimum shares needed to reconstruct (threshold)
    pub threshold: u8,
    /// Optional labels for each share (e.g., recipient names)
    pub labels: Option<Vec<String>>,
}

/// A single share that can be distributed
#[derive(Serialize, Deserialize, Clone)]
pub struct VaultShare {
    /// Share identifier (1-based)
    pub index: u8,
    /// The share data (encoded)
    pub data: Vec<u8>,
    /// Optional label (e.g., "alice@team.com")
    pub label: Option<String>,
    /// Split metadata
    pub metadata: ShareMetadata,
    /// Verification hash (to verify share belongs to this split)
    pub verification_hash: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ShareMetadata {
    /// Unique ID for this split operation
    pub split_id: String,
    /// Total number of shares created
    pub total_shares: u8,
    /// Threshold needed to reconstruct
    pub threshold: u8,
    /// When the split was performed
    pub created_at: DateTime<Utc>,
    /// PQVault version that created the split
    pub pqvault_version: String,
}

pub struct ShamirEngine;

impl ShamirEngine {
    /// Split a secret into N shares with threshold M
    pub fn split(secret: &[u8], config: &ShamirConfig) -> Result<Vec<VaultShare>> {
        if config.threshold > config.total_shares {
            return Err(anyhow!("Threshold ({}) cannot exceed total shares ({})",
                config.threshold, config.total_shares));
        }
        if config.threshold < 2 {
            return Err(anyhow!("Threshold must be at least 2"));
        }

        let sharks = Sharks(config.threshold);
        let dealer = sharks.dealer(secret);

        let split_id = uuid::Uuid::new_v4().to_string();
        let verification = sha256_hex(&format!("{}:{}", split_id, hex::encode(secret)));

        let shares: Vec<VaultShare> = dealer
            .take(config.total_shares as usize)
            .enumerate()
            .map(|(i, share)| {
                let data: Vec<u8> = (&share).into();
                let label = config.labels.as_ref()
                    .and_then(|labels| labels.get(i).cloned());
                VaultShare {
                    index: (i + 1) as u8,
                    data,
                    label,
                    metadata: ShareMetadata {
                        split_id: split_id.clone(),
                        total_shares: config.total_shares,
                        threshold: config.threshold,
                        created_at: Utc::now(),
                        pqvault_version: env!("CARGO_PKG_VERSION").to_string(),
                    },
                    verification_hash: verification.clone(),
                }
            })
            .collect();

        Ok(shares)
    }

    /// Reconstruct the secret from M or more shares
    pub fn combine(shares: &[VaultShare]) -> Result<Vec<u8>> {
        if shares.is_empty() {
            return Err(anyhow!("No shares provided"));
        }

        let threshold = shares[0].metadata.threshold;
        if shares.len() < threshold as usize {
            return Err(anyhow!(
                "Need at least {} shares to reconstruct (got {})",
                threshold, shares.len()
            ));
        }

        // Verify all shares belong to same split
        let split_id = &shares[0].metadata.split_id;
        if !shares.iter().all(|s| &s.metadata.split_id == split_id) {
            return Err(anyhow!("Shares from different split operations cannot be combined"));
        }

        let shark_shares: Vec<SharkShare> = shares.iter()
            .map(|s| SharkShare::try_from(s.data.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("Invalid share data: {}", e))?;

        let sharks = Sharks(threshold);
        let secret = sharks.recover(&shark_shares)
            .map_err(|e| anyhow!("Failed to reconstruct secret: {}", e))?;

        Ok(secret)
    }

    /// Verify a share belongs to a specific split without reconstruction
    pub fn verify_share(share: &VaultShare, split_id: &str) -> bool {
        share.metadata.split_id == split_id
    }
}
```

### MCP Tools

No new MCP tools. Shamir operations are security-critical and should only be
performed locally via CLI with user confirmation.

### CLI Commands

```bash
# Split master password into 5 shares, threshold 3
pqvault shamir split --shares 5 --threshold 3

# Split with labeled recipients
pqvault shamir split --shares 5 --threshold 3 \
  --labels "alice@co.com,bob@co.com,carol@co.com,dave@co.com,eve@co.com"

# Export shares as individual files
pqvault shamir split --shares 5 --threshold 3 --output-dir ./shares/

# Export shares as QR codes (for physical distribution)
pqvault shamir split --shares 5 --threshold 3 --format qr

# Reconstruct from share files
pqvault shamir combine share-1.json share-3.json share-5.json

# Reconstruct interactively (paste shares)
pqvault shamir combine --interactive

# Verify a share belongs to a specific split
pqvault shamir verify share-1.json
```

```rust
#[derive(Subcommand)]
pub enum ShamirCommands {
    /// Split master password into shares
    Split(SplitArgs),
    /// Reconstruct master password from shares
    Combine(CombineArgs),
    /// Verify a share
    Verify(VerifyArgs),
}

#[derive(Args)]
pub struct SplitArgs {
    /// Total number of shares to create
    #[arg(long, short = 'n')]
    shares: u8,

    /// Minimum shares needed to reconstruct
    #[arg(long, short = 't')]
    threshold: u8,

    /// Comma-separated labels for each share
    #[arg(long)]
    labels: Option<String>,

    /// Output directory for share files
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// Output format: json, qr, base64
    #[arg(long, default_value = "json")]
    format: String,
}
```

### Web UI Changes

None. Shamir operations are CLI-only for security.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `sharks` | 0.5 | Shamir's Secret Sharing implementation |
| `uuid` | 1 | Unique split operation identifiers |
| `hex` | 0.4 | Hex encoding for share display |

Add to `pqvault-core/Cargo.toml`:

```toml
[dependencies]
sharks = "0.5"
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_combine_minimum_threshold() {
        let secret = b"my-master-password-2025";
        let config = ShamirConfig { total_shares: 5, threshold: 3, labels: None };
        let shares = ShamirEngine::split(secret, &config).unwrap();
        assert_eq!(shares.len(), 5);

        // Combine with exactly threshold shares
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = ShamirEngine::combine(&subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_combine_with_all_shares() {
        let secret = b"test-secret";
        let config = ShamirConfig { total_shares: 3, threshold: 2, labels: None };
        let shares = ShamirEngine::split(secret, &config).unwrap();
        let recovered = ShamirEngine::combine(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_combine_below_threshold_fails() {
        let secret = b"test-secret";
        let config = ShamirConfig { total_shares: 5, threshold: 3, labels: None };
        let shares = ShamirEngine::split(secret, &config).unwrap();
        let subset = vec![shares[0].clone()]; // Only 1, need 3
        let result = ShamirEngine::combine(&subset);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_exceeds_total_fails() {
        let config = ShamirConfig { total_shares: 3, threshold: 5, labels: None };
        let result = ShamirEngine::split(b"test", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_shares_have_correct_metadata() {
        let config = ShamirConfig { total_shares: 3, threshold: 2, labels: None };
        let shares = ShamirEngine::split(b"test", &config).unwrap();
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.index, (i + 1) as u8);
            assert_eq!(share.metadata.total_shares, 3);
            assert_eq!(share.metadata.threshold, 2);
        }
    }

    #[test]
    fn test_mixed_split_shares_rejected() {
        let shares_a = ShamirEngine::split(b"secret_a", &ShamirConfig { total_shares: 3, threshold: 2, labels: None }).unwrap();
        let shares_b = ShamirEngine::split(b"secret_b", &ShamirConfig { total_shares: 3, threshold: 2, labels: None }).unwrap();
        let mixed = vec![shares_a[0].clone(), shares_b[1].clone()];
        let result = ShamirEngine::combine(&mixed);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_labels() {
        let config = ShamirConfig {
            total_shares: 3, threshold: 2,
            labels: Some(vec!["alice".into(), "bob".into(), "carol".into()]),
        };
        let shares = ShamirEngine::split(b"test", &config).unwrap();
        assert_eq!(shares[0].label, Some("alice".into()));
        assert_eq!(shares[1].label, Some("bob".into()));
    }
}
```

## Example Usage

```
$ pqvault shamir split --shares 5 --threshold 3 \
    --labels "alice,bob,carol,dave,eve" \
    --output-dir ./vault-shares/

  Shamir Secret Sharing
  ══════════════════════════════

  Master password split into 5 shares (threshold: 3)
  Any 3 of 5 shares can reconstruct the master password.

  Share files created:
    ./vault-shares/share-1-alice.json
    ./vault-shares/share-2-bob.json
    ./vault-shares/share-3-carol.json
    ./vault-shares/share-4-dave.json
    ./vault-shares/share-5-eve.json

  Split ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890

  IMPORTANT:
  - Distribute each share to its labeled recipient
  - No single share reveals any information about the password
  - Store shares in separate, secure locations
  - Losing 2 shares is safe; losing 3+ makes recovery impossible

$ pqvault shamir combine \
    ./vault-shares/share-1-alice.json \
    ./vault-shares/share-3-carol.json \
    ./vault-shares/share-5-eve.json

  Combining 3 shares (threshold: 3)...
  Master password reconstructed successfully.
  Vault unlocked.
```
