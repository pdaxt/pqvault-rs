# Feature 076: Tamper-Evident Audit Log

## Status: Done
## Phase: 8 (v2.8)
## Priority: Medium

## Problem

The current audit log stores events as plain records that can be modified or deleted
without detection. An attacker who gains vault access could cover their tracks by
editing the audit log to remove evidence of unauthorized access. Compliance auditors
cannot verify that the audit trail is complete and unaltered, reducing its value
for SOC2 and ISO 27001 evidence.

## Solution

Implement a hash-chain audit log where each entry includes a SHA-256 hash of the
previous entry, creating a tamper-evident chain similar to a blockchain. Any
modification to a historical entry breaks the chain, making tampering immediately
detectable. The chain can be independently verified at any time, and the latest
hash can be anchored to an external timestamping authority for non-repudiation.

## Implementation

### Files to Create/Modify

```
pqvault-audit-mcp/
  src/
    chain/
      mod.rs           # Hash chain module root
      entry.rs         # Chain entry with hash linking
      hasher.rs        # SHA-256 chain hashing
      verifier.rs      # Chain integrity verification
      anchor.rs        # External timestamp anchoring
    tools/
      audit_verify.rs  # MCP tool: verify chain integrity
      audit_anchor.rs  # MCP tool: anchor to external service
```

### Data Model Changes

```rust
use sha2::{Sha256, Digest};

/// A single entry in the tamper-evident audit chain
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChainEntry {
    /// Sequential entry number
    pub sequence: u64,
    /// Hash of the previous entry (empty string for genesis)
    pub previous_hash: String,
    /// Hash of this entry's content + previous_hash
    pub entry_hash: String,
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// The actual audit event
    pub event: AuditEvent,
    /// Optional external anchor reference
    pub anchor: Option<AnchorRef>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub key_name: Option<String>,
    pub actor: String,
    pub source: String,          // "cli", "mcp", "web", "api"
    pub details: String,
    pub ip_address: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AuditEventType {
    KeyCreated,
    KeyAccessed,
    KeyRotated,
    KeyDeleted,
    KeyExported,
    VaultUnlocked,
    VaultLocked,
    ConfigChanged,
    ShareCreated,
    ShareUsed,
    PermissionChanged,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnchorRef {
    /// External service name
    pub service: String,
    /// Transaction/receipt ID from the service
    pub receipt_id: String,
    /// Timestamp from the external service
    pub anchored_at: DateTime<Utc>,
}

/// Verification result for the entire chain
pub struct ChainVerification {
    pub total_entries: u64,
    pub verified_entries: u64,
    pub first_entry: DateTime<Utc>,
    pub last_entry: DateTime<Utc>,
    pub status: ChainStatus,
    pub broken_at: Option<u64>,      // Sequence number where chain breaks
    pub anchors_verified: usize,
}

pub enum ChainStatus {
    /// All entries verified, chain is intact
    Intact,
    /// Chain is broken at a specific entry
    Broken { sequence: u64, expected_hash: String, actual_hash: String },
    /// Chain is empty
    Empty,
}

impl ChainEntry {
    /// Create a new entry linked to the previous one
    pub fn new(sequence: u64, previous_hash: &str, event: AuditEvent) -> Self {
        let timestamp = Utc::now();
        let content_hash = Self::compute_hash(sequence, previous_hash, &timestamp, &event);
        Self {
            sequence,
            previous_hash: previous_hash.to_string(),
            entry_hash: content_hash,
            timestamp,
            event,
            anchor: None,
        }
    }

    /// Compute the SHA-256 hash for this entry
    fn compute_hash(
        sequence: u64,
        previous_hash: &str,
        timestamp: &DateTime<Utc>,
        event: &AuditEvent,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sequence.to_le_bytes());
        hasher.update(previous_hash.as_bytes());
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hasher.update(serde_json::to_string(event).unwrap().as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Verify this entry's hash is correct
    pub fn verify(&self) -> bool {
        let expected = Self::compute_hash(
            self.sequence,
            &self.previous_hash,
            &self.timestamp,
            &self.event,
        );
        self.entry_hash == expected
    }
}

/// Verify the entire chain
pub fn verify_chain(entries: &[ChainEntry]) -> ChainVerification {
    if entries.is_empty() {
        return ChainVerification {
            total_entries: 0,
            verified_entries: 0,
            first_entry: Utc::now(),
            last_entry: Utc::now(),
            status: ChainStatus::Empty,
            broken_at: None,
            anchors_verified: 0,
        };
    }

    let mut verified = 0u64;
    let mut previous_hash = String::new(); // Genesis has empty previous

    for entry in entries {
        // Verify previous hash link
        if entry.previous_hash != previous_hash {
            return ChainVerification {
                total_entries: entries.len() as u64,
                verified_entries: verified,
                first_entry: entries[0].timestamp,
                last_entry: entries.last().unwrap().timestamp,
                status: ChainStatus::Broken {
                    sequence: entry.sequence,
                    expected_hash: previous_hash,
                    actual_hash: entry.previous_hash.clone(),
                },
                broken_at: Some(entry.sequence),
                anchors_verified: 0,
            };
        }

        // Verify entry self-hash
        if !entry.verify() {
            return ChainVerification {
                total_entries: entries.len() as u64,
                verified_entries: verified,
                first_entry: entries[0].timestamp,
                last_entry: entries.last().unwrap().timestamp,
                status: ChainStatus::Broken {
                    sequence: entry.sequence,
                    expected_hash: "self-hash mismatch".into(),
                    actual_hash: entry.entry_hash.clone(),
                },
                broken_at: Some(entry.sequence),
                anchors_verified: 0,
            };
        }

        previous_hash = entry.entry_hash.clone();
        verified += 1;
    }

    ChainVerification {
        total_entries: entries.len() as u64,
        verified_entries: verified,
        first_entry: entries[0].timestamp,
        last_entry: entries.last().unwrap().timestamp,
        status: ChainStatus::Intact,
        broken_at: None,
        anchors_verified: entries.iter().filter(|e| e.anchor.is_some()).count(),
    }
}
```

### MCP Tools

```rust
#[tool(description = "Verify the integrity of the tamper-evident audit chain")]
async fn audit_verify(
    /// Verify only the last N entries
    count: Option<u64>,
) -> Result<CallToolResult> { /* ... */ }

#[tool(description = "Anchor the current chain head to an external timestamp")]
async fn audit_anchor(
    /// Anchoring service: rfc3161, bitcoin, custom
    #[arg(default = "rfc3161")]
    service: String,
) -> Result<CallToolResult> { /* ... */ }
```

### CLI Commands

```bash
# Verify entire audit chain
pqvault audit verify

# Verify last 100 entries
pqvault audit verify --count 100

# Show chain statistics
pqvault audit chain-info

# Anchor to external timestamp authority
pqvault audit anchor

# Export chain for external verification
pqvault audit export --format json > audit-chain.json
```

### Web UI Changes

None directly. Audit chain status is shown in the compliance dashboard.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `sha2` | 0.10 | SHA-256 hashing (already in workspace) |

No new dependencies required.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_entry() {
        let event = AuditEvent {
            event_type: AuditEventType::VaultUnlocked,
            key_name: None,
            actor: "user".into(),
            source: "cli".into(),
            details: "Vault created".into(),
            ip_address: None,
        };
        let entry = ChainEntry::new(0, "", event);
        assert!(entry.verify());
        assert_eq!(entry.previous_hash, "");
        assert_eq!(entry.sequence, 0);
    }

    #[test]
    fn test_chain_linking() {
        let e1 = ChainEntry::new(0, "", mock_event("created"));
        let e2 = ChainEntry::new(1, &e1.entry_hash, mock_event("accessed"));
        assert!(e2.verify());
        assert_eq!(e2.previous_hash, e1.entry_hash);
    }

    #[test]
    fn test_chain_verification_intact() {
        let chain = build_test_chain(5);
        let result = verify_chain(&chain);
        assert!(matches!(result.status, ChainStatus::Intact));
        assert_eq!(result.verified_entries, 5);
    }

    #[test]
    fn test_chain_verification_tampered() {
        let mut chain = build_test_chain(5);
        // Tamper with entry 2
        chain[2].event.details = "tampered".into();
        let result = verify_chain(&chain);
        assert!(matches!(result.status, ChainStatus::Broken { .. }));
        assert_eq!(result.broken_at, Some(2));
    }

    #[test]
    fn test_chain_verification_deleted_entry() {
        let mut chain = build_test_chain(5);
        chain.remove(2); // Delete middle entry
        let result = verify_chain(&chain);
        assert!(matches!(result.status, ChainStatus::Broken { .. }));
    }

    fn build_test_chain(n: usize) -> Vec<ChainEntry> {
        let mut chain = Vec::new();
        let mut prev_hash = String::new();
        for i in 0..n {
            let entry = ChainEntry::new(i as u64, &prev_hash, mock_event(&format!("event_{}", i)));
            prev_hash = entry.entry_hash.clone();
            chain.push(entry);
        }
        chain
    }
}
```

## Example Usage

```
$ pqvault audit verify

  Audit Chain Verification
  ══════════════════════════════════════════

  Chain Status: INTACT
  Total Entries: 1,247
  Verified: 1,247 / 1,247
  First Entry: 2024-07-15 12:00:00 UTC
  Last Entry: 2025-03-15 14:30:00 UTC
  External Anchors: 12 verified

  Chain Head Hash:
  a1b2c3d4e5f6...9876543210fedcba

  All entries verified. No tampering detected.

$ pqvault audit verify --count 10

  Verifying last 10 entries...
  Entry #1238: KeyAccessed(STRIPE_KEY) by cli        ... OK
  Entry #1239: KeyRotated(DATABASE_URL) by auto       ... OK
  Entry #1240: KeyCreated(NEW_SERVICE) by mcp         ... OK
  ...
  Entry #1247: KeyAccessed(AWS_KEY) by cli            ... OK

  All 10 entries verified.
```
