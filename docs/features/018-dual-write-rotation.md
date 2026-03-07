# Feature 018: Dual-Write Rotation

## Status: Planned
## Phase: 2 (v2.2)
## Priority: Medium

## Problem

When a key is rotated, all in-flight requests using the old key immediately fail. A web server with a 30-second connection pool timeout will fail every request for 30 seconds after rotation. API calls that were initiated before rotation but land at the provider after rotation get rejected. This makes zero-downtime rotation impossible.

## Solution

During a configurable transition period (default: 30 minutes), both the old and new key are considered valid. The vault proxy tries the new key first and falls back to the old key if the new one fails. After the transition period expires, the old key is purged. This enables seamless rotation without breaking in-flight requests.

## Implementation

### Files to Create/Modify

- `crates/pqvault-rotation-mcp/src/dual_write.rs` — Dual-write state management
- `crates/pqvault-proxy-mcp/src/proxy.rs` — Fallback logic for dual-write keys
- `crates/pqvault-core/src/models.rs` — Add dual-write fields to rotation metadata

### Data Model Changes

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DualWriteState {
    /// The new (primary) key value (encrypted)
    pub primary_value: String,
    /// The old (fallback) key value (encrypted)
    pub fallback_value: String,
    /// When dual-write mode started
    pub started_at: String,
    /// When dual-write mode ends (fallback purged)
    pub expires_at: String,
    /// Transition status
    pub status: DualWriteStatus,
    /// Count of requests served by primary key
    pub primary_hits: u64,
    /// Count of requests served by fallback key
    pub fallback_hits: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DualWriteStatus {
    Active,
    Completed,
    RolledBack,
}
```

### MCP Tools

```rust
// Tool: vault_dual_write_status
{
    "name": "vault_dual_write_status",
    "params": {},
    "returns": {
        "active_dual_writes": [
            {
                "key_name": "STRIPE_KEY",
                "started_at": "2025-01-15T10:00:00Z",
                "expires_at": "2025-01-15T10:30:00Z",
                "primary_hits": 45,
                "fallback_hits": 3,
                "time_remaining": "18 minutes"
            }
        ]
    }
}
```

### CLI Commands

```bash
pqvault rotate STRIPE_KEY --transition-period 30m
pqvault dual-write status
pqvault dual-write extend STRIPE_KEY --by 30m
pqvault dual-write complete STRIPE_KEY   # End early
```

## Core Implementation

```rust
// crates/pqvault-rotation-mcp/src/dual_write.rs

use chrono::{DateTime, Utc, Duration};

pub struct DualWriteManager;

impl DualWriteManager {
    pub fn start_dual_write(
        entry: &mut SecretEntry,
        new_encrypted_value: &str,
        transition_minutes: u32,
    ) {
        let now = Utc::now();
        let state = DualWriteState {
            primary_value: new_encrypted_value.to_string(),
            fallback_value: entry.encrypted_value.clone(),
            started_at: now.to_rfc3339(),
            expires_at: (now + Duration::minutes(transition_minutes as i64)).to_rfc3339(),
            status: DualWriteStatus::Active,
            primary_hits: 0,
            fallback_hits: 0,
        };

        entry.encrypted_value = new_encrypted_value.to_string();

        let metadata = entry.rotation_metadata
            .get_or_insert_with(RotationMetadata::default);
        metadata.dual_write_state = Some(state);
    }

    /// Get the appropriate key value, trying primary first
    pub fn resolve_value(
        entry: &SecretEntry,
        master_password: &str,
    ) -> Result<ResolvedValue> {
        let dw = match entry.rotation_metadata.as_ref().and_then(|m| m.dual_write_state.as_ref()) {
            Some(dw) if dw.status == DualWriteStatus::Active => dw,
            _ => {
                // No dual-write active, use current value
                let value = Vault::decrypt_value_static(&entry.encrypted_value, master_password)?;
                return Ok(ResolvedValue::Primary(value));
            }
        };

        // Check if dual-write has expired
        if let Ok(expires) = DateTime::parse_from_rfc3339(&dw.expires_at) {
            if Utc::now() > expires.with_timezone(&Utc) {
                let value = Vault::decrypt_value_static(&dw.primary_value, master_password)?;
                return Ok(ResolvedValue::Primary(value));
            }
        }

        let primary = Vault::decrypt_value_static(&dw.primary_value, master_password)?;
        let fallback = Vault::decrypt_value_static(&dw.fallback_value, master_password)?;

        Ok(ResolvedValue::DualWrite { primary, fallback })
    }

    pub fn complete_dual_write(entry: &mut SecretEntry) {
        if let Some(metadata) = entry.rotation_metadata.as_mut() {
            if let Some(dw) = metadata.dual_write_state.as_mut() {
                dw.status = DualWriteStatus::Completed;
            }
        }
    }

    pub fn is_expired(entry: &SecretEntry) -> bool {
        entry.rotation_metadata.as_ref()
            .and_then(|m| m.dual_write_state.as_ref())
            .and_then(|dw| DateTime::parse_from_rfc3339(&dw.expires_at).ok())
            .map(|exp| Utc::now() > exp.with_timezone(&Utc))
            .unwrap_or(true)
    }
}

pub enum ResolvedValue {
    Primary(String),
    DualWrite { primary: String, fallback: String },
}
```

### Proxy Integration

```rust
// In crates/pqvault-proxy-mcp/src/proxy.rs

async fn proxy_request_with_fallback(
    entry: &SecretEntry,
    request: &ProxyRequest,
    master_password: &str,
) -> Result<ProxyResponse> {
    match DualWriteManager::resolve_value(entry, master_password)? {
        ResolvedValue::Primary(key) => {
            forward_request(request, &key).await
        }
        ResolvedValue::DualWrite { primary, fallback } => {
            // Try primary first
            match forward_request(request, &primary).await {
                Ok(resp) if resp.status < 400 => Ok(resp),
                _ => {
                    // Fallback to old key
                    eprintln!("[proxy] Primary key failed, falling back for {}", entry.name);
                    forward_request(request, &fallback).await
                }
            }
        }
    }
}
```

## Dependencies

- No new dependencies
- Requires Feature 011 (Auto-Rotation Engine)
- Requires Feature 014 (Rotation Rollback) for rollback integration

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dual_write_resolves_both_keys() {
        let mut entry = create_test_entry("KEY");
        DualWriteManager::start_dual_write(&mut entry, "new_enc", 30);

        match DualWriteManager::resolve_value(&entry, "pass").unwrap() {
            ResolvedValue::DualWrite { primary, fallback } => {
                assert_ne!(primary, fallback);
            }
            _ => panic!("Expected DualWrite"),
        }
    }

    #[test]
    fn test_expired_dual_write_returns_primary_only() {
        let mut entry = create_test_entry("KEY");
        DualWriteManager::start_dual_write(&mut entry, "new_enc", 0); // 0 minutes = already expired

        assert!(DualWriteManager::is_expired(&entry));
    }

    #[test]
    fn test_complete_dual_write() {
        let mut entry = create_test_entry("KEY");
        DualWriteManager::start_dual_write(&mut entry, "new_enc", 30);
        DualWriteManager::complete_dual_write(&mut entry);

        let dw = entry.rotation_metadata.unwrap().dual_write_state.unwrap();
        assert_eq!(dw.status, DualWriteStatus::Completed);
    }
}
```

### Manual Verification

1. Rotate a key with transition period: `pqvault rotate KEY --transition-period 5m`
2. During transition, verify both keys work through proxy
3. After transition expires, verify only new key works
4. Check `pqvault dual-write status` during transition

## Example Usage

```bash
$ pqvault rotate STRIPE_KEY --transition-period 30m
Rotating STRIPE_KEY with 30-minute dual-write transition...
  New key generated and verified
  Dual-write mode: ACTIVE
  Both keys valid until: 2025-01-15T10:30:00Z

$ pqvault dual-write status
Active dual-write transitions:
  STRIPE_KEY  started 12m ago  expires in 18m  primary: 45 hits  fallback: 3 hits
```
