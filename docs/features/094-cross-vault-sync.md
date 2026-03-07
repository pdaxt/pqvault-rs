# Feature 094: Cross-Vault Sync

## Status: Done
## Phase: 10 (v3.0)
## Priority: Medium

## Problem

Organizations often maintain separate vaults: personal developer vaults, team/project
vaults, and infrastructure vaults. Shared secrets like database URLs or API keys must
be manually duplicated across vaults, leading to version drift. When a key is rotated
in one vault, the copies in other vaults become stale, causing hard-to-diagnose
integration failures.

## Solution

Implement selective cross-vault synchronization where specific keys can be linked
between vaults. A key in a team vault can be designated as the "source of truth"
and synced to personal vaults as read-only copies. Changes propagate automatically
or on-demand, with conflict detection for bidirectional sync scenarios.

## Implementation

### Files to Create/Modify

```
pqvault-sync-mcp/
  src/
    cross_vault/
      mod.rs           # Cross-vault sync module root
      link.rs          # Key linking between vaults
      propagator.rs    # Change propagation engine
      conflict.rs      # Conflict detection and resolution
      transport.rs     # Encrypted transport between vaults
    tools/
      vault_link.rs    # MCP tool: link keys between vaults
      vault_sync.rs    # MCP tool: sync linked keys
```

### Data Model Changes

```rust
/// A link between a key in two vaults
#[derive(Serialize, Deserialize, Clone)]
pub struct VaultLink {
    pub link_id: String,
    pub source_vault: VaultRef,
    pub target_vault: VaultRef,
    pub key_name: String,
    pub direction: SyncDirection,
    pub target_key_name: Option<String>,  // If renamed in target
    pub auto_sync: bool,
    pub created_at: DateTime<Utc>,
    pub last_synced: Option<DateTime<Utc>>,
    pub last_sync_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultRef {
    pub vault_id: String,
    pub vault_path: PathBuf,
    pub vault_name: String,
    pub vault_type: VaultType,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum VaultType {
    Personal,
    Team,
    Infrastructure,
    Project(String),
}

#[derive(Serialize, Deserialize, Clone)]
pub enum SyncDirection {
    SourceToTarget,   // One-way: source is truth
    TargetToSource,   // One-way: target is truth
    Bidirectional,    // Two-way with conflict resolution
}

pub struct CrossVaultSync {
    links: Vec<VaultLink>,
}

impl CrossVaultSync {
    pub async fn sync_link(&self, link: &VaultLink) -> Result<SyncResult> {
        let source_vault = open_vault(&link.source_vault).await?;
        let target_vault = open_vault(&link.target_vault).await?;

        let source_value = source_vault.get(&link.key_name).await?;
        let source_hash = sha256_hex(&source_value.value);

        let target_key = link.target_key_name.as_deref().unwrap_or(&link.key_name);

        match link.direction {
            SyncDirection::SourceToTarget => {
                if Some(&source_hash) != link.last_sync_hash.as_ref() {
                    target_vault.set(target_key, &source_value.value).await?;
                    Ok(SyncResult::Updated {
                        key: target_key.to_string(),
                        direction: "source -> target".into(),
                    })
                } else {
                    Ok(SyncResult::NoChange)
                }
            }
            SyncDirection::Bidirectional => {
                let target_value = target_vault.get(target_key).await;
                match target_value {
                    Ok(tv) => {
                        let target_hash = sha256_hex(&tv.value);
                        if source_hash == target_hash {
                            Ok(SyncResult::NoChange)
                        } else if link.last_sync_hash.as_deref() == Some(&source_hash) {
                            // Source unchanged, target changed — pull
                            source_vault.set(&link.key_name, &tv.value).await?;
                            Ok(SyncResult::Updated {
                                key: link.key_name.clone(),
                                direction: "target -> source".into(),
                            })
                        } else if link.last_sync_hash.as_deref() == Some(&target_hash) {
                            // Target unchanged, source changed — push
                            target_vault.set(target_key, &source_value.value).await?;
                            Ok(SyncResult::Updated {
                                key: target_key.to_string(),
                                direction: "source -> target".into(),
                            })
                        } else {
                            // Both changed — conflict
                            Ok(SyncResult::Conflict {
                                key: link.key_name.clone(),
                                source_hash,
                                target_hash,
                            })
                        }
                    }
                    Err(_) => {
                        target_vault.set(target_key, &source_value.value).await?;
                        Ok(SyncResult::Created {
                            key: target_key.to_string(),
                        })
                    }
                }
            }
            _ => todo!(),
        }
    }
}

pub enum SyncResult {
    NoChange,
    Created { key: String },
    Updated { key: String, direction: String },
    Conflict { key: String, source_hash: String, target_hash: String },
}
```

### MCP Tools

```rust
#[tool(description = "Link a key between two vaults for synchronization")]
async fn vault_link(
    /// Source vault path
    source_vault: String,
    /// Target vault path
    target_vault: String,
    /// Key name to link
    key: String,
    /// Sync direction: push, pull, bidirectional
    #[arg(default = "push")]
    direction: String,
    /// Enable automatic sync on change
    #[arg(default = false)]
    auto_sync: bool,
) -> Result<CallToolResult> { /* ... */ }

#[tool(description = "Sync all linked keys between vaults")]
async fn vault_sync(
    /// Only sync specific vault pair
    vault: Option<String>,
    /// Dry run
    #[arg(default = false)]
    dry_run: bool,
) -> Result<CallToolResult> { /* ... */ }
```

### CLI Commands

```bash
# Link a key from team vault to personal vault
pqvault vault link ~/team-vault ~/my-vault --key DATABASE_URL --direction push

# Sync all linked keys
pqvault vault sync

# Show linked keys
pqvault vault links

# Unlink a key
pqvault vault unlink DATABASE_URL --vault ~/my-vault
```

### Web UI Changes

None in this phase. Cross-vault management is CLI/MCP only.

## Dependencies

No new dependencies. Uses existing encryption and vault access APIs.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_creation() {
        let link = VaultLink {
            link_id: "test-link".into(),
            source_vault: VaultRef { vault_id: "a".into(), vault_path: "/a".into(), vault_name: "team".into(), vault_type: VaultType::Team },
            target_vault: VaultRef { vault_id: "b".into(), vault_path: "/b".into(), vault_name: "personal".into(), vault_type: VaultType::Personal },
            key_name: "DB_URL".into(),
            direction: SyncDirection::SourceToTarget,
            target_key_name: None,
            auto_sync: true,
            created_at: Utc::now(),
            last_synced: None,
            last_sync_hash: None,
        };
        assert!(link.auto_sync);
        assert!(link.target_key_name.is_none());
    }

    #[test]
    fn test_conflict_detection() {
        let link = VaultLink {
            last_sync_hash: Some("old_hash".into()),
            ..mock_link()
        };
        // Both source and target have changed from old_hash
        let source_hash = "new_source_hash";
        let target_hash = "new_target_hash";
        let is_conflict = link.last_sync_hash.as_deref() != Some(source_hash)
            && link.last_sync_hash.as_deref() != Some(target_hash);
        assert!(is_conflict);
    }

    #[test]
    fn test_no_change_detection() {
        let source_hash = "same_hash";
        let target_hash = "same_hash";
        assert_eq!(source_hash, target_hash);
    }
}
```

## Example Usage

```
$ pqvault vault link ~/team-vault ~/my-vault --key DATABASE_URL --direction push

  Vault Link Created
  ────────────────────

  Source: ~/team-vault (team)
  Target: ~/my-vault (personal)
  Key: DATABASE_URL
  Direction: team → personal (one-way)
  Auto-sync: disabled

$ pqvault vault sync

  Cross-Vault Sync
  ────────────────────────────────

  Link                Key              Status
  ──────────────────  ───────────────  ────────
  team → personal     DATABASE_URL     UPDATED (value changed)
  team → personal     REDIS_URL        No change
  infra → team        AWS_KEY          CONFLICT (resolve manually)

  1 updated, 1 unchanged, 1 conflict
```
