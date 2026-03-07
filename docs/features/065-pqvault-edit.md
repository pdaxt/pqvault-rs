# Feature 065: pqvault edit

## Status: Done
## Phase: 7 (v2.7)
## Priority: Medium

## Problem

Updating a secret value requires typing the entire new value on the command line:
`pqvault set KEY "long-complex-value-here"`. This is cumbersome for multi-line secrets
like certificates, JSON service account keys, or SSH private keys. It also exposes
the value in shell history and makes editing existing values error-prone since users
cannot see the current value while typing the replacement.

## Solution

Implement `pqvault edit KEY` which decrypts the current value into a temporary file,
opens it in the user's `$EDITOR` (defaulting to `vi`), and on save automatically
encrypts and stores the updated value. The temp file is securely wiped after use.
This provides a familiar editing workflow identical to `kubectl edit` or `git commit`.

## Implementation

### Files to Create/Modify

```
pqvault-cli/
  src/
    commands/
      edit.rs          # Edit command: decrypt → tmp file → $EDITOR → encrypt
    util/
      tempfile.rs      # Secure temporary file with zeroization on drop
      editor.rs        # $EDITOR detection and spawning
```

### Data Model Changes

No persistent schema changes. Transient struct for edit session:

```rust
use std::process::Command;
use tempfile::NamedTempFile;
use zeroize::Zeroize;

pub struct EditSession {
    /// Key being edited
    pub key_name: String,
    /// Original value hash (to detect no-change)
    pub original_hash: String,
    /// Temp file path
    pub temp_path: PathBuf,
    /// Editor command
    pub editor: String,
}

impl EditSession {
    pub fn new(key_name: &str, current_value: &str) -> Result<Self> {
        let editor = std::env::var("EDITOR")
            .or_else(|_| std::env::var("VISUAL"))
            .unwrap_or_else(|_| "vi".to_string());

        let mut tmp = NamedTempFile::new()?;
        // Set restrictive permissions before writing
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))?;
        }
        std::io::Write::write_all(&mut tmp, current_value.as_bytes())?;

        let original_hash = sha256_hex(current_value);
        let temp_path = tmp.into_temp_path().keep()?;

        Ok(Self {
            key_name: key_name.to_string(),
            original_hash,
            temp_path,
            editor,
        })
    }

    pub fn launch_editor(&self) -> Result<()> {
        let status = Command::new(&self.editor)
            .arg(&self.temp_path)
            .status()?;
        if !status.success() {
            return Err(anyhow!("Editor exited with non-zero status"));
        }
        Ok(())
    }

    pub fn read_edited_value(&self) -> Result<String> {
        let content = std::fs::read_to_string(&self.temp_path)?;
        Ok(content)
    }

    pub fn has_changes(&self, new_value: &str) -> bool {
        sha256_hex(new_value) != self.original_hash
    }

    pub fn cleanup(&self) {
        // Overwrite file with zeros before deletion
        if let Ok(len) = std::fs::metadata(&self.temp_path).map(|m| m.len()) {
            let zeros = vec![0u8; len as usize];
            let _ = std::fs::write(&self.temp_path, &zeros);
        }
        let _ = std::fs::remove_file(&self.temp_path);
    }
}

impl Drop for EditSession {
    fn drop(&mut self) {
        self.cleanup();
    }
}
```

### MCP Tools

No new MCP tools. Editing is interactive and terminal-only.

### CLI Commands

```bash
# Edit a secret in $EDITOR
pqvault edit STRIPE_SECRET_KEY

# Edit with a specific editor
EDITOR=nano pqvault edit DATABASE_URL

# Create a new key by editing (if key doesn't exist)
pqvault edit NEW_KEY --create

# Edit without confirmation prompt
pqvault edit API_KEY --no-confirm
```

Command definition:

```rust
#[derive(Args)]
pub struct EditArgs {
    /// Key name to edit
    pub key: String,

    /// Create the key if it doesn't exist
    #[arg(long, default_value_t = false)]
    create: bool,

    /// Skip confirmation prompt after editing
    #[arg(long, default_value_t = false)]
    no_confirm: bool,

    /// Override editor (default: $EDITOR or vi)
    #[arg(long)]
    editor: Option<String>,
}

pub async fn handle_edit(args: EditArgs, vault: &mut Vault) -> Result<()> {
    let current_value = match vault.get(&args.key).await {
        Ok(val) => val.value,
        Err(_) if args.create => String::new(),
        Err(e) => return Err(e),
    };

    let session = EditSession::new(&args.key, &current_value)?;
    if let Some(editor) = &args.editor {
        session.editor = editor.clone();
    }

    println!("Opening {} in {}...", args.key, session.editor);
    session.launch_editor()?;

    let new_value = session.read_edited_value()?;

    if !session.has_changes(&new_value) {
        println!("No changes detected. Vault unchanged.");
        return Ok(());
    }

    if !args.no_confirm {
        let confirmed = prompt_confirm(&format!(
            "Save changes to {}? (value changed, {} bytes → {} bytes)",
            args.key,
            current_value.len(),
            new_value.len()
        ))?;
        if !confirmed {
            println!("Edit cancelled.");
            return Ok(());
        }
    }

    vault.set(&args.key, &new_value).await?;
    println!("Updated {} successfully.", args.key);
    Ok(())
}
```

### Web UI Changes

None. Web UI will have its own inline editor in Feature 082 (Key Detail Page).

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `tempfile` | 3 | Secure temp file creation (likely already in workspace) |
| `zeroize` | 1 | Memory-safe cleanup of temp file contents |

The `zeroize` crate is also needed for Feature 080 (Memory Zeroization) and
can be added now as a workspace dependency.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edit_session_creates_temp_file() {
        let session = EditSession::new("TEST_KEY", "secret_value").unwrap();
        assert!(session.temp_path.exists());
        let content = std::fs::read_to_string(&session.temp_path).unwrap();
        assert_eq!(content, "secret_value");
    }

    #[test]
    fn test_edit_session_restrictive_permissions() {
        let session = EditSession::new("TEST_KEY", "value").unwrap();
        let metadata = std::fs::metadata(&session.temp_path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_has_changes_true() {
        let session = EditSession::new("KEY", "original").unwrap();
        assert!(session.has_changes("modified"));
    }

    #[test]
    fn test_has_changes_false() {
        let session = EditSession::new("KEY", "same_value").unwrap();
        assert!(!session.has_changes("same_value"));
    }

    #[test]
    fn test_cleanup_removes_file() {
        let session = EditSession::new("KEY", "secret").unwrap();
        let path = session.temp_path.clone();
        session.cleanup();
        assert!(!path.exists());
    }

    #[test]
    fn test_cleanup_overwrites_before_delete() {
        let session = EditSession::new("KEY", "sensitive_data").unwrap();
        let path = session.temp_path.clone();
        // Write known content
        std::fs::write(&path, "sensitive_data").unwrap();
        session.cleanup();
        // File should be gone; if it existed it would be zeroed
        assert!(!path.exists());
    }

    #[test]
    fn test_editor_detection() {
        std::env::set_var("EDITOR", "nano");
        let session = EditSession::new("KEY", "val").unwrap();
        assert_eq!(session.editor, "nano");
        std::env::remove_var("EDITOR");
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_edit_updates_vault() {
    let mut vault = test_vault_with_keys(&[("API_KEY", "old_value")]).await;
    // Simulate editing: write new value to temp file
    let session = EditSession::new("API_KEY", "old_value").unwrap();
    std::fs::write(&session.temp_path, "new_value").unwrap();
    let new_value = session.read_edited_value().unwrap();
    vault.set("API_KEY", &new_value).await.unwrap();
    assert_eq!(vault.get("API_KEY").await.unwrap().value, "new_value");
}

#[tokio::test]
async fn test_edit_no_change_skips_write() {
    let mut vault = test_vault_with_keys(&[("API_KEY", "same")]).await;
    let session = EditSession::new("API_KEY", "same").unwrap();
    // Don't modify the temp file
    let new_value = session.read_edited_value().unwrap();
    assert!(!session.has_changes(&new_value));
}
```

## Example Usage

```
$ pqvault edit DATABASE_URL
  Opening DATABASE_URL in vim...
  # Editor opens with current value:
  # postgres://user:password@host:5432/dbname
  # User modifies to:
  # postgres://user:new_password@new-host:5432/dbname
  # Saves and exits editor

  Save changes to DATABASE_URL? (value changed, 44 bytes → 52 bytes) [y/N]: y
  Updated DATABASE_URL successfully.

$ pqvault edit GCP_SERVICE_ACCOUNT --create
  Opening GCP_SERVICE_ACCOUNT in vim...
  # Editor opens empty; user pastes JSON service account key
  # Saves and exits

  Save changes to GCP_SERVICE_ACCOUNT? (new key, 2048 bytes) [y/N]: y
  Created GCP_SERVICE_ACCOUNT successfully.

$ pqvault edit API_KEY
  Opening API_KEY in vim...
  # User exits without saving
  No changes detected. Vault unchanged.
```
