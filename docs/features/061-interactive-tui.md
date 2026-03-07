# Feature 061: Interactive TUI

## Status: Done
## Phase: 7 (v2.7)
## Priority: High

## Problem

The CLI currently operates in a request-response mode where users must know the exact key
name and subcommand to interact with their vault. For power users managing 50+ secrets,
this creates friction — they need to remember key names, run `pqvault list` repeatedly,
and chain multiple commands to accomplish simple tasks like browsing and editing.

## Solution

Build a full-screen terminal UI using ratatui and crossterm that provides an interactive
browsing experience. Users can navigate keys with arrow keys, search inline, preview
values, and perform operations (rotate, delete, edit) without leaving the TUI. This
turns PQVault from a command-line tool into a terminal application.

## Implementation

### Files to Create/Modify

```
pqvault-cli/
  src/
    tui/
      mod.rs          # TUI module root, App state machine
      app.rs          # Application state and event loop
      ui.rs           # Layout rendering with ratatui widgets
      events.rs       # Crossterm event handling (key/mouse)
      widgets/
        mod.rs
        key_list.rs   # Scrollable key list with selection
        preview.rs    # Secret value preview pane
        search.rs     # Inline fuzzy search bar
        status.rs     # Bottom status bar with shortcuts
        confirm.rs    # Confirmation dialog for destructive ops
    commands/
      tui.rs          # `pqvault tui` command entry point
```

### Data Model Changes

No schema changes required. The TUI reads from the existing vault storage layer
via `pqvault-core` APIs. A transient in-memory `AppState` struct holds UI state:

```rust
use ratatui::widgets::TableState;

pub struct AppState {
    /// All keys loaded from vault
    pub keys: Vec<KeyEntry>,
    /// Filtered keys after search
    pub filtered: Vec<usize>,
    /// Table selection state
    pub table_state: TableState,
    /// Current search query
    pub search_query: String,
    /// Whether search bar is active
    pub search_mode: bool,
    /// Current view panel
    pub active_panel: Panel,
    /// Selected key detail (if any)
    pub preview_key: Option<String>,
    /// Confirmation dialog state
    pub confirm: Option<ConfirmAction>,
}

pub enum Panel {
    KeyList,
    Preview,
    Search,
}

pub enum ConfirmAction {
    Delete(String),
    Rotate(String),
    Overwrite { key: String, new_value: String },
}
```

### MCP Tools

No new MCP tools. The TUI is a local-only CLI feature that calls into `pqvault-core`
directly. However, it will display data fetched by MCP tools (health status, audit
entries) if those crates are available.

### CLI Commands

```bash
# Launch the interactive TUI
pqvault tui

# Launch TUI with a specific vault
pqvault tui --vault ~/my-project/.pqvault

# Launch TUI filtered to a category
pqvault tui --category cloud

# Launch in read-only mode (no edits allowed)
pqvault tui --readonly
```

Command registration in clap:

```rust
#[derive(Subcommand)]
pub enum Commands {
    /// Launch interactive terminal UI
    Tui(TuiArgs),
    // ... existing commands
}

#[derive(Args)]
pub struct TuiArgs {
    /// Path to vault directory
    #[arg(long)]
    vault: Option<PathBuf>,

    /// Filter to specific category
    #[arg(long)]
    category: Option<String>,

    /// Disable all write operations
    #[arg(long, default_value_t = false)]
    readonly: bool,
}
```

### Web UI Changes

None. This is a terminal-only feature.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `ratatui` | 0.26 | Terminal UI framework (successor to tui-rs) |
| `crossterm` | 0.27 | Cross-platform terminal manipulation |
| `unicode-width` | 0.1 | Correct column width for Unicode characters |

Add to `pqvault-cli/Cargo.toml`:

```toml
[dependencies]
ratatui = { version = "0.26", features = ["crossterm"] }
crossterm = "0.27"
unicode-width = "0.1"
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_filter() {
        let mut app = AppState::new(vec![
            key_entry("STRIPE_SECRET_KEY"),
            key_entry("AWS_ACCESS_KEY"),
            key_entry("DATABASE_URL"),
        ]);
        app.apply_search("stripe");
        assert_eq!(app.filtered.len(), 1);
        assert_eq!(app.keys[app.filtered[0]].name, "STRIPE_SECRET_KEY");
    }

    #[test]
    fn test_navigation_wraps() {
        let mut app = AppState::new(vec![
            key_entry("KEY_A"),
            key_entry("KEY_B"),
            key_entry("KEY_C"),
        ]);
        app.select_next(); // 0 -> 1
        app.select_next(); // 1 -> 2
        app.select_next(); // 2 -> 0 (wrap)
        assert_eq!(app.selected_index(), 0);
    }

    #[test]
    fn test_readonly_blocks_delete() {
        let mut app = AppState::new_readonly(vec![key_entry("KEY_A")]);
        let result = app.request_delete("KEY_A");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Read-only mode");
    }

    #[test]
    fn test_confirm_dialog_cancel() {
        let mut app = AppState::new(vec![key_entry("KEY_A")]);
        app.request_delete("KEY_A").unwrap();
        assert!(app.confirm.is_some());
        app.cancel_confirm();
        assert!(app.confirm.is_none());
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_tui_loads_vault_keys() {
    let vault = test_vault_with_keys(&["API_KEY", "DB_URL", "SECRET"]).await;
    let app = AppState::from_vault(&vault).await.unwrap();
    assert_eq!(app.keys.len(), 3);
}

#[tokio::test]
async fn test_tui_inline_edit_saves() {
    let vault = test_vault_with_keys(&["API_KEY"]).await;
    let mut app = AppState::from_vault(&vault).await.unwrap();
    app.edit_selected_value("new-value-123").await.unwrap();
    let stored = vault.get("API_KEY").await.unwrap();
    assert_eq!(stored.value, "new-value-123");
}
```

## Example Usage

```
$ pqvault tui

┌─ PQVault ─────────────────────────────────────────────┐
│ Search: _                                    [/] search│
├───────────────────────────────┬────────────────────────┤
│ Key Name            Category  │ Preview               │
│───────────────────────────────│────────────────────────│
│▸STRIPE_SECRET_KEY   payment   │ sk_live_51N...████████ │
│ STRIPE_PUBLISHABLE  payment   │                        │
│ AWS_ACCESS_KEY_ID   cloud     │ Provider: Stripe       │
│ AWS_SECRET_KEY      cloud     │ Created:  2025-01-15   │
│ DATABASE_URL        database  │ Rotated:  2025-03-01   │
│ REDIS_URL           database  │ Expires:  2025-06-01   │
│ GITHUB_TOKEN        vcs       │ Health:   ● Good       │
│ SENTRY_DSN          monitor   │                        │
├───────────────────────────────┴────────────────────────┤
│ ↑↓ navigate  Enter preview  r rotate  d delete  q quit│
└───────────────────────────────────────────────────────-┘
```

Keyboard shortcuts:
- `j/k` or `↑/↓` — Navigate key list
- `/` — Activate search mode
- `Enter` — Toggle value preview
- `e` — Edit selected key value
- `r` — Rotate selected key
- `d` — Delete (with confirmation)
- `c` — Copy value to clipboard
- `Tab` — Switch between panels
- `q` or `Esc` — Quit TUI
