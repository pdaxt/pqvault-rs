# Feature 087: Keyboard Shortcuts

## Status: Planned
## Phase: 9 (v2.9)
## Priority: Low

## Problem

Power users managing large vaults through the web dashboard must rely entirely on
mouse interactions for navigation, search, and operations. This is slower than
keyboard-driven workflows and makes the dashboard less efficient for users who prefer
keyboard-first interfaces like Vim, terminal applications, or IDEs.

## Solution

Add Vim-inspired keyboard shortcuts to the web dashboard. Navigation (j/k), search
(/), key operations (r for rotate, d for delete), and global actions (? for help)
are all accessible via keyboard. A floating shortcut cheatsheet is toggled with `?`.
Shortcuts are disabled when input fields are focused to prevent conflicts.

## Implementation

### Files to Create/Modify

```
pqvault-web/
  static/
    js/
      shortcuts.js      # Keyboard shortcut registration and handling
    css/
      shortcuts.css     # Cheatsheet overlay styles
  templates/
    components/
      shortcut_help.html  # Keyboard shortcut cheatsheet overlay
```

### Data Model Changes

No backend changes. Keyboard shortcuts are entirely client-side.

```javascript
// shortcuts.js - Keyboard shortcut system
class ShortcutManager {
    constructor() {
        this.shortcuts = new Map();
        this.enabled = true;
        this.selectedIndex = -1;
        this.registerDefaults();
        this.listen();
    }

    registerDefaults() {
        // Navigation
        this.register('j', 'Move down', () => this.moveSelection(1));
        this.register('k', 'Move up', () => this.moveSelection(-1));
        this.register('ArrowDown', 'Move down', () => this.moveSelection(1));
        this.register('ArrowUp', 'Move up', () => this.moveSelection(-1));
        this.register('g', 'Go to top', () => this.goToTop());
        this.register('G', 'Go to bottom', () => this.goToBottom());

        // Search
        this.register('/', 'Focus search', (e) => {
            e.preventDefault();
            document.getElementById('search-input')?.focus();
        });
        this.register('Escape', 'Clear search / close modal', () => this.handleEscape());

        // Actions on selected key
        this.register('Enter', 'Open key detail', () => this.openSelected());
        this.register('r', 'Rotate selected key', () => this.rotateSelected());
        this.register('d', 'Delete selected key', () => this.deleteSelected());
        this.register('c', 'Copy selected key value', () => this.copySelected());
        this.register('e', 'Edit selected key', () => this.editSelected());

        // Global
        this.register('?', 'Show keyboard shortcuts', () => this.toggleHelp());
        this.register('n', 'New key', () => this.newKey());
        this.register('R', 'Refresh dashboard', () => location.reload());
    }

    register(key, description, handler) {
        this.shortcuts.set(key, { key, description, handler });
    }

    listen() {
        document.addEventListener('keydown', (e) => {
            // Disable shortcuts when typing in input fields
            const target = e.target;
            if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' ||
                target.tagName === 'SELECT' || target.isContentEditable) {
                if (e.key === 'Escape') {
                    target.blur();
                }
                return;
            }

            if (!this.enabled) return;

            const shortcut = this.shortcuts.get(e.key);
            if (shortcut) {
                shortcut.handler(e);
            }
        });
    }

    moveSelection(delta) {
        const rows = document.querySelectorAll('.key-row');
        if (rows.length === 0) return;

        // Remove previous selection
        rows.forEach(r => r.classList.remove('keyboard-selected'));

        this.selectedIndex = Math.max(0, Math.min(
            this.selectedIndex + delta,
            rows.length - 1
        ));

        const selected = rows[this.selectedIndex];
        selected.classList.add('keyboard-selected');
        selected.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }

    goToTop() {
        this.selectedIndex = -1;
        this.moveSelection(1); // Will set to 0
    }

    goToBottom() {
        const rows = document.querySelectorAll('.key-row');
        this.selectedIndex = rows.length - 2;
        this.moveSelection(1);
    }

    openSelected() {
        const selected = document.querySelector('.key-row.keyboard-selected');
        if (selected) {
            const keyName = selected.dataset.key;
            window.location.href = `/keys/${keyName}`;
        }
    }

    rotateSelected() {
        const selected = document.querySelector('.key-row.keyboard-selected');
        if (selected) {
            const keyName = selected.dataset.key;
            if (confirm(`Rotate ${keyName}?`)) {
                fetch(`/api/keys/${keyName}/rotate`, { method: 'POST' })
                    .then(() => location.reload());
            }
        }
    }

    deleteSelected() {
        const selected = document.querySelector('.key-row.keyboard-selected');
        if (selected) {
            const keyName = selected.dataset.key;
            if (confirm(`Delete ${keyName}? This cannot be undone.`)) {
                fetch(`/api/keys/${keyName}`, { method: 'DELETE' })
                    .then(() => location.reload());
            }
        }
    }

    copySelected() {
        const selected = document.querySelector('.key-row.keyboard-selected');
        if (selected) {
            const keyName = selected.dataset.key;
            fetch(`/api/keys/${keyName}/value`)
                .then(r => r.text())
                .then(value => {
                    navigator.clipboard.writeText(value);
                    this.showToast('Copied to clipboard');
                });
        }
    }

    toggleHelp() {
        const overlay = document.getElementById('shortcut-help');
        overlay.classList.toggle('visible');
    }

    handleEscape() {
        // Close any open modals first
        const modal = document.querySelector('.modal.visible');
        if (modal) {
            modal.classList.remove('visible');
            return;
        }
        // Clear search
        const search = document.getElementById('search-input');
        if (search && search.value) {
            search.value = '';
            search.dispatchEvent(new Event('input'));
        }
    }
}

const shortcuts = new ShortcutManager();
```

### MCP Tools

No new MCP tools.

### CLI Commands

No new CLI commands. CLI has its own keyboard handling in the TUI (Feature 061).

### Web UI Changes

Cheatsheet overlay and visual selection indicators.

## Dependencies

No new dependencies.

## Testing

### Unit Tests (JavaScript)

```javascript
describe('ShortcutManager', () => {
    test('registers default shortcuts', () => {
        const sm = new ShortcutManager();
        expect(sm.shortcuts.has('j')).toBe(true);
        expect(sm.shortcuts.has('k')).toBe(true);
        expect(sm.shortcuts.has('/')).toBe(true);
        expect(sm.shortcuts.has('?')).toBe(true);
    });

    test('moveSelection wraps at bounds', () => {
        document.body.innerHTML = `
            <div class="key-row" data-key="A"></div>
            <div class="key-row" data-key="B"></div>
        `;
        const sm = new ShortcutManager();
        sm.moveSelection(1); // 0
        sm.moveSelection(1); // 1
        sm.moveSelection(1); // stays at 1 (no wrap)
        expect(sm.selectedIndex).toBe(1);
    });

    test('shortcuts disabled in input fields', () => {
        const input = document.createElement('input');
        document.body.appendChild(input);
        input.focus();
        const event = new KeyboardEvent('keydown', { key: 'j' });
        // Should not trigger navigation when input is focused
    });

    test('escape clears search', () => {
        document.body.innerHTML = '<input id="search-input" value="test">';
        const sm = new ShortcutManager();
        sm.handleEscape();
        expect(document.getElementById('search-input').value).toBe('');
    });
});
```

### Integration Tests

```rust
#[tokio::test]
async fn test_dashboard_includes_shortcuts_js() {
    let app = test_app().await;
    let response = app.get("/dashboard").await;
    let body = response.text().await;
    assert!(body.contains("shortcuts.js"));
    assert!(body.contains("shortcut-help"));
}
```

## Example Usage

```
Dashboard with keyboard shortcuts:

Press ? to see:

┌─── Keyboard Shortcuts ──────────────────────┐
│                                              │
│  Navigation                                  │
│  j / Down    Move selection down             │
│  k / Up      Move selection up               │
│  g           Go to top                       │
│  G           Go to bottom                    │
│  Enter       Open key detail                 │
│                                              │
│  Search                                      │
│  /           Focus search bar                │
│  Esc         Clear search / close modal      │
│                                              │
│  Actions (on selected key)                   │
│  r           Rotate key                      │
│  d           Delete key (with confirmation)  │
│  c           Copy value to clipboard         │
│  e           Edit key value                  │
│                                              │
│  Global                                      │
│  n           Create new key                  │
│  R           Refresh dashboard               │
│  ?           Toggle this help                │
│                                              │
│                           [Press ? to close] │
└──────────────────────────────────────────────┘

Navigation in action:

│ STRIPE_SECRET_KEY    payment   healthy  │
│▸AWS_ACCESS_KEY_ID    cloud     healthy  │ ← keyboard selected (highlighted)
│ DATABASE_URL         database  warning  │
│ REDIS_URL            database  healthy  │
```
