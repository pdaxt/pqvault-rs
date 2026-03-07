# Feature 081: Dark/Light Theme Toggle

## Status: Planned
## Phase: 9 (v2.9)
## Priority: Medium

## Problem

The PQVault web dashboard currently uses a single hardcoded color scheme. Users working
in dark environments find bright interfaces straining, while users in bright offices
may prefer light themes for readability. The lack of theme support also limits
accessibility compliance and prevents the dashboard from matching the user's system
preferences.

## Solution

Implement a dark/light theme toggle for the web dashboard using CSS custom properties.
The theme preference is stored in localStorage and respects the system's
`prefers-color-scheme` media query as the default. A toggle button in the header allows
manual switching. All dashboard components use theme-aware color tokens instead of
hardcoded values.

## Implementation

### Files to Create/Modify

```
pqvault-web/
  static/
    css/
      theme.css        # CSS custom properties for light/dark themes
      components.css   # Updated components using theme tokens
  templates/
    components/
      theme_toggle.html  # Toggle button component
    layout.html          # Updated to include theme system
  src/
    routes/
      preferences.rs     # User preference API endpoint
```

### Data Model Changes

No backend data model changes. Theme preference is client-side only (localStorage).

```css
/* theme.css - CSS Custom Properties */

:root {
    /* Light theme (default) */
    --bg-primary: #ffffff;
    --bg-secondary: #f8f9fa;
    --bg-tertiary: #e9ecef;
    --text-primary: #212529;
    --text-secondary: #6c757d;
    --text-muted: #adb5bd;
    --border-color: #dee2e6;
    --accent-primary: #2563eb;
    --accent-success: #16a34a;
    --accent-warning: #d97706;
    --accent-danger: #dc2626;
    --card-bg: #ffffff;
    --card-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    --input-bg: #ffffff;
    --input-border: #ced4da;
    --code-bg: #f1f3f5;
    --table-stripe: #f8f9fa;
    --scrollbar-track: #f1f3f5;
    --scrollbar-thumb: #ced4da;
}

[data-theme="dark"] {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-tertiary: #334155;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --border-color: #334155;
    --accent-primary: #3b82f6;
    --accent-success: #22c55e;
    --accent-warning: #f59e0b;
    --accent-danger: #ef4444;
    --card-bg: #1e293b;
    --card-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
    --input-bg: #1e293b;
    --input-border: #475569;
    --code-bg: #1e293b;
    --table-stripe: #1e293b;
    --scrollbar-track: #1e293b;
    --scrollbar-thumb: #475569;
}
```

```javascript
// theme.js - Theme toggle logic
class ThemeManager {
    constructor() {
        this.storageKey = 'pqvault-theme';
        this.init();
    }

    init() {
        const saved = localStorage.getItem(this.storageKey);
        if (saved) {
            this.setTheme(saved);
        } else {
            // Respect system preference
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            this.setTheme(prefersDark ? 'dark' : 'light');
        }

        // Listen for system preference changes
        window.matchMedia('(prefers-color-scheme: dark)')
            .addEventListener('change', (e) => {
                if (!localStorage.getItem(this.storageKey)) {
                    this.setTheme(e.matches ? 'dark' : 'light');
                }
            });
    }

    setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem(this.storageKey, theme);
        this.updateToggleButton(theme);
    }

    toggle() {
        const current = document.documentElement.getAttribute('data-theme');
        this.setTheme(current === 'dark' ? 'light' : 'dark');
    }

    updateToggleButton(theme) {
        const btn = document.getElementById('theme-toggle');
        if (btn) {
            btn.setAttribute('aria-label',
                theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
            btn.textContent = theme === 'dark' ? 'Light' : 'Dark';
        }
    }
}

const themeManager = new ThemeManager();
```

### MCP Tools

No new MCP tools. Theme is a client-side web feature.

### CLI Commands

No CLI changes. The CLI already respects `NO_COLOR` environment variable.

### Web UI Changes

All existing CSS updated to use theme tokens:

```css
/* Before */
.dashboard-card {
    background: #ffffff;
    color: #333333;
    border: 1px solid #e0e0e0;
}

/* After */
.dashboard-card {
    background: var(--card-bg);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    box-shadow: var(--card-shadow);
}

.key-list-row:nth-child(even) {
    background: var(--table-stripe);
}

.health-badge-good {
    color: var(--accent-success);
}

.health-badge-warning {
    color: var(--accent-warning);
}

.health-badge-critical {
    color: var(--accent-danger);
}
```

Toggle button in header:

```html
<!-- theme_toggle.html -->
<button
    id="theme-toggle"
    onclick="themeManager.toggle()"
    class="theme-toggle-btn"
    aria-label="Toggle theme"
    title="Toggle dark/light theme">
    <span class="theme-icon"></span>
</button>
```

## Dependencies

No new Rust dependencies. Uses CSS custom properties and vanilla JavaScript.

## Testing

### Unit Tests (JavaScript)

```javascript
describe('ThemeManager', () => {
    beforeEach(() => {
        localStorage.clear();
        document.documentElement.removeAttribute('data-theme');
    });

    test('defaults to system preference', () => {
        // Mock prefers-color-scheme: dark
        window.matchMedia = jest.fn().mockReturnValue({
            matches: true,
            addEventListener: jest.fn(),
        });
        const tm = new ThemeManager();
        expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    });

    test('restores saved preference', () => {
        localStorage.setItem('pqvault-theme', 'dark');
        const tm = new ThemeManager();
        expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    });

    test('toggle switches theme', () => {
        const tm = new ThemeManager();
        tm.setTheme('light');
        tm.toggle();
        expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
        tm.toggle();
        expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    });

    test('persists preference to localStorage', () => {
        const tm = new ThemeManager();
        tm.setTheme('dark');
        expect(localStorage.getItem('pqvault-theme')).toBe('dark');
    });
});
```

### Integration Tests (Rust)

```rust
#[tokio::test]
async fn test_dashboard_serves_theme_css() {
    let app = test_app().await;
    let response = app.get("/static/css/theme.css").await;
    assert_eq!(response.status(), 200);
    let body = response.text().await;
    assert!(body.contains("--bg-primary"));
    assert!(body.contains("[data-theme=\"dark\"]"));
}

#[tokio::test]
async fn test_layout_includes_theme_toggle() {
    let app = test_app().await;
    let response = app.get("/dashboard").await;
    let body = response.text().await;
    assert!(body.contains("theme-toggle"));
    assert!(body.contains("themeManager"));
}
```

## Example Usage

```
Dashboard Header:
┌────────────────────────────────────────────────────┐
│  PQVault Dashboard              [Dark] [Settings]  │
└────────────────────────────────────────────────────┘

After clicking [Dark]:
┌────────────────────────────────────────────────────┐
│  PQVault Dashboard              [Light] [Settings] │  <- dark bg
└────────────────────────────────────────────────────┘

The theme persists across page reloads and browser sessions.
System preference (prefers-color-scheme) is respected as default.
```
