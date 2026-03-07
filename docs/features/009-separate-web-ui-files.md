# Feature 009: Separate Web UI Files

## Status: Planned
## Phase: 1 (v2.1)
## Priority: Medium

## Problem

The web dashboard's entire HTML, CSS, and JavaScript is embedded as a 560-line string literal inside `web.rs`. Every UI change — even fixing a typo in a button label — requires recompiling the entire Rust binary. This makes rapid UI iteration impossible and bloats the source file with non-Rust content. Frontend developers cannot contribute without setting up a Rust toolchain.

## Solution

Extract all HTML, CSS, and JavaScript to separate static files served by `tower-http`'s `ServeDir`. The static files live alongside the crate source in `crates/pqvault-web/static/`. During development, files are served directly from disk (hot-reload). For release builds, files are embedded via `include_dir` for a single-binary deployment.

## Implementation

### Files to Create/Modify

- `crates/pqvault-web/static/index.html` — Main dashboard page
- `crates/pqvault-web/static/login.html` — Login page (for Feature 001)
- `crates/pqvault-web/static/style.css` — All CSS styles
- `crates/pqvault-web/static/app.js` — Dashboard JavaScript (API calls, DOM manipulation)
- `crates/pqvault-web/src/web.rs` — Remove embedded HTML, add ServeDir routing
- `crates/pqvault-web/src/lib.rs` — Configure static file serving
- `crates/pqvault-web/build.rs` — Optional: embed static files at compile time for release

### Data Model Changes

No data model changes.

### MCP Tools

No MCP changes. API endpoints remain identical.

### CLI Commands

```bash
# Start web server (serves static files from crate's static/ directory)
pqvault web

# Start web server with custom static file directory (for development)
pqvault web --static-dir /path/to/custom/static

# Start with live-reload enabled (watches static files for changes)
pqvault web --dev
```

### Web UI Changes

The UI itself doesn't change visually. The internal architecture changes from embedded strings to separate files:

**Before:**
```rust
// web.rs - 560 lines of HTML embedded in Rust
fn dashboard_html() -> &'static str {
    r#"<!DOCTYPE html><html>... 560 lines ...</html>"#
}
```

**After:**
```
crates/pqvault-web/static/
  index.html      — Dashboard layout and structure
  login.html      — TOTP login page
  style.css       — All styles (extracted from <style> tags)
  app.js          — All JavaScript (extracted from <script> tags)
  favicon.svg     — PQVault icon
```

## Core Implementation

### Router Changes

```rust
// crates/pqvault-web/src/web.rs

use axum::{
    Router,
    routing::{get, post, delete},
};
use tower_http::services::ServeDir;
use std::path::PathBuf;

pub fn create_router(state: AppState) -> Router {
    let static_dir = state.static_dir.clone()
        .unwrap_or_else(|| default_static_dir());

    Router::new()
        // API routes (unchanged)
        .route("/api/secrets", get(list_secrets))
        .route("/api/secrets", post(add_secret))
        .route("/api/secrets/:name", get(get_secret))
        .route("/api/secrets/:name", delete(delete_secret))
        .route("/api/search", get(search_secrets))
        .route("/api/status", get(vault_status))
        .route("/api/health", get(health_check))
        // Auth routes (Feature 001)
        .route("/api/auth/login", post(auth_login))
        .route("/api/auth/logout", post(auth_logout))
        // Serve static files for everything else
        .fallback_service(
            ServeDir::new(&static_dir)
                .append_index_html_on_directories(true)
        )
        .with_state(state)
}

fn default_static_dir() -> PathBuf {
    // In development: use the crate's static/ directory
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("static")
}

#[cfg(feature = "embed-static")]
fn default_static_dir() -> PathBuf {
    // In release: extract embedded files to temp directory
    use include_dir::{include_dir, Dir};
    static STATIC_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/static");

    let tmp = std::env::temp_dir().join("pqvault-static");
    if !tmp.exists() {
        STATIC_DIR.extract(&tmp).expect("Failed to extract static files");
    }
    tmp
}
```

### Static File: index.html

```html
<!-- crates/pqvault-web/static/index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PQVault Dashboard</title>
    <link rel="stylesheet" href="/style.css">
    <link rel="icon" href="/favicon.svg" type="image/svg+xml">
</head>
<body>
    <div id="app">
        <header>
            <h1>PQVault</h1>
            <span class="subtitle">Quantum-Proof Secrets Manager</span>
            <div class="header-actions">
                <button id="btn-refresh" title="Refresh">Refresh</button>
                <button id="btn-add" title="Add Secret">+ Add Secret</button>
            </div>
        </header>

        <div id="status-bar">
            <!-- Populated by app.js -->
        </div>

        <div id="search-container">
            <input type="text" id="search-input" placeholder="Search secrets..." />
        </div>

        <div id="secrets-table-container">
            <table id="secrets-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Category</th>
                        <th>Project</th>
                        <th>Provider</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="secrets-body">
                    <!-- Populated by app.js -->
                </tbody>
            </table>
        </div>

        <!-- Add Secret Modal -->
        <div id="add-modal" class="modal hidden">
            <div class="modal-content">
                <h2>Add Secret</h2>
                <form id="add-form">
                    <label>Name <input type="text" name="name" required /></label>
                    <label>Value <textarea name="value" required></textarea></label>
                    <label>Category <input type="text" name="category" /></label>
                    <label>Project <input type="text" name="project" /></label>
                    <div class="modal-actions">
                        <button type="submit">Add</button>
                        <button type="button" id="btn-cancel-add">Cancel</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="/app.js"></script>
</body>
</html>
```

### Static File: app.js (key portions)

```javascript
// crates/pqvault-web/static/app.js

const API_BASE = '';

async function loadSecrets() {
    const response = await fetch(`${API_BASE}/api/secrets`);
    const data = await response.json();
    renderSecrets(data.secrets || []);
}

async function loadStatus() {
    const response = await fetch(`${API_BASE}/api/status`);
    const data = await response.json();
    renderStatus(data);
}

function renderSecrets(secrets) {
    const tbody = document.getElementById('secrets-body');
    tbody.innerHTML = secrets.map(s => `
        <tr>
            <td class="key-name">${escapeHtml(s.name)}</td>
            <td><span class="badge badge-${s.category}">${s.category}</span></td>
            <td>${s.project || '-'}</td>
            <td>${s.provider || '-'}</td>
            <td><span class="status-${s.key_status}">${s.key_status}</span></td>
            <td>${formatDate(s.created)}</td>
            <td>
                <button onclick="copySecret('${s.name}')" title="Copy">Copy</button>
                <button onclick="deleteSecret('${s.name}')" title="Delete" class="btn-danger">Delete</button>
            </td>
        </tr>
    `).join('');
}

async function copySecret(name) {
    const response = await fetch(`${API_BASE}/api/secrets/${encodeURIComponent(name)}`);
    const data = await response.json();
    await navigator.clipboard.writeText(data.value);
    showNotification(`${name} copied to clipboard`);
}

async function deleteSecret(name) {
    if (!confirm(`Delete ${name}?`)) return;
    await fetch(`${API_BASE}/api/secrets/${encodeURIComponent(name)}`, { method: 'DELETE' });
    loadSecrets();
}

async function addSecret(event) {
    event.preventDefault();
    const form = event.target;
    const data = {
        name: form.name.value,
        value: form.value.value,
        category: form.category.value || undefined,
        project: form.project.value || undefined,
    };
    await fetch(`${API_BASE}/api/secrets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    form.reset();
    document.getElementById('add-modal').classList.add('hidden');
    loadSecrets();
}

// Search with debounce
let searchTimeout;
document.getElementById('search-input').addEventListener('input', (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(async () => {
        if (e.target.value.length < 2) {
            loadSecrets();
            return;
        }
        const response = await fetch(`${API_BASE}/api/search?q=${encodeURIComponent(e.target.value)}`);
        const data = await response.json();
        renderSecrets(data.results || []);
    }, 300);
});

// Modal controls
document.getElementById('btn-add').addEventListener('click', () => {
    document.getElementById('add-modal').classList.remove('hidden');
});
document.getElementById('btn-cancel-add').addEventListener('click', () => {
    document.getElementById('add-modal').classList.add('hidden');
});
document.getElementById('add-form').addEventListener('submit', addSecret);
document.getElementById('btn-refresh').addEventListener('click', loadSecrets);

// Utility functions
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatDate(iso) {
    return new Date(iso).toLocaleDateString();
}

function showNotification(msg) {
    // Simple notification toast
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

// Initial load
loadSecrets();
loadStatus();
```

## Dependencies

- `tower-http = { version = "0.6", features = ["fs"] }` — Static file serving via ServeDir
- `include_dir = "0.7"` — Optional: embed static files in release binary
- No JavaScript build toolchain required — vanilla JS, CSS, HTML

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_index_html_served() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/").await;
        assert_eq!(response.status_code(), 200);
        let body = response.text();
        assert!(body.contains("PQVault Dashboard"));
        assert!(body.contains("<script src=\"/app.js\">"));
    }

    #[tokio::test]
    async fn test_css_served() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/style.css").await;
        assert_eq!(response.status_code(), 200);
        assert!(response.headers().get("content-type").unwrap()
            .to_str().unwrap().contains("text/css"));
    }

    #[tokio::test]
    async fn test_js_served() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/app.js").await;
        assert_eq!(response.status_code(), 200);
    }

    #[tokio::test]
    async fn test_api_routes_still_work() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/secrets").await;
        assert_eq!(response.status_code(), 200);
        let body: serde_json::Value = response.json();
        assert!(body.get("secrets").is_some());
    }

    #[tokio::test]
    async fn test_404_for_missing_static_file() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/nonexistent.html").await;
        assert_eq!(response.status_code(), 404);
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_full_page_load() {
    let server = start_test_web_server().await;
    let client = reqwest::Client::new();

    // Load index
    let index = client.get(&format!("{}/", server.url())).send().await.unwrap();
    assert_eq!(index.status(), 200);
    let html = index.text().await.unwrap();

    // Verify CSS and JS references exist and are loadable
    assert!(html.contains("style.css"));
    assert!(html.contains("app.js"));

    let css = client.get(&format!("{}/style.css", server.url())).send().await.unwrap();
    assert_eq!(css.status(), 200);

    let js = client.get(&format!("{}/app.js", server.url())).send().await.unwrap();
    assert_eq!(js.status(), 200);
}
```

### Manual Verification

1. Start `pqvault web` — dashboard should render identically to current embedded version
2. Edit `static/style.css` — refresh browser, change should be visible without recompile
3. Edit `static/index.html` — refresh browser, change should be visible
4. Verify all API interactions still work (add, delete, copy, search)
5. Build release binary — verify static files are embedded and work without source directory

## Example Usage

```bash
# Development mode — serves files from disk, changes reflect on refresh
$ pqvault web
PQVault dashboard: http://localhost:3000
Static files: /path/to/crates/pqvault-web/static/
Mode: development (files served from disk)

# Custom static directory (useful for theme development)
$ pqvault web --static-dir ~/my-pqvault-theme/
PQVault dashboard: http://localhost:3000
Static files: /Users/dev/my-pqvault-theme/

# Production (embedded static files)
$ cargo build --release --features embed-static
$ ./target/release/pqvault web
PQVault dashboard: http://localhost:3000
Static files: embedded in binary
```
