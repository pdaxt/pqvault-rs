# Feature 083: Bulk Operations UI

## Status: Done
## Phase: 9 (v2.9)
## Priority: High

## Problem

The web dashboard only supports one-at-a-time key operations. Rotating 20 keys before
a compliance audit, re-categorizing keys after a reorganization, or cleaning up
deprecated secrets requires clicking through each key individually. This is slow,
error-prone, and discourages proper secret hygiene.

## Solution

Add multi-select functionality to the dashboard key list with a batch action toolbar.
Users can select keys using checkboxes, shift-click for range selection, and
Ctrl/Cmd+A for select-all. The toolbar appears when keys are selected, offering
batch rotate, delete, re-categorize, export, and tag operations.

## Implementation

### Files to Create/Modify

```
pqvault-web/
  src/
    routes/
      api/
        bulk.rs         # POST /api/bulk/:action - bulk operation endpoint
  templates/
    components/
      bulk_toolbar.html # Floating action toolbar
      key_list.html     # Updated with checkboxes and selection
  static/
    js/
      bulk.js           # Selection logic and batch execution
    css/
      bulk.css          # Toolbar and selection styles
```

### Data Model Changes

```rust
/// Bulk operation request
#[derive(Deserialize)]
pub struct BulkRequest {
    /// Selected key names
    pub keys: Vec<String>,
    /// Operation to perform
    pub action: BulkAction,
    /// Operation-specific parameters
    pub params: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BulkAction {
    Rotate,
    Delete,
    Recategorize { category: String },
    AddTag { tag: String },
    RemoveTag { tag: String },
    Export { format: String },
    SetExpiry { days: u32 },
}

#[derive(Serialize)]
pub struct BulkResponse {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub results: Vec<BulkItemResult>,
}

#[derive(Serialize)]
pub struct BulkItemResult {
    pub key: String,
    pub status: String,     // "success" | "failed"
    pub message: Option<String>,
}
```

Route handler:

```rust
pub async fn bulk_action(
    State(state): State<AppState>,
    Json(request): Json<BulkRequest>,
) -> impl IntoResponse {
    let mut vault = state.vault.write().await;
    let mut results = Vec::new();

    for key in &request.keys {
        let result = match &request.action {
            BulkAction::Rotate => {
                vault.rotate(key).await
                    .map(|_| BulkItemResult {
                        key: key.clone(),
                        status: "success".into(),
                        message: Some("Rotated".into()),
                    })
                    .unwrap_or_else(|e| BulkItemResult {
                        key: key.clone(),
                        status: "failed".into(),
                        message: Some(e.to_string()),
                    })
            }
            BulkAction::Delete => {
                vault.delete(key).await
                    .map(|_| BulkItemResult {
                        key: key.clone(),
                        status: "success".into(),
                        message: Some("Deleted".into()),
                    })
                    .unwrap_or_else(|e| BulkItemResult {
                        key: key.clone(),
                        status: "failed".into(),
                        message: Some(e.to_string()),
                    })
            }
            BulkAction::Recategorize { category } => {
                vault.set_category(key, category).await
                    .map(|_| BulkItemResult {
                        key: key.clone(),
                        status: "success".into(),
                        message: Some(format!("Category set to {}", category)),
                    })
                    .unwrap_or_else(|e| BulkItemResult {
                        key: key.clone(),
                        status: "failed".into(),
                        message: Some(e.to_string()),
                    })
            }
            _ => BulkItemResult {
                key: key.clone(),
                status: "failed".into(),
                message: Some("Action not implemented".into()),
            },
        };
        results.push(result);
    }

    let succeeded = results.iter().filter(|r| r.status == "success").count();
    Json(BulkResponse {
        total: results.len(),
        succeeded,
        failed: results.len() - succeeded,
        results,
    })
}
```

### MCP Tools

No new MCP tools. Bulk operations use existing vault APIs.

### CLI Commands

No new CLI commands. CLI bulk operations are covered by Feature 066 (pqvault bulk).

### Web UI Changes

```javascript
// bulk.js - Selection and batch action logic
class BulkSelector {
    constructor() {
        this.selected = new Set();
        this.lastClicked = null;
        this.init();
    }

    init() {
        document.querySelectorAll('.key-checkbox').forEach(cb => {
            cb.addEventListener('change', (e) => this.handleCheck(e));
        });

        document.querySelectorAll('.key-row').forEach(row => {
            row.addEventListener('click', (e) => this.handleRowClick(e));
        });

        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'a') {
                e.preventDefault();
                this.selectAll();
            }
        });
    }

    handleCheck(event) {
        const keyName = event.target.dataset.key;
        if (event.target.checked) {
            this.selected.add(keyName);
        } else {
            this.selected.delete(keyName);
        }

        if (event.shiftKey && this.lastClicked) {
            this.selectRange(this.lastClicked, keyName);
        }
        this.lastClicked = keyName;
        this.updateToolbar();
    }

    selectAll() {
        document.querySelectorAll('.key-checkbox').forEach(cb => {
            cb.checked = true;
            this.selected.add(cb.dataset.key);
        });
        this.updateToolbar();
    }

    deselectAll() {
        this.selected.clear();
        document.querySelectorAll('.key-checkbox').forEach(cb => cb.checked = false);
        this.updateToolbar();
    }

    updateToolbar() {
        const toolbar = document.getElementById('bulk-toolbar');
        const count = document.getElementById('selection-count');
        if (this.selected.size > 0) {
            toolbar.classList.add('visible');
            count.textContent = `${this.selected.size} selected`;
        } else {
            toolbar.classList.remove('visible');
        }
    }

    async executeBulk(action, params = {}) {
        const confirmed = confirm(
            `${action} ${this.selected.size} keys? This cannot be undone.`
        );
        if (!confirmed) return;

        const response = await fetch('/api/bulk/' + action, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                keys: Array.from(this.selected),
                action: action,
                params: params,
            }),
        });

        const result = await response.json();
        showBulkResult(result);
        if (result.succeeded > 0) {
            location.reload();
        }
    }
}
```

## Dependencies

No new dependencies.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bulk_request_parsing() {
        let json = r#"{"keys": ["KEY_A", "KEY_B"], "action": "rotate"}"#;
        let request: BulkRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.keys.len(), 2);
    }

    #[test]
    fn test_bulk_recategorize_parsing() {
        let json = r#"{"keys": ["KEY_A"], "action": {"recategorize": {"category": "cloud"}}}"#;
        let request: BulkRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(request.action, BulkAction::Recategorize { .. }));
    }

    #[test]
    fn test_bulk_response_counts() {
        let response = BulkResponse {
            total: 5,
            succeeded: 3,
            failed: 2,
            results: vec![],
        };
        assert_eq!(response.total, response.succeeded + response.failed);
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_bulk_rotate() {
    let app = test_app_with_keys(&[("A", "v1"), ("B", "v2"), ("C", "v3")]).await;
    let response = app.post("/api/bulk/rotate")
        .json(&BulkRequest {
            keys: vec!["A".into(), "B".into()],
            action: BulkAction::Rotate,
            params: None,
        })
        .await;
    assert_eq!(response.status(), 200);
    let result: BulkResponse = response.json().await;
    assert_eq!(result.succeeded, 2);
}

#[tokio::test]
async fn test_bulk_delete() {
    let app = test_app_with_keys(&[("A", "v1"), ("B", "v2")]).await;
    let response = app.post("/api/bulk/delete")
        .json(&BulkRequest {
            keys: vec!["A".into(), "B".into()],
            action: BulkAction::Delete,
            params: None,
        })
        .await;
    let result: BulkResponse = response.json().await;
    assert_eq!(result.succeeded, 2);
}
```

## Example Usage

```
Dashboard with selections:

┌─────────────────────────────────────────────────────────┐
│ [x] STRIPE_SECRET_KEY       payment    healthy    3d    │
│ [ ] STRIPE_PUBLISHABLE      payment    healthy    3d    │
│ [x] AWS_ACCESS_KEY_ID       cloud      healthy    15d   │
│ [x] AWS_SECRET_ACCESS_KEY   cloud      healthy    15d   │
│ [ ] DATABASE_URL            database   warning    90d   │
│ [x] REDIS_URL               database   healthy    30d   │
├─────────────────────────────────────────────────────────┤
│ 4 selected  [Rotate All] [Delete] [Re-categorize] [x]  │
└─────────────────────────────────────────────────────────┘

After clicking [Rotate All]:
  Confirm: Rotate 4 keys? This cannot be undone. [OK] [Cancel]

  Result: 4/4 succeeded
  - STRIPE_SECRET_KEY: Rotated (new value via Stripe API)
  - AWS_ACCESS_KEY_ID: Rotated (new value via AWS IAM)
  - AWS_SECRET_ACCESS_KEY: Rotated
  - REDIS_URL: Rotated
```
