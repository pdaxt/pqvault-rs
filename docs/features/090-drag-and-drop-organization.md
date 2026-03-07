# Feature 090: Drag-and-Drop Organization

## Status: Done
## Phase: 9 (v2.9)
## Priority: Low

## Problem

Reorganizing secrets between categories requires editing each key's metadata
individually. When a project is restructured or naming conventions change, moving
dozens of keys between categories is tedious. Users cannot visually group and
organize their vault contents through intuitive spatial interaction.

## Solution

Implement drag-and-drop functionality in the web dashboard so users can drag keys
between category groups, reorder keys within groups, and create new categories by
dropping keys into a "New Category" zone. Uses the native HTML5 Drag and Drop API
with touch support via a polyfill for mobile devices.

## Implementation

### Files to Create/Modify

```
pqvault-web/
  src/
    routes/
      api/
        organize.rs     # POST /api/keys/:name/move - move key to category
  static/
    js/
      dragdrop.js       # Drag and drop logic
    css/
      dragdrop.css      # Drag visual feedback styles
  templates/
    components/
      category_groups.html  # Grouped key view with drop zones
```

### Data Model Changes

```rust
/// Request to move a key to a different category
#[derive(Deserialize)]
pub struct MoveKeyRequest {
    /// Key name to move
    pub key: String,
    /// Target category
    pub target_category: String,
    /// Optional position within category (for ordering)
    pub position: Option<usize>,
}

/// Batch move request for multiple keys
#[derive(Deserialize)]
pub struct BatchMoveRequest {
    pub moves: Vec<MoveKeyRequest>,
}

#[derive(Serialize)]
pub struct MoveResult {
    pub key: String,
    pub from_category: String,
    pub to_category: String,
    pub success: bool,
}
```

Route handler:

```rust
pub async fn move_key(
    State(state): State<AppState>,
    Json(request): Json<MoveKeyRequest>,
) -> impl IntoResponse {
    let mut vault = state.vault.write().await;

    let old_category = vault.get_category(&request.key).await
        .unwrap_or_else(|_| "uncategorized".to_string());

    vault.set_category(&request.key, &request.target_category).await?;

    // Broadcast change via WebSocket
    state.broadcaster.broadcast(VaultEvent::KeyUpdated {
        key: request.key.clone(),
        change: format!("moved from {} to {}", old_category, request.target_category),
        timestamp: Utc::now().to_rfc3339(),
    });

    Json(MoveResult {
        key: request.key,
        from_category: old_category,
        to_category: request.target_category,
        success: true,
    })
}
```

### MCP Tools

No new MCP tools.

### CLI Commands

```bash
# Move a key to a different category (CLI equivalent)
pqvault categorize STRIPE_KEY --category payment
pqvault categorize AWS_KEY --category cloud
```

### Web UI Changes

```javascript
// dragdrop.js
class DragDropOrganizer {
    constructor() {
        this.draggedKey = null;
        this.init();
    }

    init() {
        // Make key rows draggable
        document.querySelectorAll('.key-row').forEach(row => {
            row.draggable = true;
            row.addEventListener('dragstart', (e) => this.onDragStart(e));
            row.addEventListener('dragend', (e) => this.onDragEnd(e));
        });

        // Set up drop zones
        document.querySelectorAll('.category-group').forEach(group => {
            group.addEventListener('dragover', (e) => this.onDragOver(e));
            group.addEventListener('dragleave', (e) => this.onDragLeave(e));
            group.addEventListener('drop', (e) => this.onDrop(e));
        });

        // New category drop zone
        const newCatZone = document.getElementById('new-category-zone');
        if (newCatZone) {
            newCatZone.addEventListener('dragover', (e) => this.onDragOver(e));
            newCatZone.addEventListener('drop', (e) => this.onDropNewCategory(e));
        }
    }

    onDragStart(event) {
        this.draggedKey = event.target.dataset.key;
        event.target.classList.add('dragging');
        event.dataTransfer.setData('text/plain', this.draggedKey);
        event.dataTransfer.effectAllowed = 'move';

        // Show all drop zones
        document.querySelectorAll('.category-group').forEach(g => {
            g.classList.add('drop-target');
        });
    }

    onDragEnd(event) {
        event.target.classList.remove('dragging');
        document.querySelectorAll('.category-group').forEach(g => {
            g.classList.remove('drop-target', 'drop-hover');
        });
    }

    onDragOver(event) {
        event.preventDefault();
        event.dataTransfer.dropEffect = 'move';
        event.currentTarget.classList.add('drop-hover');
    }

    onDragLeave(event) {
        event.currentTarget.classList.remove('drop-hover');
    }

    async onDrop(event) {
        event.preventDefault();
        const targetCategory = event.currentTarget.dataset.category;
        const keyName = event.dataTransfer.getData('text/plain');

        if (!keyName || !targetCategory) return;

        event.currentTarget.classList.remove('drop-hover');

        try {
            const response = await fetch('/api/keys/move', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    key: keyName,
                    target_category: targetCategory,
                }),
            });

            if (response.ok) {
                // Move the DOM element
                const row = document.querySelector(`[data-key="${keyName}"]`);
                const targetGroup = event.currentTarget.querySelector('.key-list');
                if (row && targetGroup) {
                    targetGroup.appendChild(row);
                    this.updateGroupCounts();
                    this.showToast(`Moved ${keyName} to ${targetCategory}`);
                }
            }
        } catch (error) {
            this.showToast(`Failed to move ${keyName}`, 'error');
        }
    }

    async onDropNewCategory(event) {
        event.preventDefault();
        const keyName = event.dataTransfer.getData('text/plain');
        const categoryName = prompt('Enter new category name:');
        if (!categoryName) return;

        await fetch('/api/keys/move', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                key: keyName,
                target_category: categoryName,
            }),
        });

        location.reload(); // Reload to show new category group
    }

    updateGroupCounts() {
        document.querySelectorAll('.category-group').forEach(group => {
            const count = group.querySelectorAll('.key-row').length;
            const badge = group.querySelector('.category-count');
            if (badge) badge.textContent = count;
        });
    }
}

const organizer = new DragDropOrganizer();
```

```css
/* dragdrop.css */
.key-row[draggable="true"] {
    cursor: grab;
}

.key-row.dragging {
    opacity: 0.5;
    cursor: grabbing;
}

.category-group.drop-target {
    border: 2px dashed var(--border-color);
    border-radius: 8px;
}

.category-group.drop-hover {
    border-color: var(--accent-primary);
    background: color-mix(in srgb, var(--accent-primary) 5%, transparent);
}

#new-category-zone {
    border: 2px dashed var(--text-muted);
    border-radius: 8px;
    padding: 2rem;
    text-align: center;
    color: var(--text-muted);
    margin-top: 1rem;
}

#new-category-zone.drop-hover {
    border-color: var(--accent-success);
    color: var(--accent-success);
}
```

## Dependencies

No new Rust or JavaScript dependencies. Uses native HTML5 Drag and Drop API.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_move_request_parsing() {
        let json = r#"{"key": "API_KEY", "target_category": "cloud"}"#;
        let req: MoveKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.key, "API_KEY");
        assert_eq!(req.target_category, "cloud");
    }

    #[test]
    fn test_batch_move_parsing() {
        let json = r#"{"moves": [
            {"key": "A", "target_category": "x"},
            {"key": "B", "target_category": "y"}
        ]}"#;
        let req: BatchMoveRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.moves.len(), 2);
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_move_key_api() {
    let app = test_app_with_keys(&[("STRIPE_KEY", "v")]).await;
    let response = app.post("/api/keys/move")
        .json(&MoveKeyRequest {
            key: "STRIPE_KEY".into(),
            target_category: "payment".into(),
            position: None,
        })
        .await;
    assert_eq!(response.status(), 200);
    let result: MoveResult = response.json().await;
    assert_eq!(result.to_category, "payment");
    assert!(result.success);
}
```

## Example Usage

```
Dashboard in grouped view with drag-and-drop:

┌─── payment (3 keys) ──────────────────────────────┐
│ STRIPE_SECRET_KEY       healthy   [drag handle]    │
│ STRIPE_PUBLISHABLE      healthy   [drag handle]    │
│ RAZORPAY_KEY_ID         healthy   [drag handle]    │
└────────────────────────────────────────────────────┘

┌─── cloud (3 keys) ────────────────────────────────┐
│ AWS_ACCESS_KEY_ID       healthy   [drag handle]    │
│ AWS_SECRET_KEY          healthy   [drag handle]    │
│ ┌──────────────────────────────────────────────┐   │
│ │        Drop here to add to "cloud"           │   │ ← drop zone active
│ └──────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────┘

┌─── database (2 keys) ─────────────────────────────┐
│ DATABASE_URL            warning   [drag handle]    │
│ REDIS_URL               healthy   [drag handle]    │
└────────────────────────────────────────────────────┘

┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
│        Drop here to create new category           │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘

Dragging REDIS_URL from "database" to "cache":
  Toast: "Moved REDIS_URL to cache"
  Category counts updated automatically
```
