# Feature 082: Key Detail Page

## Status: Done
## Phase: 9 (v2.9)
## Priority: High

## Problem

The web dashboard currently shows keys in a flat list with minimal metadata. Users
cannot see the full picture for a key — its version history, usage patterns, access
policies, audit trail, and health status — without running multiple CLI commands.
There is no single view that answers "tell me everything about this key."

## Solution

Build a dedicated key detail page accessible by clicking any key in the dashboard.
The page shows comprehensive information organized into tabs: Overview, History,
Usage, Audit Trail, and Policies. Each tab loads data lazily from the backend API.
This becomes the central hub for understanding and managing any individual secret.

## Implementation

### Files to Create/Modify

```
pqvault-web/
  src/
    routes/
      key_detail.rs     # GET /keys/:name - key detail page
      api/
        key_history.rs  # GET /api/keys/:name/history
        key_usage.rs    # GET /api/keys/:name/usage
        key_audit.rs    # GET /api/keys/:name/audit
        key_policy.rs   # GET /api/keys/:name/policy
  templates/
    key_detail.html     # Main detail page template
    components/
      key_overview.html   # Overview tab
      key_history.html    # Version history tab
      key_usage.html      # Usage statistics tab
      key_audit.html      # Audit trail tab
      key_policy.html     # Access policies tab
  static/
    js/
      key_detail.js     # Tab switching, data loading
    css/
      key_detail.css    # Detail page styles
```

### Data Model Changes

```rust
/// Complete key detail response
#[derive(Serialize)]
pub struct KeyDetail {
    pub name: String,
    pub category: Option<String>,
    pub provider: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub current_version: u32,
    pub health: HealthSummary,
    pub value_preview: String,    // Masked: "sk_live_████████"
    pub value_length: usize,
    pub encryption: EncryptionInfo,
}

#[derive(Serialize)]
pub struct HealthSummary {
    pub status: String,          // "healthy", "warning", "critical"
    pub score: u32,              // 0-100
    pub issues: Vec<String>,
    pub last_checked: DateTime<Utc>,
    pub days_until_expiry: Option<i64>,
    pub days_since_rotation: Option<i64>,
}

#[derive(Serialize)]
pub struct EncryptionInfo {
    pub algorithm: String,       // "AES-256-GCM"
    pub kem: String,             // "ML-KEM-768"
    pub key_exchange: String,    // "X25519"
}

#[derive(Serialize)]
pub struct UsageStats {
    pub total_accesses: u64,
    pub last_7_days: u64,
    pub last_30_days: u64,
    pub daily_trend: Vec<DailyCount>,   // Last 30 days
    pub top_accessors: Vec<AccessorCount>,
    pub access_sources: HashMap<String, u64>, // "cli": 45, "mcp": 30
}

#[derive(Serialize)]
pub struct DailyCount {
    pub date: String,
    pub count: u64,
}
```

Route handlers:

```rust
pub async fn key_detail_page(
    Path(key_name): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let vault = state.vault.read().await;

    let entry = vault.get_metadata(&key_name).await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let health = state.health_checker.check_key(&key_name).await
        .unwrap_or_default();

    let detail = KeyDetail {
        name: key_name.clone(),
        category: entry.category,
        provider: entry.provider,
        tags: entry.tags,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        rotated_at: entry.rotated_at,
        expires_at: entry.expires_at,
        current_version: entry.version,
        health: health.into(),
        value_preview: mask_value(&entry.value_prefix, entry.value_length),
        value_length: entry.value_length,
        encryption: EncryptionInfo {
            algorithm: "AES-256-GCM".into(),
            kem: "ML-KEM-768".into(),
            key_exchange: "X25519".into(),
        },
    };

    let template = state.templates.render("key_detail.html", &detail)?;
    Html(template)
}

pub async fn key_usage_api(
    Path(key_name): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let stats = state.audit.usage_stats(&key_name, 30).await?;
    Json(stats)
}
```

### MCP Tools

No new MCP tools. The detail page consumes existing MCP data via internal APIs.

### CLI Commands

No new CLI commands. Similar information available via `pqvault show KEY --detailed`.

### Web UI Changes

Key detail page layout:

```html
<!-- key_detail.html -->
<div class="key-detail">
    <header class="key-header">
        <h1>{{ name }}</h1>
        <div class="key-meta">
            <span class="badge category">{{ category }}</span>
            <span class="badge provider">{{ provider }}</span>
            <span class="badge health-{{ health.status }}">{{ health.status }}</span>
        </div>
        <div class="key-actions">
            <button onclick="copyValue('{{ name }}')" class="btn-secondary">Copy</button>
            <button onclick="rotateKey('{{ name }}')" class="btn-warning">Rotate</button>
            <button onclick="deleteKey('{{ name }}')" class="btn-danger">Delete</button>
        </div>
    </header>

    <nav class="tabs">
        <button class="tab active" data-tab="overview">Overview</button>
        <button class="tab" data-tab="history">History</button>
        <button class="tab" data-tab="usage">Usage</button>
        <button class="tab" data-tab="audit">Audit Trail</button>
        <button class="tab" data-tab="policy">Policies</button>
    </nav>

    <div class="tab-content" id="tab-overview">
        <div class="info-grid">
            <div class="info-card">
                <h3>Value</h3>
                <code class="masked-value">{{ value_preview }}</code>
                <span class="value-length">({{ value_length }} chars)</span>
            </div>
            <div class="info-card">
                <h3>Health Score</h3>
                <div class="score-ring" data-score="{{ health.score }}">{{ health.score }}</div>
            </div>
            <div class="info-card">
                <h3>Encryption</h3>
                <p>{{ encryption.algorithm }} + {{ encryption.kem }}</p>
            </div>
            <div class="info-card">
                <h3>Dates</h3>
                <p>Created: {{ created_at }}</p>
                <p>Last rotated: {{ rotated_at }}</p>
                <p>Expires: {{ expires_at }}</p>
            </div>
        </div>
    </div>

    <div class="tab-content hidden" id="tab-history">
        <!-- Loaded via AJAX from /api/keys/:name/history -->
    </div>

    <div class="tab-content hidden" id="tab-usage">
        <!-- Loaded via AJAX, rendered with Chart.js sparklines -->
    </div>
</div>
```

## Dependencies

No new Rust dependencies. Uses existing `axum`, `serde`, and template engine.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_value_short() {
        assert_eq!(mask_value("sk_l", 32), "sk_l████████████████████████████");
    }

    #[test]
    fn test_mask_value_very_short() {
        assert_eq!(mask_value("", 4), "████");
    }

    #[test]
    fn test_health_summary_from_checks() {
        let checks = vec![
            HealthCheck { name: "entropy".into(), status: "pass".into(), score: 95 },
            HealthCheck { name: "expiry".into(), status: "warning".into(), score: 60 },
        ];
        let summary = HealthSummary::from_checks(&checks);
        assert_eq!(summary.status, "warning");
        assert_eq!(summary.score, 77); // average
    }

    #[test]
    fn test_key_detail_serialization() {
        let detail = KeyDetail {
            name: "API_KEY".into(),
            category: Some("general".into()),
            provider: None,
            tags: vec!["production".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            rotated_at: None,
            expires_at: None,
            current_version: 1,
            health: HealthSummary::default(),
            value_preview: "████████".into(),
            value_length: 32,
            encryption: EncryptionInfo::default(),
        };
        let json = serde_json::to_string(&detail).unwrap();
        assert!(json.contains("API_KEY"));
        assert!(!json.contains("actual_secret_value"));
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_key_detail_page_renders() {
    let app = test_app_with_keys(&[("STRIPE_KEY", "sk_live_test123")]).await;
    let response = app.get("/keys/STRIPE_KEY").await;
    assert_eq!(response.status(), 200);
    let body = response.text().await;
    assert!(body.contains("STRIPE_KEY"));
    assert!(body.contains("sk_l")); // prefix shown
    assert!(!body.contains("sk_live_test123")); // full value hidden
}

#[tokio::test]
async fn test_key_usage_api() {
    let app = test_app_with_keys(&[("KEY", "val")]).await;
    let response = app.get("/api/keys/KEY/usage").await;
    assert_eq!(response.status(), 200);
    let stats: UsageStats = response.json().await;
    assert!(stats.daily_trend.len() <= 30);
}
```

## Example Usage

```
Browser: http://localhost:3001/keys/STRIPE_SECRET_KEY

┌─────────────────────────────────────────────────────────┐
│ STRIPE_SECRET_KEY                                       │
│ [payment] [stripe] [healthy]                            │
│                                    [Copy] [Rotate] [Del]│
├─────────────────────────────────────────────────────────┤
│ [Overview]  History  Usage  Audit Trail  Policies       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Value                    Health Score                  │
│  sk_live_████████████     ┌───┐                        │
│  (35 chars)               │ 95│                        │
│                           └───┘                        │
│  Encryption               Dates                        │
│  AES-256-GCM + ML-KEM    Created: 2024-07-15          │
│  X25519 key exchange      Rotated: 2025-03-01          │
│                           Expires: 2025-06-01          │
│                                                         │
│  Tags: production, api, stripe                          │
│                                                         │
└─────────────────────────────────────────────────────────┘
```
