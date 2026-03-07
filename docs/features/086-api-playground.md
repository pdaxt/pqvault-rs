# Feature 086: API Playground

## Status: Planned
## Phase: 9 (v2.9)
## Priority: Medium

## Problem

When a key is rotated or a new API key is provisioned, developers need to verify it
works before deploying to production. Currently they must switch to a terminal, craft
a curl command or write a test script, and manually check the response. There is no
way to quickly test a key's validity from within the PQVault interface.

## Solution

Build an inline API playground in the web dashboard where users can select a key,
pick a test endpoint template (based on the key's provider), send a test request,
and see the response. The playground injects the key value into the request securely
without exposing it in the browser. All test requests are proxied through the backend
to prevent CORS issues and keep keys server-side.

## Implementation

### Files to Create/Modify

```
pqvault-web/
  src/
    routes/
      api/
        playground.rs   # POST /api/playground/test - proxied test request
    playground/
      mod.rs            # Playground module root
      templates.rs      # Provider-specific test request templates
      executor.rs       # Request execution and response formatting
  templates/
    playground.html     # Playground UI page
    components/
      request_builder.html  # Request builder form
      response_viewer.html  # Response display with syntax highlighting
  static/
    js/
      playground.js     # Interactive request builder logic
```

### Data Model Changes

```rust
/// Test request to execute
#[derive(Deserialize)]
pub struct PlaygroundRequest {
    /// Key to test
    pub key_name: String,
    /// HTTP method
    pub method: String,          // GET, POST, etc.
    /// URL to send to
    pub url: String,
    /// How to inject the key
    pub injection: KeyInjection,
    /// Optional request body
    pub body: Option<String>,
    /// Additional headers
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyInjection {
    /// Authorization: Bearer <key>
    BearerToken,
    /// Custom header (e.g., "X-API-Key")
    Header { name: String },
    /// Query parameter
    QueryParam { name: String },
    /// Basic auth (key as password)
    BasicAuth { username: String },
}

#[derive(Serialize)]
pub struct PlaygroundResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub duration_ms: u64,
    pub success: bool,
}

/// Provider-specific test templates
pub struct TestTemplate {
    pub provider: String,
    pub name: String,
    pub description: String,
    pub method: String,
    pub url: String,
    pub injection: KeyInjection,
    pub expected_status: u16,
}

pub fn get_provider_templates() -> Vec<TestTemplate> {
    vec![
        TestTemplate {
            provider: "stripe".into(),
            name: "List Charges".into(),
            description: "Verify Stripe key by listing recent charges".into(),
            method: "GET".into(),
            url: "https://api.stripe.com/v1/charges?limit=1".into(),
            injection: KeyInjection::BasicAuth { username: String::new() },
            expected_status: 200,
        },
        TestTemplate {
            provider: "openai".into(),
            name: "List Models".into(),
            description: "Verify OpenAI key by listing available models".into(),
            method: "GET".into(),
            url: "https://api.openai.com/v1/models".into(),
            injection: KeyInjection::BearerToken,
            expected_status: 200,
        },
        TestTemplate {
            provider: "github".into(),
            name: "Get Authenticated User".into(),
            description: "Verify GitHub token by fetching user info".into(),
            method: "GET".into(),
            url: "https://api.github.com/user".into(),
            injection: KeyInjection::BearerToken,
            expected_status: 200,
        },
        TestTemplate {
            provider: "aws".into(),
            name: "STS Get Caller Identity".into(),
            description: "Verify AWS credentials via STS".into(),
            method: "POST".into(),
            url: "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15".into(),
            injection: KeyInjection::Header { name: "Authorization".into() },
            expected_status: 200,
        },
    ]
}
```

Backend executor:

```rust
pub async fn execute_playground(
    State(state): State<AppState>,
    Json(request): Json<PlaygroundRequest>,
) -> impl IntoResponse {
    // Retrieve the actual key value
    let vault = state.vault.read().await;
    let key_value = vault.get(&request.key_name).await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    // Build the proxied request
    let client = reqwest::Client::new();
    let mut req_builder = client.request(
        request.method.parse().unwrap_or(reqwest::Method::GET),
        &request.url,
    );

    // Inject the key
    req_builder = match &request.injection {
        KeyInjection::BearerToken => {
            req_builder.bearer_auth(key_value.value.expose())
        }
        KeyInjection::Header { name } => {
            req_builder.header(name, key_value.value.expose())
        }
        KeyInjection::QueryParam { name } => {
            req_builder.query(&[(name.as_str(), key_value.value.expose())])
        }
        KeyInjection::BasicAuth { username } => {
            req_builder.basic_auth(username, Some(key_value.value.expose()))
        }
    };

    let start = std::time::Instant::now();
    let response = req_builder.send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let duration = start.elapsed();
    let status = response.status();
    let headers: HashMap<String, String> = response.headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = response.text().await.unwrap_or_default();

    Json(PlaygroundResponse {
        status_code: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or("").into(),
        headers,
        body,
        duration_ms: duration.as_millis() as u64,
        success: status.is_success(),
    })
}
```

### MCP Tools

No new MCP tools. The playground is a web-only feature.

### CLI Commands

No new CLI commands. CLI users can use `curl` directly.

### Web UI Changes

Interactive request builder with provider templates and response viewer.

## Dependencies

No new Rust dependencies. Uses existing `reqwest` for proxied requests.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_templates_exist() {
        let templates = get_provider_templates();
        assert!(templates.len() >= 4);
        assert!(templates.iter().any(|t| t.provider == "stripe"));
        assert!(templates.iter().any(|t| t.provider == "github"));
    }

    #[test]
    fn test_playground_request_parsing() {
        let json = r#"{
            "key_name": "STRIPE_KEY",
            "method": "GET",
            "url": "https://api.stripe.com/v1/charges",
            "injection": {"basic_auth": {"username": ""}}
        }"#;
        let req: PlaygroundRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.key_name, "STRIPE_KEY");
    }

    #[test]
    fn test_response_serialization() {
        let resp = PlaygroundResponse {
            status_code: 200,
            status_text: "OK".into(),
            headers: HashMap::new(),
            body: r#"{"data": []}"#.into(),
            duration_ms: 150,
            success: true,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("200"));
    }

    #[test]
    fn test_bearer_injection() {
        // Verify that bearer token injection constructs correct header
        let injection = KeyInjection::BearerToken;
        assert!(matches!(injection, KeyInjection::BearerToken));
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_playground_proxies_request() {
    let app = test_app_with_keys(&[("TEST_KEY", "test_value")]).await;
    // Use a mock HTTP server
    let mock = mockito::mock("GET", "/test")
        .match_header("Authorization", "Bearer test_value")
        .with_status(200)
        .with_body(r#"{"ok": true}"#)
        .create();

    let response = app.post("/api/playground/test")
        .json(&PlaygroundRequest {
            key_name: "TEST_KEY".into(),
            method: "GET".into(),
            url: format!("{}/test", mockito::server_url()),
            injection: KeyInjection::BearerToken,
            body: None,
            headers: None,
        })
        .await;
    let result: PlaygroundResponse = response.json().await;
    assert_eq!(result.status_code, 200);
    assert!(result.success);
}
```

## Example Usage

```
Browser: http://localhost:3001/playground

┌─ API Playground ──────────────────────────────────────────┐
│                                                           │
│  Key: [STRIPE_SECRET_KEY  v]  Template: [List Charges  v] │
│                                                           │
│  Method: [GET v]                                          │
│  URL:    [https://api.stripe.com/v1/charges?limit=1    ]  │
│  Auth:   [Basic Auth (empty username, key as password)  ] │
│                                                           │
│  Headers:                                                 │
│  [Content-Type    ] [application/json     ]               │
│                                                           │
│                              [Send Request]               │
├───────────────────────────────────────────────────────────┤
│  Response (200 OK) — 142ms                                │
│  ┌───────────────────────────────────────────────────┐    │
│  │ {                                                 │    │
│  │   "data": [                                       │    │
│  │     {                                             │    │
│  │       "id": "ch_3N...",                           │    │
│  │       "amount": 2000,                             │    │
│  │       "status": "succeeded"                       │    │
│  │     }                                             │    │
│  │   ],                                              │    │
│  │   "has_more": true                                │    │
│  │ }                                                 │    │
│  └───────────────────────────────────────────────────┘    │
│  Key is valid and working.                                │
└───────────────────────────────────────────────────────────┘
```
