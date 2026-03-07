# Feature 040: Grafana/Prometheus Export

## Status: Done
## Phase: 4 (v2.4)
## Priority: Low

## Problem

PQVault's metrics exist in isolation and cannot be integrated with existing observability stacks. Teams using Grafana, Prometheus, Datadog, or other monitoring tools must rely solely on PQVault's built-in dashboard. There is no standard metrics endpoint for scraping, making it impossible to create unified dashboards that show vault metrics alongside application metrics, infrastructure metrics, and cost data.

## Solution

Expose a `/metrics` HTTP endpoint in Prometheus exposition format. The endpoint exports key usage counts, cost data, health scores, latency percentiles, error rates, and agent activity metrics. This allows any Prometheus-compatible scraper to collect PQVault metrics and visualize them in Grafana or any other compatible tool. Includes a sample Grafana dashboard JSON for quick setup.

## Implementation

### Files to Create/Modify

- `crates/pqvault-web/src/metrics.rs` — Prometheus metrics collector and endpoint handler
- `crates/pqvault-web/src/routes.rs` — Register `/metrics` route
- `crates/pqvault-core/src/telemetry.rs` — Core metrics recording interface
- `docs/grafana/pqvault-dashboard.json` — Sample Grafana dashboard

### Data Model Changes

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Prometheus-compatible metric types
#[derive(Debug, Clone)]
pub enum MetricValue {
    Counter(f64),
    Gauge(f64),
    Histogram(HistogramData),
}

#[derive(Debug, Clone)]
pub struct HistogramData {
    pub sum: f64,
    pub count: u64,
    pub buckets: Vec<(f64, u64)>, // (le, count)
}

/// Labels for metric dimensions
pub type Labels = Vec<(String, String)>;

/// Single metric with labels
#[derive(Debug, Clone)]
pub struct Metric {
    pub name: String,
    pub help: String,
    pub metric_type: String, // "counter", "gauge", "histogram"
    pub values: Vec<(Labels, MetricValue)>,
}

/// Metrics registry
pub struct MetricsRegistry {
    metrics: Arc<RwLock<Vec<Metric>>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Render all metrics in Prometheus exposition format
    pub async fn render(&self) -> String {
        let metrics = self.metrics.read().await;
        let mut output = String::new();

        for metric in metrics.iter() {
            output.push_str(&format!("# HELP {} {}\n", metric.name, metric.help));
            output.push_str(&format!("# TYPE {} {}\n", metric.name, metric.metric_type));

            for (labels, value) in &metric.values {
                let label_str = if labels.is_empty() {
                    String::new()
                } else {
                    let pairs: Vec<String> = labels.iter()
                        .map(|(k, v)| format!("{}=\"{}\"", k, v))
                        .collect();
                    format!("{{{}}}", pairs.join(","))
                };

                match value {
                    MetricValue::Counter(v) | MetricValue::Gauge(v) => {
                        output.push_str(&format!("{}{} {}\n", metric.name, label_str, v));
                    }
                    MetricValue::Histogram(h) => {
                        for (le, count) in &h.buckets {
                            let bucket_labels = format!(
                                "{}le=\"{}\"{}",
                                if labels.is_empty() { "{" } else { &label_str[..label_str.len()-1] },
                                if *le == f64::INFINITY { "+Inf".to_string() } else { le.to_string() },
                                if labels.is_empty() { "}" } else { "}" }
                            );
                            output.push_str(&format!("{}_bucket{} {}\n", metric.name, bucket_labels, count));
                        }
                        output.push_str(&format!("{}_sum{} {}\n", metric.name, label_str, h.sum));
                        output.push_str(&format!("{}_count{} {}\n", metric.name, label_str, h.count));
                    }
                }
            }
            output.push('\n');
        }

        output
    }

    /// Collect current vault metrics
    pub async fn collect(&self, vault: &Vault, health: &HealthService) {
        let mut metrics = Vec::new();

        // Key counts by category
        let key_counts = vault.count_by_category().await;
        metrics.push(Metric {
            name: "pqvault_keys_total".into(),
            help: "Total number of keys in vault".into(),
            metric_type: "gauge".into(),
            values: key_counts.into_iter().map(|(cat, count)| {
                (vec![("category".into(), cat)], MetricValue::Gauge(count as f64))
            }).collect(),
        });

        // Request counts by key and type
        let requests = vault.request_counts().await;
        metrics.push(Metric {
            name: "pqvault_requests_total".into(),
            help: "Total requests per key".into(),
            metric_type: "counter".into(),
            values: requests.into_iter().map(|(key, access_type, count)| {
                (vec![
                    ("key".into(), key),
                    ("type".into(), access_type),
                ], MetricValue::Counter(count as f64))
            }).collect(),
        });

        // Cost per key
        let costs = vault.daily_costs().await;
        metrics.push(Metric {
            name: "pqvault_cost_usd".into(),
            help: "Daily cost in USD per key".into(),
            metric_type: "gauge".into(),
            values: costs.into_iter().map(|(key, cost)| {
                (vec![("key".into(), key)], MetricValue::Gauge(cost))
            }).collect(),
        });

        // Health scores
        let scores = health.all_scores().await;
        metrics.push(Metric {
            name: "pqvault_health_score".into(),
            help: "Health score per key (0-100)".into(),
            metric_type: "gauge".into(),
            values: scores.into_iter().map(|(key, score)| {
                (vec![("key".into(), key)], MetricValue::Gauge(score))
            }).collect(),
        });

        // Active agents
        let agents = vault.active_agent_count().await;
        metrics.push(Metric {
            name: "pqvault_active_agents".into(),
            help: "Number of active agent sessions".into(),
            metric_type: "gauge".into(),
            values: vec![(vec![], MetricValue::Gauge(agents as f64))],
        });

        *self.metrics.write().await = metrics;
    }
}
```

### HTTP Handler

```rust
use axum::{extract::State, response::IntoResponse};

/// GET /metrics — Prometheus scrape endpoint
pub async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Collect fresh metrics
    state.metrics_registry.collect(&state.vault, &state.health).await;
    let body = state.metrics_registry.render().await;

    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}
```

### MCP Tools

No new MCP tools — this is a web-only endpoint. The metrics are derived from existing vault data.

### CLI Commands

```bash
# View metrics in Prometheus format
pqvault metrics
# # HELP pqvault_keys_total Total number of keys in vault
# # TYPE pqvault_keys_total gauge
# pqvault_keys_total{category="api-keys"} 15
# pqvault_keys_total{category="database"} 8
# ...

# Test metrics endpoint
curl http://localhost:3001/metrics

# Configure Prometheus scrape (prometheus.yml):
# scrape_configs:
#   - job_name: 'pqvault'
#     scrape_interval: 30s
#     static_configs:
#       - targets: ['localhost:3001']
```

### Web UI Changes

- Link to `/metrics` endpoint in settings page
- Prometheus/Grafana integration instructions
- "Copy scrape config" button

## Dependencies

- `axum = "0.8"` (existing) — HTTP endpoint
- `tokio = "1"` (existing) — Async runtime
- No new crate dependencies (Prometheus format is simple text)

## Testing

### Unit Tests

```rust
#[test]
fn prometheus_counter_format() {
    let metric = Metric {
        name: "pqvault_requests_total".into(),
        help: "Total requests".into(),
        metric_type: "counter".into(),
        values: vec![
            (vec![("key".into(), "API_KEY".into())], MetricValue::Counter(42.0)),
        ],
    };
    let output = render_metric(&metric);
    assert!(output.contains("# HELP pqvault_requests_total Total requests"));
    assert!(output.contains("# TYPE pqvault_requests_total counter"));
    assert!(output.contains(r#"pqvault_requests_total{key="API_KEY"} 42"#));
}

#[test]
fn prometheus_gauge_no_labels() {
    let metric = Metric {
        name: "pqvault_active_agents".into(),
        help: "Active agents".into(),
        metric_type: "gauge".into(),
        values: vec![(vec![], MetricValue::Gauge(3.0))],
    };
    let output = render_metric(&metric);
    assert!(output.contains("pqvault_active_agents 3"));
}

#[test]
fn prometheus_histogram_buckets() {
    let metric = Metric {
        name: "pqvault_request_duration_seconds".into(),
        help: "Request duration".into(),
        metric_type: "histogram".into(),
        values: vec![(vec![], MetricValue::Histogram(HistogramData {
            sum: 5.5,
            count: 100,
            buckets: vec![(0.01, 50), (0.1, 80), (1.0, 99), (f64::INFINITY, 100)],
        }))],
    };
    let output = render_metric(&metric);
    assert!(output.contains(r#"_bucket{le="0.01"} 50"#));
    assert!(output.contains(r#"_bucket{le="+Inf"} 100"#));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn metrics_endpoint_returns_prometheus_format() {
    let app = test_app().await;
    let response = app.client
        .get(&format!("http://{}/metrics", app.addr))
        .send().await.unwrap();

    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert!(body.contains("# HELP pqvault_keys_total"));
    assert!(body.contains("# TYPE pqvault_keys_total gauge"));
}

#[tokio::test]
async fn metrics_content_type_correct() {
    let app = test_app().await;
    let response = app.client
        .get(&format!("http://{}/metrics", app.addr))
        .send().await.unwrap();

    let ct = response.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.contains("text/plain"));
}
```

### Manual Verification

1. Start PQVault web server
2. Visit `/metrics` in browser — verify valid Prometheus format
3. Configure Prometheus to scrape the endpoint
4. Import sample Grafana dashboard
5. Verify graphs update with real vault activity

## Example Usage

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'pqvault'
    scrape_interval: 30s
    metrics_path: /metrics
    static_configs:
      - targets: ['localhost:3001']

# Grafana dashboard queries:
# Total keys: pqvault_keys_total
# Request rate: rate(pqvault_requests_total[5m])
# Cost per hour: pqvault_cost_usd
# Health scores: pqvault_health_score
# Active agents: pqvault_active_agents
```

```bash
# Quick test with curl:
curl -s http://localhost:3001/metrics | grep pqvault_keys_total
# pqvault_keys_total{category="api-keys"} 15
# pqvault_keys_total{category="database"} 8
```
