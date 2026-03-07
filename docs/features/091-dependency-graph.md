# Feature 091: Dependency Graph

## Status: Planned
## Phase: 10 (v3.0)
## Priority: High

## Problem

In microservice architectures, multiple services share the same secrets. When a key
needs rotation, engineers cannot quickly determine which services will be affected.
Relationships between keys and services are documented informally (if at all), making
it impossible to answer questions like "which services use STRIPE_SECRET_KEY?" or
"what keys does the payment-service need?"

## Solution

Build an interactive dependency graph visualization using D3.js force-directed layout.
The graph shows keys as nodes, services as nodes, and edges representing usage
relationships. Users can click nodes to see details, filter by service or key, and
simulate the impact of revoking a key. Dependency data is declared via metadata
annotations on keys and discovered via environment variable scanning.

## Implementation

### Files to Create/Modify

```
pqvault-web/
  src/
    routes/
      api/
        graph.rs        # GET /api/graph - dependency graph data
    graph/
      mod.rs            # Graph module root
      builder.rs        # Build graph from key metadata and scans
      scanner.rs        # Environment variable scanner for auto-discovery
  templates/
    graph.html          # Graph visualization page
  static/
    js/
      graph.js          # D3.js force-directed graph rendering
    css/
      graph.css         # Graph styles
```

### Data Model Changes

```rust
/// A node in the dependency graph
#[derive(Serialize, Clone)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: GraphNodeType,
    pub metadata: HashMap<String, String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum GraphNodeType {
    Secret,         // A vault key
    Service,        // A consuming service/application
    Provider,       // External provider (Stripe, AWS, etc.)
    Environment,    // prod, staging, dev
}

/// An edge connecting two nodes
#[derive(Serialize, Clone)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub edge_type: GraphEdgeType,
    pub label: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum GraphEdgeType {
    Uses,           // Service uses a secret
    ProvidedBy,     // Secret is provided by a provider
    DeployedTo,     // Service deployed to environment
    DependsOn,      // Service depends on another service
}

/// Complete graph data for visualization
#[derive(Serialize)]
pub struct DependencyGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub stats: GraphStats,
}

#[derive(Serialize)]
pub struct GraphStats {
    pub total_secrets: usize,
    pub total_services: usize,
    pub total_providers: usize,
    pub total_edges: usize,
    pub orphaned_secrets: usize,    // Secrets not used by any service
    pub critical_secrets: Vec<String>, // Used by 3+ services
}

/// Dependency declaration on a key
#[derive(Serialize, Deserialize, Clone)]
pub struct KeyDependency {
    pub services: Vec<String>,
    pub environments: Vec<String>,
    pub notes: Option<String>,
}

/// Graph builder
pub struct GraphBuilder {
    nodes: HashMap<String, GraphNode>,
    edges: Vec<GraphEdge>,
}

impl GraphBuilder {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_secret(&mut self, key: &str, provider: Option<&str>, deps: &KeyDependency) {
        // Add secret node
        self.nodes.insert(key.to_string(), GraphNode {
            id: key.to_string(),
            label: key.to_string(),
            node_type: GraphNodeType::Secret,
            metadata: HashMap::new(),
        });

        // Add provider node and edge
        if let Some(prov) = provider {
            let prov_id = format!("provider:{}", prov);
            self.nodes.entry(prov_id.clone()).or_insert(GraphNode {
                id: prov_id.clone(),
                label: prov.to_string(),
                node_type: GraphNodeType::Provider,
                metadata: HashMap::new(),
            });
            self.edges.push(GraphEdge {
                source: key.to_string(),
                target: prov_id,
                edge_type: GraphEdgeType::ProvidedBy,
                label: None,
            });
        }

        // Add service nodes and edges
        for service in &deps.services {
            let svc_id = format!("service:{}", service);
            self.nodes.entry(svc_id.clone()).or_insert(GraphNode {
                id: svc_id.clone(),
                label: service.clone(),
                node_type: GraphNodeType::Service,
                metadata: HashMap::new(),
            });
            self.edges.push(GraphEdge {
                source: svc_id,
                target: key.to_string(),
                edge_type: GraphEdgeType::Uses,
                label: None,
            });
        }
    }

    pub fn build(self) -> DependencyGraph {
        let nodes: Vec<GraphNode> = self.nodes.into_values().collect();
        let secret_count = nodes.iter().filter(|n| matches!(n.node_type, GraphNodeType::Secret)).count();
        let service_count = nodes.iter().filter(|n| matches!(n.node_type, GraphNodeType::Service)).count();
        let provider_count = nodes.iter().filter(|n| matches!(n.node_type, GraphNodeType::Provider)).count();

        DependencyGraph {
            stats: GraphStats {
                total_secrets: secret_count,
                total_services: service_count,
                total_providers: provider_count,
                total_edges: self.edges.len(),
                orphaned_secrets: 0,  // Calculated after build
                critical_secrets: vec![],
            },
            nodes,
            edges: self.edges,
        }
    }
}
```

### MCP Tools

No new MCP tools directly. The graph data API is consumed by the web UI.

### CLI Commands

```bash
# Show dependency tree in CLI
pqvault deps STRIPE_SECRET_KEY

# Show all services for a key
pqvault deps --key STRIPE_SECRET_KEY --services

# Show all keys for a service
pqvault deps --service payment-api --keys

# Declare a dependency
pqvault deps add STRIPE_SECRET_KEY --service payment-api --service checkout-service

# Export graph as DOT format
pqvault deps export --format dot > deps.dot
```

### Web UI Changes

D3.js force-directed graph:

```javascript
// graph.js
async function renderGraph() {
    const response = await fetch('/api/graph');
    const data = await response.json();

    const width = document.getElementById('graph-container').clientWidth;
    const height = 600;

    const svg = d3.select('#graph-container')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.edges).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(30));

    const link = svg.append('g')
        .selectAll('line')
        .data(data.edges)
        .join('line')
        .attr('stroke', d => edgeColor(d.edge_type))
        .attr('stroke-width', 1.5);

    const node = svg.append('g')
        .selectAll('g')
        .data(data.nodes)
        .join('g')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));

    node.append('circle')
        .attr('r', d => nodeRadius(d.node_type))
        .attr('fill', d => nodeColor(d.node_type));

    node.append('text')
        .text(d => d.label)
        .attr('dx', 12)
        .attr('dy', 4)
        .style('font-size', '11px');

    simulation.on('tick', () => {
        link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });
}
```

## Dependencies

No new Rust dependencies. D3.js loaded via CDN:

```html
<script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_builder_basic() {
        let mut builder = GraphBuilder::new();
        builder.add_secret("STRIPE_KEY", Some("stripe"), &KeyDependency {
            services: vec!["payment-api".into()],
            environments: vec!["production".into()],
            notes: None,
        });
        let graph = builder.build();
        assert_eq!(graph.stats.total_secrets, 1);
        assert_eq!(graph.stats.total_services, 1);
        assert_eq!(graph.stats.total_providers, 1);
        assert_eq!(graph.stats.total_edges, 2); // uses + provided_by
    }

    #[test]
    fn test_shared_secret() {
        let mut builder = GraphBuilder::new();
        builder.add_secret("DB_URL", None, &KeyDependency {
            services: vec!["api".into(), "worker".into(), "scheduler".into()],
            environments: vec![],
            notes: None,
        });
        let graph = builder.build();
        assert_eq!(graph.stats.total_services, 3);
        // DB_URL is used by 3 services — it should be flagged as critical
    }

    #[test]
    fn test_graph_serialization() {
        let graph = DependencyGraph {
            nodes: vec![GraphNode {
                id: "KEY".into(),
                label: "KEY".into(),
                node_type: GraphNodeType::Secret,
                metadata: HashMap::new(),
            }],
            edges: vec![],
            stats: GraphStats::default(),
        };
        let json = serde_json::to_string(&graph).unwrap();
        assert!(json.contains("KEY"));
        assert!(json.contains("secret"));
    }
}
```

## Example Usage

```
Browser: http://localhost:3001/graph

Interactive force-directed graph showing:

    [Stripe] ---- STRIPE_SECRET_KEY ---- [payment-api]
                                    \
                                     --- [checkout-svc]

    [AWS]    ---- AWS_ACCESS_KEY    ---- [api-server]
             \                      \
              --- AWS_SECRET_KEY     --- [worker]
                                     \
                                      -- [scheduler]

    [Custom] ---- DATABASE_URL     ---- [api-server]
                                    \--- [worker]
                                    \--- [scheduler]
                                    \--- [admin-panel]

Legend:
  (blue circle)  = Secret
  (green square) = Service
  (orange diamond) = Provider
  — Uses  ·· Provided By

Stats sidebar:
  Secrets: 12 | Services: 6 | Providers: 4
  Critical: DATABASE_URL (used by 4 services)
  Orphaned: LEGACY_KEY (no service uses it)
```
