# Feature 092: Impact Analysis

## Status: Planned
## Phase: 10 (v3.0)
## Priority: High

## Problem

Before revoking or rotating a key, engineers need to understand the blast radius.
Currently they must manually trace which services, environments, and integrations
depend on a key. Getting this wrong causes outages — revoking a shared database URL
can take down multiple services simultaneously. There is no automated way to assess
the impact of a key change before executing it.

## Solution

Implement an impact analysis engine that answers "what breaks if I change this key?"
It uses the dependency graph (Feature 091), deployment metadata, and historical
access patterns to generate a detailed impact report. Before rotation or deletion,
users see affected services, estimated downtime, and rollback instructions. The
analysis can run in dry-run mode as part of CI/CD pipelines.

## Implementation

### Files to Create/Modify

```
pqvault-mcp/
  src/
    impact/
      mod.rs           # Impact analysis module root
      analyzer.rs      # Core impact analysis engine
      reporter.rs      # Impact report generation
    tools/
      impact_check.rs  # MCP tool: analyze impact of key change

pqvault-web/
  src/
    routes/
      api/
        impact.rs      # GET /api/impact/:key - impact analysis endpoint
  templates/
    components/
      impact_report.html  # Impact report visualization
```

### Data Model Changes

```rust
/// Impact analysis request
#[derive(Deserialize)]
pub struct ImpactRequest {
    pub key: String,
    pub action: ImpactAction,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactAction {
    Revoke,
    Rotate,
    Delete,
    Expire,
}

/// Complete impact analysis result
#[derive(Serialize)]
pub struct ImpactReport {
    pub key: String,
    pub action: String,
    pub severity: ImpactSeverity,
    pub affected_services: Vec<AffectedService>,
    pub affected_environments: Vec<String>,
    pub estimated_downtime: Option<String>,
    pub mitigation_steps: Vec<String>,
    pub rollback_plan: Vec<String>,
    pub safe_to_proceed: bool,
    pub warnings: Vec<String>,
}

#[derive(Serialize)]
pub enum ImpactSeverity {
    None,        // No services affected
    Low,         // 1 non-critical service
    Medium,      // 1 critical or 2+ non-critical services
    High,        // 2+ critical services
    Critical,    // Production database or auth key
}

#[derive(Serialize)]
pub struct AffectedService {
    pub name: String,
    pub environment: String,
    pub criticality: ServiceCriticality,
    pub last_accessed: Option<DateTime<Utc>>,
    pub access_frequency: String,     // "12/day", "3/hour"
    pub auto_rotation_support: bool,  // Can handle key change gracefully
}

#[derive(Serialize)]
pub enum ServiceCriticality {
    Critical,    // Revenue-impacting, user-facing
    High,        // Important internal service
    Medium,      // Development/staging
    Low,         // Testing, non-essential
}

pub struct ImpactAnalyzer {
    graph: DependencyGraph,
    audit_store: Arc<AuditStore>,
    service_registry: ServiceRegistry,
}

impl ImpactAnalyzer {
    pub async fn analyze(&self, key: &str, action: &ImpactAction) -> Result<ImpactReport> {
        // Find all services that use this key
        let dependents = self.graph.edges.iter()
            .filter(|e| e.target == key && matches!(e.edge_type, GraphEdgeType::Uses))
            .map(|e| e.source.clone())
            .collect::<Vec<_>>();

        let mut affected_services = Vec::new();
        for service_id in &dependents {
            let service_name = service_id.strip_prefix("service:").unwrap_or(service_id);
            let service_info = self.service_registry.get(service_name).await;
            let last_access = self.audit_store.last_access(key, service_name).await?;
            let frequency = self.audit_store.access_frequency(key, service_name, 7).await?;

            affected_services.push(AffectedService {
                name: service_name.to_string(),
                environment: service_info.as_ref()
                    .map_or("unknown".into(), |s| s.environment.clone()),
                criticality: service_info.as_ref()
                    .map_or(ServiceCriticality::Medium, |s| s.criticality.clone()),
                last_accessed: last_access,
                access_frequency: format!("{}/day", frequency),
                auto_rotation_support: service_info.as_ref()
                    .map_or(false, |s| s.supports_auto_rotation),
            });
        }

        let severity = calculate_severity(&affected_services);
        let safe = matches!(severity, ImpactSeverity::None | ImpactSeverity::Low);

        let mitigation = generate_mitigation_steps(key, action, &affected_services);
        let rollback = generate_rollback_plan(key, action);

        Ok(ImpactReport {
            key: key.to_string(),
            action: format!("{:?}", action),
            severity,
            affected_services,
            affected_environments: extract_environments(&dependents),
            estimated_downtime: estimate_downtime(&affected_services, action),
            mitigation_steps: mitigation,
            rollback_plan: rollback,
            safe_to_proceed: safe,
            warnings: generate_warnings(key, &affected_services),
        })
    }
}

fn calculate_severity(services: &[AffectedService]) -> ImpactSeverity {
    let critical_count = services.iter()
        .filter(|s| matches!(s.criticality, ServiceCriticality::Critical))
        .count();
    let total = services.len();

    match (critical_count, total) {
        (0, 0) => ImpactSeverity::None,
        (0, 1) => ImpactSeverity::Low,
        (0, _) => ImpactSeverity::Medium,
        (1, _) => ImpactSeverity::High,
        (_, _) => ImpactSeverity::Critical,
    }
}
```

### MCP Tools

```rust
#[tool(description = "Analyze the impact of revoking, rotating, or deleting a key")]
async fn impact_check(
    /// Key to analyze
    key: String,
    /// Action to simulate: revoke, rotate, delete
    action: String,
) -> Result<CallToolResult> {
    let analyzer = ImpactAnalyzer::new(&config).await?;
    let action = match action.as_str() {
        "revoke" => ImpactAction::Revoke,
        "rotate" => ImpactAction::Rotate,
        "delete" => ImpactAction::Delete,
        _ => return Err(anyhow!("Unknown action: {}", action)),
    };
    let report = analyzer.analyze(&key, &action).await?;
    Ok(format_impact_report(&report))
}
```

### CLI Commands

```bash
# Check impact before rotating
pqvault impact STRIPE_SECRET_KEY --action rotate

# Check impact before deleting
pqvault impact OLD_API_KEY --action delete

# JSON output for CI integration
pqvault impact DATABASE_URL --action revoke --format json

# CI gate: fail if impact is high or critical
pqvault impact SHARED_KEY --action rotate --max-severity medium
```

### Web UI Changes

Impact report shown as a modal before destructive operations and as a dedicated page.

## Dependencies

Requires Feature 091 (Dependency Graph) for service-to-key relationships.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_none() {
        let services: Vec<AffectedService> = vec![];
        assert!(matches!(calculate_severity(&services), ImpactSeverity::None));
    }

    #[test]
    fn test_severity_critical() {
        let services = vec![
            mock_service("api", ServiceCriticality::Critical),
            mock_service("web", ServiceCriticality::Critical),
        ];
        assert!(matches!(calculate_severity(&services), ImpactSeverity::Critical));
    }

    #[test]
    fn test_severity_medium() {
        let services = vec![
            mock_service("svc-a", ServiceCriticality::Low),
            mock_service("svc-b", ServiceCriticality::Low),
        ];
        assert!(matches!(calculate_severity(&services), ImpactSeverity::Medium));
    }

    #[test]
    fn test_safe_to_proceed_low() {
        let report = ImpactReport {
            severity: ImpactSeverity::Low,
            safe_to_proceed: true,
            ..mock_report()
        };
        assert!(report.safe_to_proceed);
    }

    #[test]
    fn test_mitigation_steps_generated() {
        let services = vec![mock_service("api", ServiceCriticality::High)];
        let steps = generate_mitigation_steps("DB_URL", &ImpactAction::Rotate, &services);
        assert!(!steps.is_empty());
        assert!(steps.iter().any(|s| s.contains("api")));
    }
}
```

## Example Usage

```
$ pqvault impact DATABASE_URL --action revoke

  Impact Analysis: DATABASE_URL
  ══════════════════════════════════════════════════

  Action: REVOKE
  Severity: CRITICAL

  Affected Services (4):
    Service          Environment  Criticality  Usage       Auto-rotate
    ───────────────  ───────────  ───────────  ──────────  ───────────
    api-server       production   CRITICAL     45/day      No
    worker           production   HIGH         120/day     No
    scheduler        production   MEDIUM       8/day       No
    admin-panel      staging      LOW          2/day       No

  Affected Environments: production, staging
  Estimated Downtime: 5-15 minutes (until all services restart)

  Mitigation Steps:
    1. Prepare new DATABASE_URL with same connection params
    2. Update api-server deployment config
    3. Update worker deployment config
    4. Update scheduler deployment config
    5. Deploy all services simultaneously
    6. Verify all services healthy before revoking old key

  Rollback Plan:
    1. Restore previous DATABASE_URL from version history
    2. Restart affected services
    3. Verify database connectivity

  Warnings:
    - api-server does NOT support auto-rotation
    - 4 services in production will be affected
    - Last access was 2 minutes ago (actively in use)

  RECOMMENDATION: Do NOT proceed without coordinated deployment.
  Use `pqvault rotate DATABASE_URL --coordinated` for safe rotation.
```
