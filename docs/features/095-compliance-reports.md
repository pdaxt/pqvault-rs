# Feature 095: Compliance Reports

## Status: Done
## Phase: 10 (v3.0)
## Priority: Medium

## Problem

Organizations pursuing SOC2, ISO 27001, or PCI-DSS certification must produce evidence
of proper secret management practices. Auditors ask for documentation of key rotation
policies, access controls, encryption methods, and audit trails. Assembling this evidence
manually from CLI output and dashboard screenshots is tedious and error-prone, often
taking days of engineering time per audit cycle.

## Solution

Auto-generate compliance evidence packages tailored to specific frameworks (SOC2,
ISO 27001, PCI-DSS). Each package includes required documentation: encryption
methodology, key rotation compliance, access control matrix, audit trail excerpts,
and incident response procedures. Reports map PQVault capabilities to specific
compliance control requirements with evidence references.

## Implementation

### Files to Create/Modify

```
pqvault-audit-mcp/
  src/
    compliance/
      mod.rs           # Compliance module root
      frameworks.rs    # Framework definitions (SOC2, ISO, PCI)
      evidence.rs      # Evidence collection and mapping
      generator.rs     # Report generation engine
      controls.rs      # Control requirement definitions
    tools/
      compliance_report.rs   # MCP tool: generate compliance report
      compliance_status.rs   # MCP tool: compliance readiness check
```

### Data Model Changes

```rust
/// Compliance framework definition
#[derive(Serialize, Deserialize, Clone)]
pub struct ComplianceFramework {
    pub name: String,           // "SOC2 Type II"
    pub version: String,        // "2017"
    pub controls: Vec<Control>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Control {
    pub id: String,             // "CC6.1"
    pub category: String,       // "Logical and Physical Access Controls"
    pub requirement: String,    // Description of what's required
    pub pqvault_evidence: Vec<EvidenceMapping>,
    pub status: ControlStatus,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum ControlStatus {
    Met,
    PartiallyMet { gap: String },
    NotMet { recommendation: String },
    NotApplicable,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EvidenceMapping {
    pub evidence_type: EvidenceType,
    pub description: String,
    pub data_source: String,
    pub auto_collected: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum EvidenceType {
    Configuration,    // System configuration showing control
    AuditLog,         // Audit trail demonstrating compliance
    Policy,           // Documented policy
    Screenshot,       // UI evidence
    Metric,           // Quantitative measurement
    TestResult,       // Automated test output
}

/// Generated compliance report
#[derive(Serialize)]
pub struct ComplianceReport {
    pub framework: String,
    pub generated_at: DateTime<Utc>,
    pub period: CompliancePeriod,
    pub overall_status: OverallStatus,
    pub controls_summary: ControlsSummary,
    pub sections: Vec<ReportSection>,
}

#[derive(Serialize)]
pub struct CompliancePeriod {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct OverallStatus {
    pub met: usize,
    pub partially_met: usize,
    pub not_met: usize,
    pub not_applicable: usize,
    pub compliance_percentage: f64,
}

#[derive(Serialize)]
pub struct ControlsSummary {
    pub total_controls: usize,
    pub controls: Vec<ControlEvidence>,
}

#[derive(Serialize)]
pub struct ControlEvidence {
    pub control_id: String,
    pub requirement: String,
    pub status: String,
    pub evidence: Vec<EvidenceItem>,
    pub notes: Option<String>,
}

#[derive(Serialize)]
pub struct EvidenceItem {
    pub evidence_type: String,
    pub description: String,
    pub data: String,   // JSON blob, metric value, or reference
    pub collected_at: DateTime<Utc>,
}

/// SOC2 framework controls relevant to secret management
pub fn soc2_controls() -> Vec<Control> {
    vec![
        Control {
            id: "CC6.1".into(),
            category: "Logical and Physical Access Controls".into(),
            requirement: "The entity implements logical access security software, infrastructure, and architectures over protected information assets".into(),
            pqvault_evidence: vec![
                EvidenceMapping {
                    evidence_type: EvidenceType::Configuration,
                    description: "AES-256-GCM encryption with ML-KEM-768 post-quantum KEM".into(),
                    data_source: "vault_config".into(),
                    auto_collected: true,
                },
            ],
            status: ControlStatus::Met,
        },
        Control {
            id: "CC6.3".into(),
            category: "Logical and Physical Access Controls".into(),
            requirement: "The entity authorizes, modifies, or removes access based on authorization".into(),
            pqvault_evidence: vec![
                EvidenceMapping {
                    evidence_type: EvidenceType::AuditLog,
                    description: "Tamper-evident audit log of all access events".into(),
                    data_source: "audit_chain".into(),
                    auto_collected: true,
                },
            ],
            status: ControlStatus::Met,
        },
        Control {
            id: "CC7.2".into(),
            category: "System Operations".into(),
            requirement: "The entity monitors system components for anomalies".into(),
            pqvault_evidence: vec![
                EvidenceMapping {
                    evidence_type: EvidenceType::Metric,
                    description: "Health monitoring scores and anomaly detection".into(),
                    data_source: "health_mcp".into(),
                    auto_collected: true,
                },
            ],
            status: ControlStatus::Met,
        },
    ]
}
```

### MCP Tools

```rust
#[tool(description = "Generate a compliance evidence report for a specific framework")]
async fn compliance_report(
    /// Framework: soc2, iso27001, pci-dss
    framework: String,
    /// Report period start date
    from: String,
    /// Report period end date
    #[arg(default = "today")]
    to: String,
    /// Output format: json, pdf, html
    #[arg(default = "json")]
    format: String,
) -> Result<CallToolResult> { /* ... */ }

#[tool(description = "Check compliance readiness against a framework")]
async fn compliance_status(
    /// Framework: soc2, iso27001, pci-dss
    framework: String,
) -> Result<CallToolResult> { /* ... */ }
```

### CLI Commands

```bash
# Generate SOC2 compliance report
pqvault compliance report soc2 --from 2025-01-01 --to 2025-03-31

# Check readiness status
pqvault compliance status soc2

# Export as PDF
pqvault compliance report iso27001 --format pdf --output compliance.pdf

# List controls and their status
pqvault compliance controls soc2
```

### Web UI Changes

None in this phase. Compliance reports are generated as downloadable documents.

## Dependencies

No new Rust dependencies.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soc2_controls_exist() {
        let controls = soc2_controls();
        assert!(controls.len() >= 3);
        assert!(controls.iter().any(|c| c.id == "CC6.1"));
    }

    #[test]
    fn test_compliance_percentage() {
        let status = OverallStatus {
            met: 8, partially_met: 1, not_met: 1, not_applicable: 0,
            compliance_percentage: 80.0,
        };
        let total = status.met + status.partially_met + status.not_met;
        assert_eq!(status.compliance_percentage, (status.met as f64 / total as f64) * 100.0);
    }

    #[test]
    fn test_evidence_mapping() {
        let control = &soc2_controls()[0];
        assert!(!control.pqvault_evidence.is_empty());
        assert!(control.pqvault_evidence[0].auto_collected);
    }

    #[test]
    fn test_control_status_serialization() {
        let status = ControlStatus::PartiallyMet { gap: "Missing IP restrictions".into() };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("partially_met"));
    }
}
```

## Example Usage

```
$ pqvault compliance status soc2

  SOC2 Type II Readiness
  ══════════════════════════════════════

  Controls: 10 total
    Met:           8 (80%)
    Partially Met: 1 (10%)
    Not Met:       1 (10%)
    N/A:           0

  Gaps:
    CC6.6 (Partially Met): IP allowlisting configured but not enforced on all keys
    CC8.1 (Not Met):       No change management approvals for key rotation

  Recommendations:
    1. Enable IP allowlisting on all production keys (Feature 077)
    2. Implement approval workflow for key changes
    3. Enable tamper-evident audit log anchoring (Feature 076)

$ pqvault compliance report soc2 --from 2025-01-01 --to 2025-03-31 --format pdf

  Generating SOC2 compliance report...
  Period: 2025-01-01 to 2025-03-31

  Collecting evidence:
    CC6.1 - Encryption configuration ... done
    CC6.3 - Audit log entries (1,247 events) ... done
    CC7.2 - Health monitoring data ... done
    ...

  Report saved: pqvault-soc2-2025Q1.pdf (24 pages)
```
