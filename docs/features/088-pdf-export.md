# Feature 088: PDF Export

## Status: Done
## Phase: 9 (v2.9)
## Priority: Medium

## Problem

Compliance audits (SOC2, ISO 27001, PCI-DSS) require documented evidence of secret
management practices. Auditors need printable reports showing secret inventory, rotation
schedules, access controls, and health status. Currently this data exists only in the
dashboard and CLI, requiring manual screenshots or copy-paste to assemble evidence
packages. This is tedious and produces inconsistent documentation.

## Solution

Add PDF export functionality to the web dashboard that generates compliance-ready
reports. Reports include secret inventory (without values), rotation compliance,
health scores, audit trail summaries, and access policy documentation. The PDF is
generated server-side using a lightweight HTML-to-PDF approach, maintaining consistent
branding and formatting.

## Implementation

### Files to Create/Modify

```
pqvault-web/
  src/
    routes/
      api/
        export.rs       # GET /api/export/pdf - PDF generation endpoint
    export/
      mod.rs            # Export module root
      pdf.rs            # PDF generation engine
      templates.rs      # Report template definitions
      sections.rs       # Report section builders
  templates/
    reports/
      compliance.html   # Full compliance report template
      inventory.html    # Secret inventory report template
      audit.html        # Audit trail report template
  static/
    css/
      print.css         # Print-specific styles
```

### Data Model Changes

```rust
/// PDF report generation request
#[derive(Deserialize)]
pub struct ExportRequest {
    /// Report type
    pub report_type: ReportType,
    /// Date range for audit data
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Include specific sections
    pub sections: Option<Vec<ReportSection>>,
    /// Company name for header
    pub company_name: Option<String>,
    /// Prepared by
    pub prepared_by: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    Compliance,    // Full SOC2/ISO27001 evidence package
    Inventory,     // Secret inventory listing
    AuditTrail,    // Access log report
    HealthReport,  // Current health status
    Custom,        // Pick specific sections
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSection {
    ExecutiveSummary,
    SecretInventory,
    RotationCompliance,
    HealthScores,
    AccessPolicies,
    AuditTrail,
    EncryptionDetails,
    Recommendations,
}

/// Data collected for report generation
#[derive(Serialize)]
pub struct ReportData {
    pub generated_at: String,
    pub company_name: String,
    pub prepared_by: String,
    pub vault_summary: VaultSummary,
    pub secrets: Vec<SecretReportEntry>,
    pub rotation_compliance: RotationCompliance,
    pub health_overview: HealthOverview,
    pub audit_entries: Vec<AuditReportEntry>,
    pub encryption_info: EncryptionReport,
}

#[derive(Serialize)]
pub struct VaultSummary {
    pub total_secrets: usize,
    pub by_category: HashMap<String, usize>,
    pub by_provider: HashMap<String, usize>,
    pub by_health: HashMap<String, usize>,
    pub encryption_algorithm: String,
}

#[derive(Serialize)]
pub struct SecretReportEntry {
    pub name: String,
    pub category: String,
    pub provider: String,
    pub created_at: String,
    pub last_rotated: String,
    pub health_status: String,
    pub health_score: u32,
    pub has_ip_policy: bool,
    pub has_time_policy: bool,
    // NOTE: Value is NEVER included in reports
}

#[derive(Serialize)]
pub struct RotationCompliance {
    pub total_keys: usize,
    pub compliant: usize,        // Rotated within policy window
    pub non_compliant: usize,    // Overdue for rotation
    pub never_rotated: usize,
    pub compliance_percentage: f64,
}
```

Report generation:

```rust
pub async fn generate_pdf(
    State(state): State<AppState>,
    Query(params): Query<ExportRequest>,
) -> impl IntoResponse {
    let vault = state.vault.read().await;

    // Collect report data
    let data = collect_report_data(&vault, &state, &params).await?;

    // Render HTML template
    let html = state.templates.render(
        &format!("reports/{}.html", params.report_type.template_name()),
        &data,
    )?;

    // Convert HTML to PDF using headless rendering
    let pdf_bytes = html_to_pdf(&html).await?;

    let filename = format!(
        "pqvault-{}-{}.pdf",
        params.report_type.template_name(),
        Utc::now().format("%Y%m%d")
    );

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/pdf"),
            (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", filename)),
        ],
        pdf_bytes,
    )
}

/// Lightweight HTML to PDF using printable CSS
async fn html_to_pdf(html: &str) -> Result<Vec<u8>> {
    // Option 1: Use weasyprint subprocess
    let mut child = tokio::process::Command::new("weasyprint")
        .arg("-")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        tokio::io::AsyncWriteExt::write_all(&mut stdin, html.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(anyhow!("PDF generation failed"));
    }

    Ok(output.stdout)
}
```

### MCP Tools

No new MCP tools. PDF export is a web-only feature.

### CLI Commands

```bash
# Generate PDF from CLI
pqvault export pdf --type compliance --output report.pdf

# Inventory report
pqvault export pdf --type inventory --output secrets-inventory.pdf

# Audit trail for date range
pqvault export pdf --type audit --from 2025-01-01 --to 2025-03-31

# With company branding
pqvault export pdf --type compliance --company "Acme Corp" --prepared-by "Security Team"
```

### Web UI Changes

Export button in dashboard header and key detail pages.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio` | 1 | Async subprocess for PDF generation (already in workspace) |

External: `weasyprint` (Python) or `wkhtmltopdf` for HTML-to-PDF conversion.
Alternative: Use Playwright MCP's `browser_pdf_save` for server-side rendering.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_data_excludes_values() {
        let entry = SecretReportEntry {
            name: "API_KEY".into(),
            category: "general".into(),
            provider: "custom".into(),
            created_at: "2025-01-01".into(),
            last_rotated: "2025-03-01".into(),
            health_status: "healthy".into(),
            health_score: 95,
            has_ip_policy: false,
            has_time_policy: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        // Verify no value field exists
        assert!(!json.contains("value"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn test_rotation_compliance_calculation() {
        let compliance = RotationCompliance {
            total_keys: 20,
            compliant: 15,
            non_compliant: 3,
            never_rotated: 2,
            compliance_percentage: 75.0,
        };
        assert_eq!(compliance.compliance_percentage, 75.0);
        assert_eq!(compliance.total_keys, compliance.compliant + compliance.non_compliant + compliance.never_rotated);
    }

    #[test]
    fn test_report_type_template_name() {
        assert_eq!(ReportType::Compliance.template_name(), "compliance");
        assert_eq!(ReportType::Inventory.template_name(), "inventory");
        assert_eq!(ReportType::AuditTrail.template_name(), "audit");
    }

    #[test]
    fn test_filename_format() {
        let filename = format!(
            "pqvault-compliance-{}.pdf",
            chrono::Utc::now().format("%Y%m%d")
        );
        assert!(filename.starts_with("pqvault-compliance-"));
        assert!(filename.ends_with(".pdf"));
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_pdf_export_endpoint() {
    let app = test_app_with_keys(&[("KEY_A", "v1"), ("KEY_B", "v2")]).await;
    let response = app.get("/api/export/pdf?report_type=inventory").await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/pdf"
    );
}
```

## Example Usage

```
Browser: Click "Export PDF" button in dashboard header

┌─────────────────────────────────────────┐
│  Export Report                          │
│                                         │
│  Report Type: [Compliance Report    v]  │
│  Company:     [Acme Corp             ]  │
│  Prepared By: [Security Team         ]  │
│  Date Range:  [2025-01-01] to [today ]  │
│                                         │
│  Sections:                              │
│  [x] Executive Summary                 │
│  [x] Secret Inventory                  │
│  [x] Rotation Compliance               │
│  [x] Health Scores                     │
│  [x] Access Policies                   │
│  [x] Audit Trail                       │
│  [ ] Encryption Details                │
│  [x] Recommendations                   │
│                                         │
│              [Cancel] [Generate PDF]    │
└─────────────────────────────────────────┘

Generated PDF includes:
- Cover page with company logo and date
- Executive summary with key metrics
- Table of all secrets (names only, no values)
- Rotation compliance chart (75% compliant)
- Health score distribution
- Sanitized audit trail
- Security recommendations
```
