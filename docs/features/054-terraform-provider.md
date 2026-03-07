# Feature 054: Terraform Provider

## Status: Planned
## Phase: 6 (v2.6)
## Priority: High

## Problem

Terraform stores secrets in state files in plaintext. When infrastructure-as-code references API keys, database passwords, or other sensitive values, those values end up in `terraform.tfstate` — often stored in S3 or a remote backend with insufficient encryption. There is no integration between PQVault's key rotation and Terraform's infrastructure lifecycle, meaning Terraform plans may use stale credentials.

## Solution

Build a Terraform provider (`terraform-provider-pqvault`) that exposes PQVault keys as data sources. The provider fetches secrets at plan/apply time, never writes them to state (using `sensitive = true`), and validates key health before deployment. Resources can depend on PQVault keys, ensuring infrastructure is always deployed with current credentials. The provider is a separate Go project using the Terraform Plugin Framework.

## Implementation

### Files to Create/Modify

- `terraform-provider-pqvault/main.go` — Provider entry point
- `terraform-provider-pqvault/internal/provider/provider.go` — Provider configuration
- `terraform-provider-pqvault/internal/provider/data_source_secret.go` — Secret data source
- `terraform-provider-pqvault/internal/provider/data_source_health.go` — Health check data source
- `terraform-provider-pqvault/internal/client/client.go` — PQVault API client

### Data Model Changes

```hcl
# Provider configuration
terraform {
  required_providers {
    pqvault = {
      source  = "pdaxt/pqvault"
      version = "~> 1.0"
    }
  }
}

provider "pqvault" {
  url   = "https://vault.company.com"
  token = var.pqvault_token  # Or PQVAULT_TOKEN env var
}
```

```go
// internal/provider/provider.go
package provider

import (
    "github.com/hashicorp/terraform-plugin-framework/provider"
    "github.com/hashicorp/terraform-plugin-framework/provider/schema"
)

type PQVaultProvider struct {
    client *client.PQVaultClient
}

func (p *PQVaultProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
    resp.Schema = schema.Schema{
        Attributes: map[string]schema.Attribute{
            "url": schema.StringAttribute{
                Required:    true,
                Description: "PQVault server URL",
            },
            "token": schema.StringAttribute{
                Optional:    true,
                Sensitive:   true,
                Description: "Service account token (or PQVAULT_TOKEN env var)",
            },
        },
    }
}

// internal/provider/data_source_secret.go
type SecretDataSource struct {
    client *client.PQVaultClient
}

type SecretDataSourceModel struct {
    KeyName    types.String `tfsdk:"key_name"`
    Value      types.String `tfsdk:"value"`
    Version    types.Int64  `tfsdk:"version"`
    LastRotated types.String `tfsdk:"last_rotated"`
    HealthScore types.Float64 `tfsdk:"health_score"`
    Provider    types.String `tfsdk:"provider_name"`
}

func (d *SecretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
    resp.Schema = schema.Schema{
        Description: "Fetches a secret from PQVault",
        Attributes: map[string]schema.Attribute{
            "key_name": schema.StringAttribute{
                Required:    true,
                Description: "Name of the key in PQVault",
            },
            "value": schema.StringAttribute{
                Computed:    true,
                Sensitive:   true,
                Description: "The secret value (never stored in state)",
            },
            "version": schema.Int64Attribute{
                Computed:    true,
                Description: "Current version of the secret",
            },
            "last_rotated": schema.StringAttribute{
                Computed:    true,
                Description: "When the key was last rotated",
            },
            "health_score": schema.Float64Attribute{
                Computed:    true,
                Description: "Key health score (0-100)",
            },
            "provider_name": schema.StringAttribute{
                Computed:    true,
                Description: "Key provider (e.g., anthropic, openai)",
            },
        },
    }
}

func (d *SecretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
    var config SecretDataSourceModel
    resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

    secret, err := d.client.GetSecret(ctx, config.KeyName.ValueString())
    if err != nil {
        resp.Diagnostics.AddError("Failed to fetch secret", err.Error())
        return
    }

    config.Value = types.StringValue(secret.Value)
    config.Version = types.Int64Value(secret.Version)
    config.LastRotated = types.StringValue(secret.LastRotated)
    config.HealthScore = types.Float64Value(secret.HealthScore)
    config.Provider = types.StringValue(secret.Provider)

    resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
```

### Terraform Usage

```hcl
# Fetch secrets from PQVault
data "pqvault_secret" "db_url" {
  key_name = "PROD_DATABASE_URL"
}

data "pqvault_secret" "stripe_key" {
  key_name = "STRIPE_SECRET_KEY"
}

# Health check data source
data "pqvault_health" "db_health" {
  key_name = "PROD_DATABASE_URL"
}

# Use in resources
resource "aws_ssm_parameter" "db_url" {
  name  = "/myapp/database_url"
  type  = "SecureString"
  value = data.pqvault_secret.db_url.value
}

resource "aws_lambda_function" "api" {
  function_name = "api-handler"
  environment {
    variables = {
      DATABASE_URL = data.pqvault_secret.db_url.value
      STRIPE_KEY   = data.pqvault_secret.stripe_key.value
    }
  }
}

# Fail deployment if key is unhealthy
resource "null_resource" "health_gate" {
  count = data.pqvault_health.db_health.score < 50 ? 1 : 0

  provisioner "local-exec" {
    command = "echo 'ERROR: Database key health score is ${data.pqvault_health.db_health.score}/100' && exit 1"
  }
}

# Output (marked sensitive)
output "db_version" {
  value = data.pqvault_secret.db_url.version
}
```

### CLI Commands

```bash
# Install the provider
terraform init

# Plan with PQVault secrets
terraform plan

# Apply
terraform apply

# Refresh secrets without full apply
terraform refresh
```

### Web UI Changes

- Terraform provider documentation page
- Service account creation wizard for Terraform
- Usage statistics showing Terraform plan/apply events

## Dependencies

- Go 1.21+ (separate project)
- `terraform-plugin-framework v1.5` — Terraform provider framework
- Feature 051 (GitHub Actions) — Service account authentication model

## Testing

### Unit Tests (Go)

```go
func TestSecretDataSourceSchema(t *testing.T) {
    ds := &SecretDataSource{}
    req := datasource.SchemaRequest{}
    resp := &datasource.SchemaResponse{}
    ds.Schema(context.Background(), req, resp)

    assert.Contains(t, resp.Schema.Attributes, "key_name")
    assert.Contains(t, resp.Schema.Attributes, "value")
    assert.True(t, resp.Schema.Attributes["value"].(schema.StringAttribute).Sensitive)
}

func TestSecretValueNotInState(t *testing.T) {
    // Verify that value attribute has Sensitive: true
    // which prevents it from appearing in state
    attr := resp.Schema.Attributes["value"].(schema.StringAttribute)
    assert.True(t, attr.Sensitive)
}
```

### Integration Tests

```go
func TestAccSecretDataSource(t *testing.T) {
    resource.Test(t, resource.TestCase{
        ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
        Steps: []resource.TestStep{
            {
                Config: `
                    data "pqvault_secret" "test" {
                        key_name = "TEST_KEY"
                    }
                `,
                Check: resource.ComposeTestCheckFunc(
                    resource.TestCheckResourceAttrSet("data.pqvault_secret.test", "value"),
                    resource.TestCheckResourceAttrSet("data.pqvault_secret.test", "version"),
                ),
            },
        },
    })
}
```

### Manual Verification

1. Install provider and configure with PQVault URL
2. Create `.tf` file with data sources
3. Run `terraform plan` and verify secrets are fetched
4. Run `terraform apply` and verify resources are created with correct values
5. Rotate a key in PQVault, run `terraform plan` — verify change detected
6. Check state file — verify secret values are NOT present

## Example Usage

```hcl
# Complete example: Deploy with PQVault secrets
provider "pqvault" {
  url = "https://vault.company.com"
}

provider "aws" {
  region = "us-east-1"
}

data "pqvault_secret" "db" {
  key_name = "PROD_DATABASE_URL"
}

data "pqvault_secret" "redis" {
  key_name = "PROD_REDIS_URL"
}

resource "aws_ecs_task_definition" "app" {
  family = "myapp"
  container_definitions = jsonencode([{
    name  = "app"
    image = "myapp:latest"
    environment = [
      { name = "DATABASE_URL", value = data.pqvault_secret.db.value },
      { name = "REDIS_URL",    value = data.pqvault_secret.redis.value },
    ]
  }])
}
```
