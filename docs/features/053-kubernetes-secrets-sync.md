# Feature 053: Kubernetes Secrets Sync

## Status: Done
## Phase: 6 (v2.6)
## Priority: High

## Problem

Kubernetes secrets are stored as base64-encoded plaintext in etcd with no encryption at rest by default, no rotation mechanism, and no audit trail. Teams manually `kubectl create secret` and forget to update them when keys change. Stale K8s secrets cause production outages when PQVault keys are rotated but K8s secrets are not. There is no link between PQVault's key lifecycle management and Kubernetes secret delivery.

## Solution

Build a Kubernetes operator (`pqvault-k8s-operator`) that watches PQVaultSecret custom resources and syncs corresponding PQVault keys into native Kubernetes secrets. The operator polls PQVault on a configurable interval, detects rotations, and automatically updates K8s secrets. Pods using those secrets can be optionally restarted via rolling update annotations. The operator is a separate Go project using controller-runtime.

## Implementation

### Files to Create/Modify

- `pqvault-k8s-operator/main.go` — Operator entry point
- `pqvault-k8s-operator/api/v1alpha1/pqvaultsecret_types.go` — CRD definition
- `pqvault-k8s-operator/controllers/pqvaultsecret_controller.go` — Reconciliation loop
- `pqvault-k8s-operator/pkg/client/pqvault.go` — PQVault API client
- `pqvault-k8s-operator/config/crd/pqvaultsecret.yaml` — CRD YAML
- `crates/pqvault-web/src/api/k8s.rs` — K8s-specific API endpoints

### Data Model Changes

```yaml
# Custom Resource Definition
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: pqvaultsecrets.pqvault.io
spec:
  group: pqvault.io
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                vaultUrl:
                  type: string
                serviceAccountRef:
                  type: string
                keys:
                  type: array
                  items:
                    type: object
                    properties:
                      vaultKey:
                        type: string
                      secretKey:
                        type: string
                refreshInterval:
                  type: string
                  default: "5m"
                restartDeployments:
                  type: array
                  items:
                    type: string
            status:
              type: object
              properties:
                lastSynced:
                  type: string
                syncStatus:
                  type: string
                version:
                  type: integer
                conditions:
                  type: array
  scope: Namespaced
  names:
    plural: pqvaultsecrets
    singular: pqvaultsecret
    kind: PQVaultSecret
    shortNames:
      - pvs
```

```go
// api/v1alpha1/pqvaultsecret_types.go
package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type PQVaultSecretSpec struct {
    VaultURL           string            `json:"vaultUrl"`
    ServiceAccountRef  string            `json:"serviceAccountRef"`
    Keys               []KeyMapping      `json:"keys"`
    RefreshInterval    string            `json:"refreshInterval,omitempty"`
    RestartDeployments []string          `json:"restartDeployments,omitempty"`
    Template           *SecretTemplate   `json:"template,omitempty"`
}

type KeyMapping struct {
    VaultKey  string `json:"vaultKey"`
    SecretKey string `json:"secretKey"`
}

type SecretTemplate struct {
    Type        string            `json:"type,omitempty"`
    Labels      map[string]string `json:"labels,omitempty"`
    Annotations map[string]string `json:"annotations,omitempty"`
}

type PQVaultSecretStatus struct {
    LastSynced string             `json:"lastSynced,omitempty"`
    SyncStatus string             `json:"syncStatus,omitempty"`
    Version    int64              `json:"version,omitempty"`
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}

type PQVaultSecret struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`
    Spec              PQVaultSecretSpec   `json:"spec"`
    Status            PQVaultSecretStatus `json:"status,omitempty"`
}
```

```go
// controllers/pqvaultsecret_controller.go
func (r *PQVaultSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    var pvs v1alpha1.PQVaultSecret
    if err := r.Get(ctx, req.NamespacedName, &pvs); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // Fetch secrets from PQVault
    vaultClient := pqvault.NewClient(pvs.Spec.VaultURL, r.getToken(pvs.Spec.ServiceAccountRef))
    secrets, err := vaultClient.GetSecrets(ctx, pvs.Spec.Keys)
    if err != nil {
        return ctrl.Result{RequeueAfter: 30 * time.Second}, err
    }

    // Create or update K8s Secret
    k8sSecret := &corev1.Secret{
        ObjectMeta: metav1.ObjectMeta{
            Name:      pvs.Name,
            Namespace: pvs.Namespace,
        },
        Data: secrets,
    }

    changed, err := r.createOrUpdate(ctx, k8sSecret, &pvs)
    if err != nil {
        return ctrl.Result{}, err
    }

    // Restart deployments if secrets changed
    if changed && len(pvs.Spec.RestartDeployments) > 0 {
        for _, deploy := range pvs.Spec.RestartDeployments {
            r.rolloutRestart(ctx, pvs.Namespace, deploy)
        }
    }

    // Update status
    pvs.Status.LastSynced = time.Now().UTC().Format(time.RFC3339)
    pvs.Status.SyncStatus = "Synced"
    r.Status().Update(ctx, &pvs)

    interval, _ := time.ParseDuration(pvs.Spec.RefreshInterval)
    return ctrl.Result{RequeueAfter: interval}, nil
}
```

### CLI Commands

```bash
# Install CRD
kubectl apply -f https://pqvault.io/k8s/crd.yaml

# Deploy operator
kubectl apply -f https://pqvault.io/k8s/operator.yaml

# Create PQVaultSecret resource
kubectl apply -f - <<EOF
apiVersion: pqvault.io/v1alpha1
kind: PQVaultSecret
metadata:
  name: myapp-secrets
  namespace: production
spec:
  vaultUrl: https://vault.company.com
  serviceAccountRef: pqvault-k8s-sa
  keys:
    - vaultKey: PROD_DATABASE_URL
      secretKey: database-url
    - vaultKey: PROD_REDIS_URL
      secretKey: redis-url
    - vaultKey: STRIPE_SECRET_KEY
      secretKey: stripe-key
  refreshInterval: "5m"
  restartDeployments:
    - myapp-web
    - myapp-worker
EOF

# Check sync status
kubectl get pqvaultsecrets
# NAME             STATUS   LAST SYNCED              VERSION
# myapp-secrets    Synced   2026-03-07T14:30:00Z     3

# Verify K8s secret was created
kubectl get secret myapp-secrets -o yaml
```

### Web UI Changes

- Kubernetes integration page showing connected clusters
- Sync status per PQVaultSecret resource
- Last sync time and version tracking
- Helm chart configuration wizard

## Dependencies

- Go 1.21+ (separate project)
- `controller-runtime v0.17` — Kubernetes controller framework
- `client-go` — Kubernetes API client
- Feature 051 (GitHub Actions) — Service account authentication model

## Testing

### Unit Tests (Go)

```go
func TestKeyMapping(t *testing.T) {
    mappings := []KeyMapping{
        {VaultKey: "PROD_DB_URL", SecretKey: "database-url"},
        {VaultKey: "PROD_REDIS", SecretKey: "redis-url"},
    }
    secrets := map[string][]byte{
        "database-url": []byte("postgres://host/db"),
        "redis-url":    []byte("redis://host:6379"),
    }
    assert.Equal(t, 2, len(secrets))
}

func TestRefreshInterval(t *testing.T) {
    interval, err := time.ParseDuration("5m")
    assert.NoError(t, err)
    assert.Equal(t, 5*time.Minute, interval)
}
```

### Integration Tests

```go
func TestReconcileCreatesSecret(t *testing.T) {
    // Setup envtest with fake K8s API
    // Create PQVaultSecret CR
    // Verify K8s Secret is created
    // Verify status is updated
}

func TestReconcileUpdatesOnRotation(t *testing.T) {
    // Create initial secret
    // Simulate key rotation in PQVault
    // Trigger reconcile
    // Verify K8s secret is updated
    // Verify deployment is restarted
}
```

### Manual Verification

1. Deploy operator to a test cluster
2. Create PQVaultSecret resource
3. Verify K8s secret is created with correct values
4. Rotate a key in PQVault
5. Wait for refresh interval
6. Verify K8s secret is updated
7. Verify linked deployments are restarted

## Example Usage

```yaml
# Pod using PQVault-synced secrets:
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-web
spec:
  template:
    spec:
      containers:
        - name: web
          image: myapp:latest
          envFrom:
            - secretRef:
                name: myapp-secrets
          # Or individual keys:
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: myapp-secrets
                  key: database-url
```
