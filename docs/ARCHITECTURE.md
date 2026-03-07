# PQVault Architecture

## Overview

PQVault is a quantum-proof secrets manager built in Rust, designed for AI agent workflows. It uses a **micro MCP architecture** where each concern area is a separate MCP binary, registered independently in Claude Code.

---

## Micro MCP Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Claude Code / AI Agents                    │
├─────────┬──────────┬──────────┬──────────┬─────────┬────────┤
│ pqvault │ pqvault  │ pqvault  │ pqvault  │ pqvault │ pqvault│
│   mcp   │  proxy   │  health  │   env    │ rotation│  agent │
│         │   mcp    │   mcp    │   mcp    │   mcp   │   mcp  │
├─────────┴──────────┴──────────┴──────────┴─────────┴────────┤
│                       pqvault-core                           │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐ ┌─────────┐ │
│  │ vault  │ │ crypto │ │ models │ │ keychain │ │providers│ │
│  └────────┘ └────────┘ └────────┘ └──────────┘ └─────────┘ │
├──────────────────────────────────────────────────────────────┤
│                    Encrypted Storage                         │
│  ~/.pqvault/vault.enc  │  vault.meta.json  │  audit.log     │
│  pq_public.bin         │  pq_private.enc   │  usage.json    │
│  x25519_public.bin     │  x25519_private.enc│               │
└──────────────────────────────────────────────────────────────┘
```

---

## Crate Dependency Graph

```
pqvault-cli ──────────────┐
pqvault-web ──────────────┤
pqvault-mcp ──────────────┤
pqvault-proxy-mcp ────────┤
pqvault-health-mcp ───────┤──► pqvault-core
pqvault-env-mcp ──────────┤
pqvault-rotation-mcp ─────┤
pqvault-agent-mcp ────────┤
pqvault-audit-mcp ────────┤
pqvault-scan-mcp ─────────┤
pqvault-sync-mcp ─────────┤
pqvault-team-mcp ─────────┘
```

All micro MCPs depend on `pqvault-core` for shared vault operations, cryptography, and data models.

---

## Crate Descriptions

### pqvault-core (library)
Shared foundation used by all other crates.

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `vault` | Open/save/init encrypted vault | `open_vault()`, `save_vault()`, `vault_exists()` |
| `crypto` | Hybrid ML-KEM-768 + X25519 + AES-256-GCM | `hybrid_encrypt()`, `hybrid_decrypt()`, `password_encrypt()` |
| `models` | Data structures | `VaultData`, `SecretEntry`, `ProjectEntry` |
| `keychain` | macOS Keychain + 3-tier caching | `get_master_password()`, `store_master_password()` |
| `providers` | API provider configs + detection | `PROVIDERS`, `detect_provider()`, `AuthMethod` |

### pqvault-mcp (binary)
Core vault operations MCP server.

| Tool | Description |
|------|-------------|
| `vault_status` | Vault summary: total secrets, projects, health |
| `vault_get` | Retrieve a secret value by key name |
| `vault_list` | List all secrets with metadata |
| `vault_add` | Add a new secret |
| `vault_delete` | Remove a secret |
| `vault_search` | Search secrets by name, category, tag |
| `vault_import_claude` | Import from ~/.claude.json |

### pqvault-proxy-mcp (binary)
Zero-knowledge API proxy — agents make API calls without seeing keys.

| Tool | Description |
|------|-------------|
| `vault_proxy` | Proxy HTTP request with auto-injected auth |

Key features:
- SSRF protection (no localhost, no IPs, domain allowlist)
- Rate limiting (per-minute token bucket, daily/monthly counters)
- Cost tracking per request
- Auth injection: Bearer, Basic, Custom Header, Query Param

### pqvault-health-mcp (binary)
Monitoring, usage tracking, and intelligence.

| Tool | Description |
|------|-------------|
| `vault_health` | Health report: expired, needs rotation, orphaned |
| `vault_dashboard` | Smart dashboard with alerts, usage overview |
| `vault_usage` | Per-key usage stats and status |

### pqvault-env-mcp (binary)
Environment file management.

| Tool | Description |
|------|-------------|
| `vault_project_env` | Generate .env content for a project |
| `vault_write_env` | Write .env file to disk for a project |

### pqvault-rotation-mcp (binary)
Key lifecycle management.

| Tool | Description |
|------|-------------|
| `vault_rotate` | Rotate a key (manual or auto via provider API) |
| `vault_auto_rotate` | Run auto-rotation for all due keys |
| `vault_rotation_policy` | Set/get rotation policies |
| `vault_rollback` | Rollback a rotation |

### pqvault-agent-mcp (binary)
AI agent control plane — the differentiator.

| Tool | Description |
|------|-------------|
| `agent_create_token` | Create scoped agent token |
| `agent_list_tokens` | List all agent tokens |
| `agent_revoke_token` | Revoke an agent token |
| `agent_set_budget` | Set per-agent-per-key budget cap |
| `agent_usage_report` | Per-agent usage breakdown |

### pqvault-audit-mcp (binary)
Audit logging and compliance.

| Tool | Description |
|------|-------------|
| `vault_audit_log` | Query audit log entries |
| `vault_compliance_report` | Generate compliance evidence |

### pqvault-scan-mcp (binary)
Secret scanning and breach detection.

| Tool | Description |
|------|-------------|
| `vault_scan` | Scan directory for hardcoded secrets |
| `vault_breach_check` | Check keys against breach databases |

### pqvault-sync-mcp (binary)
Cloud synchronization.

| Tool | Description |
|------|-------------|
| `vault_sync` | Sync to/from cloud providers (Vercel, AWS, GCP) |

### pqvault-team-mcp (binary)
Team and access control.

| Tool | Description |
|------|-------------|
| `vault_rbac` | Manage roles and permissions |
| `vault_workspace` | Manage team workspaces |

### pqvault-web (binary)
Web dashboard (Axum server).

- Serves at `http://localhost:9876`
- REST API: `/api/secrets`, `/api/health`, `/api/dashboard`
- WebSocket: `/ws/dashboard` for real-time updates
- Static files: HTML/CSS/JS served via tower-http

### pqvault-cli (binary)
Command-line interface.

| Command | Description |
|---------|-------------|
| `pqvault init` | Initialize new vault |
| `pqvault serve` | Start MCP server (legacy, single process) |
| `pqvault status` | Show vault status |
| `pqvault list` | List all secrets |
| `pqvault get <key>` | Get a secret value |
| `pqvault add <key> <value>` | Add a secret |
| `pqvault delete <key>` | Delete a secret |
| `pqvault health` | Run health check |
| `pqvault web` | Start web dashboard |
| `pqvault run` | Run command with injected secrets |
| `pqvault import` | Import from .env file |
| `pqvault export` | Export to .env/JSON/YAML |
| `pqvault scan` | Scan for hardcoded secrets |
| `pqvault diff` | Compare environments |
| `pqvault doctor` | System diagnostic |
| `pqvault tui` | Interactive terminal UI |

---

## Encryption Architecture

### Hybrid Post-Quantum Encryption

```
Plaintext (vault JSON)
        │
        ▼
┌───────────────────────────────────────┐
│  ML-KEM-768 Encapsulation             │
│  (Post-quantum KEM, NIST FIPS 203)    │
│  → pq_shared_secret                   │
├───────────────────────────────────────┤
│  X25519 Diffie-Hellman                │
│  (Classical ECDH)                     │
│  → x25519_shared_secret              │
├───────────────────────────────────────┤
│  HKDF-SHA256                          │
│  salt = random 32 bytes               │
│  info = "pqvault-hybrid-dek-v1"       │
│  input = pq_ss || x25519_ss           │
│  → DEK (256-bit)                      │
├───────────────────────────────────────┤
│  AES-256-GCM                          │
│  nonce = random 12 bytes              │
│  aad = "pqvault-v1"                   │
│  → Ciphertext + Auth Tag              │
└───────────────────────────────────────┘
        │
        ▼
  vault.enc (encrypted file)
```

**Why hybrid?** Attacker must break BOTH ML-KEM-768 AND X25519 to recover the DEK. Post-quantum alone has less field-tested security. Classical alone is vulnerable to quantum computers. Hybrid is the NIST-recommended approach.

### Password-Based Encryption (Keypair Protection)

```
Master Password (from Keychain)
        │
        ▼
┌───────────────────────┐
│  scrypt (N=2^17, r=8) │
│  salt = random 32B     │
│  → 256-bit key         │
├───────────────────────┤
│  AES-256-GCM           │
│  aad = "pqvault-pw-v1" │
│  → Encrypted keypair   │
└───────────────────────┘
```

### Three-Tier Password Caching

```
Request master password
        │
        ▼
   ┌─ OnceLock (process memory) ──► Hit? Return immediately
   │
   ├─ File cache (~/.pqvault/.master_cache) ──► Hit? Cache in OnceLock, return
   │
   └─ macOS Keychain (keyring crate) ──► Hit? Cache in file + OnceLock, return
                                          Miss? Error: vault locked
```

**Why 3 tiers?** 48 tmux panes × 1 MCP process each = 48 simultaneous Keychain prompts. File cache eliminates this.

---

## Data Flow

### vault_get (MCP Tool)
```
Agent → stdio → pqvault-mcp
  → open_vault()
    → get_master_password() [3-tier cache]
    → read vault.enc from disk
    → hybrid_decrypt(payload, pq_secret, x25519_private)
    → deserialize JSON → VaultData
  → lookup key in secrets HashMap
  → log_access("get", key, "", caller)
  → record_access(key, caller) [usage tracking]
  → return value to agent
```

### vault_proxy (MCP Tool)
```
Agent → stdio → pqvault-proxy-mcp
  → open_vault() → get key value
  → detect_provider(key_name, value)
  → check_rate_limit(key_name)
  → resolve_url(url_input, provider)
  → validate_url(url, allowed_domains) [SSRF check]
  → inject_auth(headers, url, key_value, auth_method)
  → execute_proxy(client, method, url, headers, body)
  → record_access(key_name, caller)
  → return response (key value NEVER in response)
```

---

## File Layout

```
~/.pqvault/
├── vault.enc            # Encrypted vault data (hybrid encryption)
├── vault.meta.json      # Unencrypted metadata (version, created date)
├── pq_public.bin        # ML-KEM-768 public key (plaintext)
├── pq_private.enc       # ML-KEM-768 private key (password-encrypted)
├── x25519_public.bin    # X25519 public key (plaintext)
├── x25519_private.enc   # X25519 private key (password-encrypted)
├── audit.log            # Audit log (plaintext JSONL → encrypted in v2.1)
├── audit.log.1          # Rotated audit log
├── audit.log.2          # Rotated audit log
├── usage.json           # Usage statistics (plaintext → encrypted in v2.1)
├── .master_cache        # File-cached master password (tier 2)
└── config.toml          # User config (v2.7+)
```

---

## Claude Code Integration

### MCP Registration
Each micro MCP registers as a separate MCP server in `~/.claude.json`:

```json
{
  "mcpServers": {
    "pqvault": {
      "command": "/Users/pran/.cargo/bin/pqvault-mcp",
      "args": [],
      "env": {}
    },
    "pqvault-proxy": {
      "command": "/Users/pran/.cargo/bin/pqvault-proxy-mcp",
      "args": [],
      "env": {}
    },
    "pqvault-health": {
      "command": "/Users/pran/.cargo/bin/pqvault-health-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

### Tool Discovery
Claude Code discovers tools via MCP `tools/list`:
- `pqvault` → vault_status, vault_get, vault_list, vault_add, vault_delete, vault_search, vault_import_claude
- `pqvault-proxy` → vault_proxy
- `pqvault-health` → vault_health, vault_dashboard, vault_usage

### Agent Workflow
1. Agent needs API key → calls `vault_proxy` (never sees key)
2. Agent wants key status → calls `vault_usage`
3. Agent needs .env file → calls `vault_write_env`
4. Agent detects rotation needed → calls `vault_rotate`

---

## Version Evolution

### v2.0 (Current)
- Monolithic: single binary with all tools
- 14 MCP tools in one `mcp.rs`
- Web dashboard with embedded HTML

### v2.1-2.9 (Micro MCP)
- Cargo workspace with 13 crates
- Each concern area = separate MCP binary
- Independent deployment and testing

### v3.0 (Daemon Architecture)
```
pqvault-daemon (always-on background process)
├── Unix socket / gRPC API
├── File watcher (vault.enc changes)
├── Background jobs
│   ├── Auto-rotation scheduler
│   ├── Health check pinger
│   ├── Cost tracker
│   └── Alert evaluator
└── Encrypted file store

pqvault-cli → socket → daemon
pqvault-mcp → socket → daemon
pqvault-web → socket → daemon
```

### v4.0 (Optional Cloud Sync)
- Local daemon remains primary
- Optional E2E encrypted cloud sync
- Team vault sharing
- Cross-device synchronization
- Offline-first architecture

---

## Security Model

### Threat Model
| Threat | Mitigation |
|--------|------------|
| Quantum computer breaks encryption | Hybrid ML-KEM-768 + X25519 (must break both) |
| Key leaked in agent output | vault_proxy never exposes key values |
| Master password compromised | macOS Keychain + scrypt KDF + file permissions |
| SSRF via vault_proxy | HTTPS-only, no IPs, no localhost, domain allowlist |
| Audit log tampering | Hash chain (v2.8), encrypted at rest (v2.1) |
| Agent budget abuse | Per-agent budget caps + circuit breaker (v2.3) |
| Unauthorized vault access | TOTP web auth (v2.1), RBAC (v2.5) |
| Key left in memory | zeroize crate on secret values (v2.8) |

### Trust Boundaries
1. **Vault file** — Encrypted with hybrid PQ crypto. Safe to back up to untrusted storage.
2. **MCP transport** — stdio (local). No network exposure.
3. **Web dashboard** — localhost only. TOTP auth (v2.1+).
4. **vault_proxy** — SSRF-hardened. Only HTTPS to allowlisted domains.
5. **Keychain** — macOS-managed. Requires user authentication.

---

*Last updated: 2026-03-07*
