# PQVault Audit Report

**Version:** 2.1.0
**Date:** 2026-03-10
**Source lines:** 8,495 (crates) + 4,915 (legacy src/)

---

## MCP Scorecard

| Crate | Tools | Tests | Security | Docs | Grade | Score |
|-------|:-----:|:-----:|:--------:|:----:|:-----:|:-----:|
| pqvault-core | N/A | 37 | Good | Partial | **B** | 72 |
| pqvault-mcp | 7 | 0 | Good | None | **C** | 55 |
| pqvault-proxy-mcp | 1 | 0 | Good | None | **C** | 52 |
| pqvault-health-mcp | 3 | 0 | OK | None | **D** | 40 |
| pqvault-env-mcp | 3 | 0 | OK | None | **D** | 38 |
| pqvault-unified | 14 | 0 | OK | None | **D** | 42 |
| pqvault-cli | N/A | 0 | Good | None | **C** | 50 |
| pqvault-web | N/A | 0 | OK | None | **D** | 35 |

**Platform Score: 48/100 (D+)**

---

## CRITICAL Issues (P0)

### 1. Stale BSKiller databases in repo root

```
bskiller-growth.db / bskiller-scraper.db
```

These are SQLite databases from a completely different project. They're in `.gitignore` (`*.db`) but present on disk. If `.gitignore` ever changes or someone force-adds, these leak. **Remove them.**

### 2. Legacy `src/` monolith still ships as a binary

The workspace `Cargo.toml` includes `src/main.rs` (4,915 lines) alongside the crate versions. This means `cargo build` produces BOTH the old monolith AND the new crate binaries. The `src/main.rs` declares version `2.0.0` while crates are `2.1.0`. **Either remove `src/` or extract it as a crate.**

### 3. Zero tests outside pqvault-core

37 tests exist but ALL are in `pqvault-core`. Every MCP server binary (mcp, proxy, health, env, unified, web, cli) has **zero tests**. This means:
- No test coverage for MCP tool parameter validation
- No test coverage for error handling in tools
- No test coverage for the web dashboard
- No test coverage for CLI commands

---

## HIGH Issues (P1)

### 4. 65 unwrap() calls across crates

Panic-inducing `unwrap()` calls in production code. For a **secrets manager**, a panic can mean:
- Vault left in inconsistent state
- Decrypted secrets in memory during crash
- No audit trail of failed operation

**Affected files (top offenders):**
- `pqvault-core/src/vault.rs`
- `pqvault-core/src/crypto.rs`
- `pqvault-mcp/src/main.rs`
- `pqvault-unified/src/main.rs`

### 5. No CI/CD pipeline

No `.github/workflows/` directory. This means:
- No automated tests on PR
- No release automation
- No `cargo clippy` or `cargo fmt` enforcement
- No security audit (`cargo audit`)
- No binary publishing

### 6. Roadmap lists crates that don't exist

`ARCHITECTURE.md` references:
- `pqvault-rotation-mcp` (not in workspace)
- `pqvault-agent-mcp` (not in workspace)
- `pqvault-audit-mcp` (not in workspace)
- `pqvault-scan-mcp` (not in workspace)
- `pqvault-sync-mcp` (not in workspace)
- `pqvault-team-mcp` (not in workspace)

6 phantom crates listed in architecture docs that don't exist. **Misleading to anyone reading the docs.**

### 7. No doc comments on public APIs

`pqvault-core` exports 13 public modules with dozens of public functions. Zero `///` doc comments. `cargo doc` produces empty documentation.

---

## MEDIUM Issues (P2)

### 8. No input validation on MCP tools

MCP tool parameters (key names, search queries, tag lists) have no validation:
- No max length on key names
- No character restrictions on key names
- No limit on tag count
- No max body size on vault_proxy
- No URL validation on vault_proxy besides SSRF checks

### 9. Audit log is append-only plaintext

`~/.pqvault/audit.log` is a plaintext file. It can be:
- Tampered with (no integrity checks)
- Read by any process (no encryption)
- Grows unbounded (no rotation)

For a security product, the audit log should have integrity guarantees.

### 10. No rate limit persistence

Rate limits are defined per-secret but usage counters reset when the process restarts. In an MCP setup where the server starts/stops per session, rate limits are effectively useless.

### 11. `server.json` in repo root

```json
server.json
```
Contains configuration that may include connection details. Should be in `.gitignore`.

### 12. npm directory for cross-platform install

The `npm/` directory contains `install.js`, `run.js`, `package.json` for npm-based installation. This is a distribution strategy but:
- Not documented in README
- Not tested
- package.json may have stale version

---

## LOW Issues (P3)

### 13. No `cargo clippy` clean

Not verified if the codebase passes `cargo clippy` without warnings. Should be enforced in CI.

### 14. Missing `zeroize` on sensitive data

The `zeroize` crate is a dependency but usage isn't verified across all code paths. Decrypted secrets should be zeroized when dropped to prevent memory leaks of sensitive data.

### 15. Web dashboard auth

`pqvault-web` has an `auth` module but it's unclear if the dashboard requires authentication by default or is open to anyone on `:9876`.

### 16. Stress tests exist but aren't in CI

`tests/stress_tests.rs` (1,187 lines) exists but isn't run automatically. These tests likely test concurrent access patterns.

---

## Feature Gaps & Opportunities

### Missing from a star-worthy OSS project

| Feature | Impact | Effort | Notes |
|---------|--------|--------|-------|
| **GitHub Actions CI** | HIGH | 2h | Test, clippy, fmt, audit, release |
| **crates.io publish** | HIGH | 1h | Makes `cargo install pqvault-cli` work |
| **GitHub Releases** | HIGH | 1h | Enables homebrew formula |
| **Integration tests** | HIGH | 4h | Test MCP tools end-to-end |
| **Doc comments** | MED | 3h | Every public function needs `///` |
| **Error types** | MED | 2h | Replace `anyhow` in core with typed errors |
| **Changelog** | MED | 1h | CHANGELOG.md with keep-a-changelog format |
| **Example configs** | LOW | 1h | `examples/` directory with Claude Desktop configs |
| **Shell completions** | LOW | 30m | `clap_complete` is a dep but not wired up |
| **Man pages** | LOW | 1h | `clap_mangen` for `man pqvault` |

### Competitive Opportunities

| Opportunity | Why It Matters |
|-------------|---------------|
| **First Rust MCP secrets vault** | No competition in this niche. Own the category. |
| **Post-quantum is a selling point** | NIST standardized ML-KEM in 2024. PQVault is early. |
| **npm cross-platform install** | Already started. Finish it for `npx pqvault` |
| **VS Code extension** | PQVault status bar showing key health |
| **GitHub Action** | `uses: pdaxt/pqvault-action@v1` for CI secret management |
| **awesome-mcp listing** | Submit to awesome-mcp-servers for discoverability |

---

## Next Steps (Priority Order)

### P0 - Do Now
1. **Remove stale .db files** from repo root
2. **Decide: keep or kill legacy `src/`** (recommend: delete, crates are the future)
3. **Remove phantom crates** from ARCHITECTURE.md

### P1 - This Week
4. **Add GitHub Actions** (test + clippy + fmt + audit)
5. **Write integration tests** for pqvault-mcp tools (at minimum: init, add, get, delete)
6. **Replace unwrap() with proper error handling** in vault.rs and crypto.rs
7. **Publish to crates.io** (pqvault-cli at minimum)

### P2 - This Month
8. **Add doc comments** to all public pqvault-core functions
9. **Input validation** on all MCP tool parameters
10. **Audit log integrity** (HMAC chain or signed entries)
11. **Rate limit persistence** (write to disk, reload on start)
12. **GitHub Release** with binary artifacts (enables homebrew)

### P3 - Backlog
13. **Wire up shell completions** (clap_complete already imported)
14. **Verify zeroize usage** on all sensitive data paths
15. **Web dashboard auth** verification
16. **npm publish** for cross-platform install
17. **CHANGELOG.md**

---

## Gotchas

1. **Keychain prompt storms**: 48 panes × 1 MCP = 48 macOS Keychain prompts. Three-tier caching exists but requires vault to be opened once first.

2. **Legacy + crate binary conflict**: `cargo build` produces both `src/main.rs` binary AND crate binaries. The legacy binary has different behavior. Confusing.

3. **`pqvault-unified` duplicates all tool code**: Instead of delegating to the individual MCP crates, unified copy-pastes all tool implementations. Any fix must be applied twice.

4. **Vault file locking**: No file-level locking on `vault.enc`. Two simultaneous saves = data loss. The lazy cache helps but doesn't prevent it.

5. **Provider detection is regex-based**: Key patterns like `sk-*` could false-match. A Stripe test key and OpenAI key both start with `sk-`.
