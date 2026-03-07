# Feature 026: Just-in-Time Decryption

## Status: Planned
## Phase: 3 (v2.3)
## Priority: High

## Problem

Keys currently sit decrypted in memory for the entire duration of a vault session. This creates a window where memory dumps, core files, or swap could expose plaintext secrets. The longer a key remains decrypted in memory, the larger the attack surface for cold boot attacks, /proc/mem reads, or hypervisor-level memory inspection.

## Solution

Decrypt key material only at the exact moment of `vault_proxy` use, then immediately zero the memory after the proxy call completes. This follows the principle of minimal exposure — plaintext exists in memory for milliseconds instead of minutes. The `zeroize` crate ensures memory is overwritten even if the compiler would otherwise optimize away the clear.

## Implementation

### Files to Create/Modify

- `crates/pqvault-proxy-mcp/src/jit.rs` — Core JIT decryption engine with zeroize-on-drop wrappers
- `crates/pqvault-proxy-mcp/src/lib.rs` — Integrate JIT module, replace eager decryption path
- `crates/pqvault-core/src/crypto.rs` — Add `decrypt_ephemeral()` returning `Zeroizing<Vec<u8>>`
- `crates/pqvault-core/src/vault.rs` — Remove cached plaintext from `VaultEntry` struct

### Data Model Changes

```rust
use zeroize::{Zeroize, Zeroizing};

/// Ephemeral key material that zeros on drop
pub struct EphemeralKey {
    inner: Zeroizing<Vec<u8>>,
    decrypted_at: std::time::Instant,
    max_ttl: std::time::Duration,
}

impl EphemeralKey {
    pub fn new(plaintext: Vec<u8>, max_ttl: std::time::Duration) -> Self {
        Self {
            inner: Zeroizing::new(plaintext),
            decrypted_at: std::time::Instant::now(),
            max_ttl,
        }
    }

    /// Access the key material. Panics if TTL exceeded.
    pub fn as_bytes(&self) -> &[u8] {
        assert!(
            self.decrypted_at.elapsed() < self.max_ttl,
            "Ephemeral key exceeded TTL, refusing access"
        );
        &self.inner
    }
}

/// JIT decryption context — ensures cleanup
pub struct JitContext {
    key_name: String,
    ephemeral: Option<EphemeralKey>,
    use_count: u32,
    max_uses: u32,
}

impl Drop for JitContext {
    fn drop(&mut self) {
        // Zeroizing handles the actual memory zeroing
        self.ephemeral.take();
        tracing::debug!(key = %self.key_name, uses = self.use_count, "JIT context dropped, memory zeroed");
    }
}
```

### MCP Tools

```rust
/// vault_proxy_jit — decrypt, use, zero in one atomic operation
#[tool(name = "vault_proxy_jit")]
async fn vault_proxy_jit(
    &self,
    #[arg(description = "Key name to use")] key_name: String,
    #[arg(description = "Target URL for the proxied request")] url: String,
    #[arg(description = "HTTP method")] method: Option<String>,
    #[arg(description = "Request body")] body: Option<String>,
) -> Result<CallToolResult, McpError> {
    let mut ctx = JitContext::new(&key_name, Duration::from_millis(500), 1);
    let ephemeral = self.vault.decrypt_ephemeral(&key_name).await?;
    ctx.set_key(ephemeral);

    let result = self.proxy_request(&ctx, &url, method, body).await;

    // ctx drops here — memory zeroed automatically
    drop(ctx);

    result
}
```

### CLI Commands

```bash
# Use JIT mode explicitly (default in v2.3+)
pqvault proxy --jit --key ANTHROPIC_API_KEY -- curl https://api.anthropic.com/v1/messages

# Verify JIT is active
pqvault config get proxy.jit_enabled

# Set maximum TTL for ephemeral keys (default: 500ms)
pqvault config set proxy.jit_max_ttl_ms 200

# Set maximum uses per decryption (default: 1)
pqvault config set proxy.jit_max_uses 1
```

### Web UI Changes

- Add "JIT Enabled" badge on vault_proxy status panel
- Show ephemeral key lifetime histogram in health dashboard
- Display "Memory Exposure Time" metric per key

## Dependencies

- `zeroize = "1"` — Securely zero memory on drop (new dependency)
- `zeroize_derive = "1"` — Derive macro for Zeroize trait
- `pqvault-core` — `decrypt_ephemeral()` API
- Feature 001 (vault_proxy) must be implemented first

## Testing

### Unit Tests

```rust
#[test]
fn ephemeral_key_zeros_on_drop() {
    let plaintext = b"sk-secret-key-12345".to_vec();
    let ptr = plaintext.as_ptr();
    let len = plaintext.len();

    let ek = EphemeralKey::new(plaintext, Duration::from_secs(5));
    assert_eq!(ek.as_bytes(), b"sk-secret-key-12345");
    drop(ek);

    // Memory should be zeroed (best-effort check)
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(slice.iter().all(|&b| b == 0), "Memory was not zeroed");
}

#[test]
#[should_panic(expected = "exceeded TTL")]
fn ephemeral_key_panics_after_ttl() {
    let ek = EphemeralKey::new(b"secret".to_vec(), Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(10));
    let _ = ek.as_bytes(); // should panic
}

#[test]
fn jit_context_limits_uses() {
    let mut ctx = JitContext::new("test_key", Duration::from_secs(5), 1);
    ctx.set_key(EphemeralKey::new(b"val".to_vec(), Duration::from_secs(5)));
    assert!(ctx.use_key().is_ok());
    assert!(ctx.use_key().is_err()); // max_uses exceeded
}
```

### Integration Tests

```rust
#[tokio::test]
async fn jit_proxy_zeros_after_use() {
    let vault = test_vault().await;
    vault.store("TEST_KEY", "secret_value").await.unwrap();

    let result = vault.proxy_jit("TEST_KEY", "https://httpbin.org/get").await;
    assert!(result.is_ok());

    // Verify no plaintext in vault's internal state
    assert!(vault.has_cached_plaintext("TEST_KEY").is_none());
}
```

### Manual Verification

1. Enable JIT mode, make a proxy call
2. Attach debugger, inspect process memory for plaintext
3. Verify plaintext is not found after call completes
4. Check audit log shows JIT decryption events

## Example Usage

```bash
# Before JIT (v2.2): key decrypted at session start, stays in memory
pqvault proxy --key OPENAI_KEY -- curl https://api.openai.com/v1/models
# Memory contains plaintext for entire session duration

# After JIT (v2.3): key decrypted only during the curl call
pqvault proxy --jit --key OPENAI_KEY -- curl https://api.openai.com/v1/models
# Memory contains plaintext for ~5ms

# In MCP context (automatic):
# Agent calls vault_proxy_jit → decrypt → inject → request → zero → return
```
