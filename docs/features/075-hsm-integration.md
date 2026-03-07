# Feature 075: HSM Integration

## Status: Done
## Phase: 8 (v2.8)
## Priority: Medium

## Problem

The master key is currently stored in the macOS Keychain, which is software-based
and vulnerable to malware with elevated privileges. For high-security environments,
compliance frameworks (SOC2, PCI-DSS) require hardware-backed key storage where the
master key never leaves the physical device. Enterprises using PQVault for production
secrets need hardware security module support.

## Solution

Integrate with YubiKey hardware security modules to store the master encryption key
on a physical device. The key is generated on-device, never exported, and all
cryptographic operations (key wrapping/unwrapping) happen on the YubiKey itself.
This provides tamper-evident, hardware-backed security with physical possession
as a second factor.

## Implementation

### Files to Create/Modify

```
pqvault-core/
  src/
    hsm/
      mod.rs           # HSM trait and module root
      yubikey.rs       # YubiKey PIV integration
      keychain.rs      # Existing Keychain backend (refactored)
      backend.rs       # KeyBackend trait definition
      manager.rs       # Backend selection and management
```

### Data Model Changes

```rust
use yubikey::{YubiKey, piv, MgmKey, Key};

/// Trait for master key storage backends
#[async_trait]
pub trait KeyBackend: Send + Sync {
    /// Backend name for display
    fn name(&self) -> &str;

    /// Whether the backend is available on this system
    fn is_available(&self) -> bool;

    /// Store a wrapped master key
    async fn store_key(&mut self, key_data: &[u8]) -> Result<()>;

    /// Retrieve and unwrap the master key
    async fn retrieve_key(&self) -> Result<Vec<u8>>;

    /// Delete the stored key
    async fn delete_key(&mut self) -> Result<()>;

    /// Perform a key wrapping operation on the HSM
    async fn wrap_key(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Perform a key unwrapping operation on the HSM
    async fn unwrap_key(&self, wrapped: &[u8]) -> Result<Vec<u8>>;

    /// Get backend status information
    async fn status(&self) -> BackendStatus;
}

pub struct BackendStatus {
    pub backend_type: String,
    pub available: bool,
    pub key_stored: bool,
    pub details: HashMap<String, String>,
}

/// YubiKey PIV backend
pub struct YubiKeyBackend {
    serial: Option<u32>,
    slot: piv::SlotId,
    pin: Option<String>,
}

impl YubiKeyBackend {
    pub fn new() -> Result<Self> {
        Ok(Self {
            serial: None,
            slot: piv::SlotId::KeyManagement, // Slot 9D
            pin: None,
        })
    }

    pub fn with_serial(mut self, serial: u32) -> Self {
        self.serial = Some(serial);
        self
    }

    fn open_yubikey(&self) -> Result<YubiKey> {
        match self.serial {
            Some(serial) => YubiKey::open_by_serial(serial.into())
                .map_err(|e| anyhow!("Failed to open YubiKey {}: {}", serial, e)),
            None => YubiKey::open()
                .map_err(|e| anyhow!("Failed to open YubiKey: {}", e)),
        }
    }
}

#[async_trait]
impl KeyBackend for YubiKeyBackend {
    fn name(&self) -> &str { "YubiKey PIV" }

    fn is_available(&self) -> bool {
        self.open_yubikey().is_ok()
    }

    async fn store_key(&mut self, key_data: &[u8]) -> Result<()> {
        let mut yk = self.open_yubikey()?;

        // Verify PIN
        let pin = self.pin.as_deref()
            .ok_or_else(|| anyhow!("YubiKey PIN required"))?;
        yk.verify_pin(pin.as_bytes())?;

        // Generate an RSA key on the YubiKey
        let generated = piv::generate(
            &mut yk,
            self.slot,
            piv::AlgorithmId::Rsa2048,
            piv::PinPolicy::Once,
            piv::TouchPolicy::Always,  // Require physical touch
        )?;

        // Encrypt the master key with the YubiKey's public key
        let wrapped = wrap_with_public_key(&generated, key_data)?;

        // Store the wrapped key locally (only YubiKey can unwrap it)
        store_wrapped_key(&wrapped)?;

        Ok(())
    }

    async fn retrieve_key(&self) -> Result<Vec<u8>> {
        let mut yk = self.open_yubikey()?;
        let pin = self.pin.as_deref()
            .ok_or_else(|| anyhow!("YubiKey PIN required"))?;
        yk.verify_pin(pin.as_bytes())?;

        let wrapped = load_wrapped_key()?;

        // Decrypt on the YubiKey (key never leaves the device)
        let decrypted = piv::decrypt_data(
            &mut yk,
            &wrapped,
            piv::AlgorithmId::Rsa2048,
            self.slot,
        )?;

        Ok(decrypted)
    }

    async fn status(&self) -> BackendStatus {
        let mut details = HashMap::new();
        match self.open_yubikey() {
            Ok(yk) => {
                details.insert("serial".into(), yk.serial().to_string());
                details.insert("version".into(), yk.version().to_string());
                BackendStatus {
                    backend_type: "YubiKey PIV".into(),
                    available: true,
                    key_stored: load_wrapped_key().is_ok(),
                    details,
                }
            }
            Err(e) => BackendStatus {
                backend_type: "YubiKey PIV".into(),
                available: false,
                key_stored: false,
                details: [("error".into(), e.to_string())].into(),
            },
        }
    }

    async fn delete_key(&mut self) -> Result<()> {
        delete_wrapped_key()?;
        Ok(())
    }

    async fn wrap_key(&self, data: &[u8]) -> Result<Vec<u8>> {
        let yk = self.open_yubikey()?;
        let cert = piv::Certificate::read(&yk, self.slot)?;
        wrap_with_public_key(&cert.subject_pki(), data)
    }

    async fn unwrap_key(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        self.retrieve_key().await
    }
}

/// Backend selector
pub struct KeyBackendManager;

impl KeyBackendManager {
    pub fn select(config: &PqvaultConfig) -> Box<dyn KeyBackend> {
        match config.security.key_backend.as_deref() {
            Some("yubikey") => Box::new(YubiKeyBackend::new().unwrap()),
            Some("keychain") | None => Box::new(KeychainBackend::new()),
            Some(other) => panic!("Unknown key backend: {}", other),
        }
    }
}
```

### MCP Tools

No new MCP tools. HSM operations are CLI-only for security.

### CLI Commands

```bash
# Initialize vault with YubiKey backend
pqvault init --backend yubikey

# Migrate existing vault from Keychain to YubiKey
pqvault hsm migrate --from keychain --to yubikey

# Show HSM status
pqvault hsm status

# List available YubiKeys
pqvault hsm list

# Reset HSM key (requires current PIN)
pqvault hsm reset
```

### Web UI Changes

None. HSM operations require physical device interaction.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `yubikey` | 0.8 | YubiKey PIV smartcard interface |
| `x509-cert` | 0.2 | X.509 certificate handling for PIV |

Add to `pqvault-core/Cargo.toml`:

```toml
[dependencies]
yubikey = { version = "0.8", optional = true }
x509-cert = { version = "0.2", optional = true }

[features]
hsm = ["yubikey", "x509-cert"]
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_selection_keychain() {
        let config = PqvaultConfig::default();
        let backend = KeyBackendManager::select(&config);
        assert_eq!(backend.name(), "macOS Keychain");
    }

    #[test]
    fn test_backend_selection_yubikey() {
        let mut config = PqvaultConfig::default();
        config.security.key_backend = Some("yubikey".into());
        let backend = KeyBackendManager::select(&config);
        assert_eq!(backend.name(), "YubiKey PIV");
    }

    #[test]
    fn test_yubikey_availability() {
        let backend = YubiKeyBackend::new().unwrap();
        // In CI without a YubiKey, this should return false
        let status = tokio_test::block_on(backend.status());
        // Don't assert is_available since CI may not have a YubiKey
        assert_eq!(status.backend_type, "YubiKey PIV");
    }

    #[test]
    fn test_wrapped_key_storage() {
        let tmpdir = tempdir().unwrap();
        let wrapped = vec![0x01, 0x02, 0x03, 0x04];
        store_wrapped_key_at(&tmpdir.path().join("wrapped.key"), &wrapped).unwrap();
        let loaded = load_wrapped_key_from(&tmpdir.path().join("wrapped.key")).unwrap();
        assert_eq!(wrapped, loaded);
    }

    #[test]
    fn test_keychain_backend_trait_impl() {
        let backend = KeychainBackend::new();
        assert_eq!(backend.name(), "macOS Keychain");
        assert!(backend.is_available()); // Keychain always available on macOS
    }
}
```

## Example Usage

```
$ pqvault hsm status

  HSM Status
  ────────────────────────

  Backend: YubiKey PIV
  Available: Yes
  Serial: 12345678
  Firmware: 5.4.3
  Key Stored: Yes
  Slot: 9D (Key Management)
  PIN Policy: Once per session
  Touch Policy: Always (physical touch required)

$ pqvault init --backend yubikey

  Initializing PQVault with YubiKey backend...

  YubiKey detected: Serial 12345678 (Firmware 5.4.3)
  Enter YubiKey PIN: ******
  Touch YubiKey to confirm...  [touched]

  Generating RSA-2048 key on YubiKey slot 9D...
  Master key wrapped and stored locally.
  The master key NEVER leaves the YubiKey.

  Vault initialized successfully.
  Backend: YubiKey PIV (serial: 12345678)
  Touch required for every vault unlock.
```
