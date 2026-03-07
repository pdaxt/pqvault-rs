use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::audit::log_access;
use crate::crypto::{
    generate_keypair, hybrid_decrypt, hybrid_encrypt, password_decrypt, password_encrypt,
    EncryptedPayload,
};
use crate::keychain::{generate_master_password, get_master_password, store_master_password};
use crate::models::VaultData;
use x25519_dalek::StaticSecret;

fn vault_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".pqvault")
}

pub fn vault_file() -> PathBuf {
    vault_dir().join("vault.enc")
}
pub fn meta_file() -> PathBuf {
    vault_dir().join("vault.meta.json")
}
fn pq_public_file() -> PathBuf {
    vault_dir().join("pq_public.bin")
}
fn pq_private_file() -> PathBuf {
    vault_dir().join("pq_private.enc")
}
fn x25519_public_file() -> PathBuf {
    vault_dir().join("x25519_public.bin")
}
fn x25519_private_file() -> PathBuf {
    vault_dir().join("x25519_private.enc")
}
fn backup_dir() -> PathBuf {
    vault_dir().join("backups")
}

pub fn vault_exists() -> bool {
    meta_file().exists()
}

pub fn init_vault() -> anyhow::Result<String> {
    let dir = vault_dir();
    fs::create_dir_all(&dir)?;
    fs::create_dir_all(backup_dir())?;

    let master_pw = generate_master_password(48);
    store_master_password(&master_pw)?;

    let kp = generate_keypair()?;

    // Save public keys
    fs::write(pq_public_file(), &kp.pq_public)?;
    fs::write(x25519_public_file(), kp.x25519_public.as_bytes())?;

    // Save private keys (encrypted)
    let pq_priv_enc = password_encrypt(&kp.pq_secret, &master_pw)?;
    fs::write(pq_private_file(), &pq_priv_enc)?;

    let x25519_raw = kp.x25519_private.to_bytes();
    let x25519_priv_enc = password_encrypt(&x25519_raw, &master_pw)?;
    fs::write(x25519_private_file(), &x25519_priv_enc)?;

    // Restrict permissions
    fs::set_permissions(pq_private_file(), fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(x25519_private_file(), fs::Permissions::from_mode(0o600))?;

    // Save metadata
    let meta = serde_json::json!({
        "version": "1.0",
        "encryption": "hybrid-mlkem768-x25519-aes256gcm",
        "kdf": "scrypt-n131072-r8-p1",
        "pq_algorithm": "ML-KEM-768 (FIPS 203)",
        "classical_algorithm": "X25519",
        "symmetric_algorithm": "AES-256-GCM",
    });
    fs::write(meta_file(), serde_json::to_string_pretty(&meta)?)?;

    // Create empty vault
    let empty = VaultData::default();
    save_vault_internal(&empty, &master_pw)?;

    log_access("init", "", "", "cli");
    Ok(master_pw)
}

fn load_x25519_private(master_pw: &str) -> anyhow::Result<StaticSecret> {
    let enc = fs::read(x25519_private_file())?;
    let raw = password_decrypt(&enc, master_pw)?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid X25519 private key size"))?;
    Ok(StaticSecret::from(bytes))
}

fn save_vault_internal(data: &VaultData, _master_pw: &str) -> anyhow::Result<()> {
    let plaintext = serde_json::to_string_pretty(data)?.into_bytes();
    let pq_public = fs::read(pq_public_file())?;
    let x25519_public = fs::read(x25519_public_file())?;
    let payload = hybrid_encrypt(&plaintext, &pq_public, &x25519_public)?;
    let serialized = payload.serialize();
    fs::write(vault_file(), &serialized)?;
    fs::set_permissions(vault_file(), fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn open_vault() -> anyhow::Result<VaultData> {
    let master_pw = get_master_password()?
        .ok_or_else(|| anyhow::anyhow!("No master password found. Run 'pqvault init' first."))?;

    if !vault_file().exists() {
        anyhow::bail!("Vault file not found. Run 'pqvault init' first.");
    }

    let encrypted = fs::read(vault_file())?;
    let payload = EncryptedPayload::deserialize(&encrypted)?;

    let pq_secret_enc = fs::read(pq_private_file())?;
    let pq_secret = password_decrypt(&pq_secret_enc, &master_pw)?;
    let x25519_private = load_x25519_private(&master_pw)?;

    let plaintext = hybrid_decrypt(&payload, &pq_secret, &x25519_private)?;
    let data: VaultData = serde_json::from_slice(&plaintext)?;

    log_access("open", "", "", "mcp");
    Ok(data)
}

pub fn save_vault(data: &VaultData) -> anyhow::Result<()> {
    let master_pw = get_master_password()?
        .ok_or_else(|| anyhow::anyhow!("No master password found."))?;
    save_vault_internal(data, &master_pw)?;
    log_access("save", "", "", "mcp");
    Ok(())
}

/// Auto-reloading vault holder. Checks file mtime and size before each access
/// and reloads from disk if another process has updated the vault file.
pub struct VaultHolder {
    data: Option<VaultData>,
    loaded_mtime: Option<std::time::SystemTime>,
    loaded_size: u64,
}

impl VaultHolder {
    pub fn new() -> Self {
        let (data, mtime, size) = if vault_exists() {
            let meta = fs::metadata(vault_file()).ok();
            let mtime = meta.as_ref().and_then(|m| m.modified().ok());
            let size = meta.map(|m| m.len()).unwrap_or(0);
            (open_vault().ok(), mtime, size)
        } else {
            (None, None, 0)
        };
        Self {
            data,
            loaded_mtime: mtime,
            loaded_size: size,
        }
    }

    /// Get a reference to vault data, reloading from disk if stale.
    pub fn get(&mut self) -> Option<&VaultData> {
        self.reload_if_stale();
        self.data.as_ref()
    }

    /// Get a mutable reference to vault data, reloading from disk if stale.
    pub fn get_mut(&mut self) -> Option<&mut VaultData> {
        self.reload_if_stale();
        self.data.as_mut()
    }

    /// After saving vault to disk, update our mtime/size so we don't reload our own write.
    pub fn mark_saved(&mut self) {
        let meta = fs::metadata(vault_file()).ok();
        self.loaded_mtime = meta.as_ref().and_then(|m| m.modified().ok());
        self.loaded_size = meta.map(|m| m.len()).unwrap_or(0);
    }

    fn reload_if_stale(&mut self) {
        let meta = fs::metadata(vault_file()).ok();
        let current_mtime = meta.as_ref().and_then(|m| m.modified().ok());
        let current_size = meta.map(|m| m.len()).unwrap_or(0);
        if current_mtime != self.loaded_mtime || current_size != self.loaded_size {
            if let Ok(data) = open_vault() {
                self.data = Some(data);
                self.loaded_mtime = current_mtime;
                self.loaded_size = current_size;
                tracing::info!("Vault reloaded from disk (file changed by another process)");
            }
        }
    }
}

pub fn backup_vault() -> anyhow::Result<Option<PathBuf>> {
    if !vault_file().exists() {
        return Ok(None);
    }
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let backup_path = backup_dir().join(format!("vault.{}.enc", today));
    fs::create_dir_all(backup_dir())?;
    fs::copy(vault_file(), &backup_path)?;
    log_access("backup", "", "", "cli");
    Ok(Some(backup_path))
}
