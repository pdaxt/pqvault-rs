use rand::Rng;
use std::path::PathBuf;
use std::sync::OnceLock;

const SERVICE_NAME: &str = "pqvault";
const ACCOUNT_NAME: &str = "master";

/// In-process cache (avoids repeated Keychain calls within same process)
static CACHED_PASSWORD: OnceLock<Option<String>> = OnceLock::new();

fn cache_path() -> PathBuf {
    dirs::home_dir().unwrap().join(".pqvault").join(".master_cache")
}

/// Read master password from file cache (no Keychain prompt)
fn read_file_cache() -> Option<String> {
    let path = cache_path();
    if !path.exists() {
        return None;
    }
    std::fs::read_to_string(&path)
        .ok()
        .filter(|s| !s.is_empty())
}

/// Write master password to file cache with 0600 permissions
fn write_file_cache(pw: &str) {
    let path = cache_path();
    let _ = std::fs::write(&path, pw);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
}

pub fn store_master_password(password: &str) -> anyhow::Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME)?;
    entry.set_password(password)?;
    write_file_cache(password);
    Ok(())
}

pub fn get_master_password() -> anyhow::Result<Option<String>> {
    let cached = CACHED_PASSWORD.get_or_init(|| {
        // 1. Try file cache first (no Keychain prompt)
        if let Some(pw) = read_file_cache() {
            return Some(pw);
        }

        // 2. Fall back to Keychain (may prompt once)
        let entry = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME).ok()?;
        match entry.get_password() {
            Ok(pw) => {
                // Cache to file for future processes
                write_file_cache(&pw);
                Some(pw)
            }
            Err(_) => None,
        }
    });
    Ok(cached.clone())
}

pub fn delete_master_password() -> anyhow::Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME)?;
    match entry.delete_credential() {
        Ok(()) => {}
        Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(e.into()),
    }
    let _ = std::fs::remove_file(cache_path());
    Ok(())
}

pub fn has_master_password() -> bool {
    get_master_password().ok().flatten().is_some()
}

pub fn generate_master_password(length: usize) -> String {
    let charset: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect()
}
