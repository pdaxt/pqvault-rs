use rand::Rng;

const SERVICE_NAME: &str = "pqvault";
const ACCOUNT_NAME: &str = "master";

pub fn store_master_password(password: &str) -> anyhow::Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME)?;
    entry.set_password(password)?;
    Ok(())
}

pub fn get_master_password() -> anyhow::Result<Option<String>> {
    let entry = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME)?;
    match entry.get_password() {
        Ok(pw) => Ok(Some(pw)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn delete_master_password() -> anyhow::Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
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
