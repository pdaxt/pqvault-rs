use anyhow::Result;
use clap::{Parser, Subcommand};

use pqvault_core::health::check_health;
use pqvault_core::models;
use pqvault_core::vault;

#[derive(Parser)]
#[command(name = "pqvault", version = "2.1.0")]
#[command(about = "Quantum-proof centralized secrets management")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init,
    /// Show vault status
    Status,
    /// List all secrets
    List,
    /// Get a secret value
    Get {
        /// Key name
        key: String,
    },
    /// Add a secret
    Add {
        /// Key name
        key: String,
        /// Secret value
        value: String,
        /// Category
        #[arg(short, long)]
        category: Option<String>,
    },
    /// Delete a secret
    Delete {
        /// Key name
        key: String,
    },
    /// Check vault health
    Health,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            if vault::vault_exists() {
                eprintln!("Vault already exists at ~/.pqvault/");
                return Ok(());
            }
            let pw = vault::init_vault()?;
            eprintln!("Vault initialized. Master password stored in macOS Keychain.");
            eprintln!("Backup password: {}", pw);
            Ok(())
        }
        Commands::Status => {
            if !vault::vault_exists() {
                eprintln!("No vault found. Run 'pqvault init' first.");
                return Ok(());
            }
            let data = vault::open_vault()?;
            let report = check_health(&data);
            println!("Total Secrets: {}", report.total_secrets);
            println!("Projects: {}", data.projects.len());
            println!(
                "Health: {}",
                if report.is_healthy() {
                    "HEALTHY"
                } else {
                    "ISSUES FOUND"
                }
            );
            if !report.expired.is_empty() {
                println!("Expired: {}", report.expired.join(", "));
            }
            if !report.needs_rotation.is_empty() {
                println!("Needs Rotation: {}", report.needs_rotation.join(", "));
            }
            Ok(())
        }
        Commands::List => {
            if !vault::vault_exists() {
                eprintln!("No vault found.");
                return Ok(());
            }
            let data = vault::open_vault()?;
            let mut keys: Vec<&String> = data.secrets.keys().collect();
            keys.sort();
            for k in keys {
                let s = &data.secrets[k];
                println!(
                    "{} [{}] projects={} rotated={}",
                    k,
                    s.category,
                    s.projects.join(","),
                    s.rotated
                );
            }
            Ok(())
        }
        Commands::Get { key } => {
            if !vault::vault_exists() {
                eprintln!("No vault found.");
                return Ok(());
            }
            let data = vault::open_vault()?;
            match data.secrets.get(&key) {
                Some(s) => println!("{}", s.value),
                None => eprintln!("Key not found: {}", key),
            }
            Ok(())
        }
        Commands::Add {
            key,
            value,
            category,
        } => {
            if !vault::vault_exists() {
                eprintln!("No vault found. Run 'pqvault init' first.");
                return Ok(());
            }
            let mut data = vault::open_vault()?;
            let cat = category.unwrap_or_else(|| models::auto_categorize(&key));
            data.secrets.insert(
                key.clone(),
                models::SecretEntry {
                    value,
                    category: cat.clone(),
                    description: String::new(),
                    created: chrono::Local::now().format("%Y-%m-%d").to_string(),
                    rotated: chrono::Local::now().format("%Y-%m-%d").to_string(),
                    expires: None,
                    rotation_days: 90,
                    projects: vec![],
                    tags: vec![],
                    account: None,
                    environment: None,
                    related_keys: vec![],
                    last_verified: None,
                    last_error: None,
                    key_status: "unknown".to_string(),
                },
            );
            vault::save_vault(&data)?;
            println!("Added: {} [{}]", key, cat);
            Ok(())
        }
        Commands::Delete { key } => {
            if !vault::vault_exists() {
                eprintln!("No vault found.");
                return Ok(());
            }
            let mut data = vault::open_vault()?;
            if data.secrets.remove(&key).is_some() {
                for proj in data.projects.values_mut() {
                    proj.keys.retain(|k| k != &key);
                }
                vault::save_vault(&data)?;
                println!("Deleted: {}", key);
            } else {
                eprintln!("Key not found: {}", key);
            }
            Ok(())
        }
        Commands::Health => {
            if !vault::vault_exists() {
                eprintln!("No vault found.");
                return Ok(());
            }
            let data = vault::open_vault()?;
            let report = check_health(&data);
            println!("Total: {} secrets", report.total_secrets);
            if report.is_healthy() {
                println!("Status: HEALTHY");
            } else {
                if !report.expired.is_empty() {
                    println!("EXPIRED: {}", report.expired.join(", "));
                }
                if !report.needs_rotation.is_empty() {
                    println!("NEEDS ROTATION: {}", report.needs_rotation.join(", "));
                }
            }
            Ok(())
        }
    }
}
