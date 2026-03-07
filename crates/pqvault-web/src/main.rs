use anyhow::Result;
use clap::Parser;

mod web;

#[derive(Parser)]
#[command(name = "pqvault-web", version = "2.1.0")]
#[command(about = "PQVault Web Dashboard")]
struct Cli {
    /// Port to listen on
    #[arg(short, long, default_value_t = 9876)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if !pqvault_core::vault::vault_exists() {
        eprintln!("No vault found. Run 'pqvault init' first.");
        return Ok(());
    }

    web::start_web(cli.port).await?;
    Ok(())
}
