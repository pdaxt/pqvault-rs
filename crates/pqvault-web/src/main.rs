use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

mod auth;
mod web;

#[derive(Parser)]
#[command(name = "pqvault-web", version = "2.1.0")]
#[command(about = "PQVault Web Dashboard")]
struct Cli {
    /// Port to listen on (overridden by $PORT env var on Cloud Run)
    #[arg(short, long, default_value_t = 9876)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(false)
        .init();

    let cli = Cli::parse();

    // Cloud Run sets $PORT; use it if available, else CLI arg
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(cli.port);

    web::start_web(port).await?;
    Ok(())
}
