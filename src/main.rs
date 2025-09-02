mod cache;
mod config;
mod http_cache;
mod server;

use crate::config::Config; // includes eviction policy
use anyhow::Result;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env (if present) so both .env file and system env work seamlessly
    let _ = dotenvy::dotenv();
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;
    tracing::info!(?config, "Starting caching server");

    server::run(config).await
}
