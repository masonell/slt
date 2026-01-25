use clap::Parser;
use slt::config::ServerConfig;
use slt::server::tcp::TcpFrontDoor;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(about = "Run the SLT server front door.")]
struct Args {
    /// Path to the server configuration file (TOML).
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let raw = fs::read_to_string(&args.config)?;
    let config: ServerConfig = toml::from_str(&raw)?;
    let config = Arc::new(config);

    let frontdoor = TcpFrontDoor::bind(config.clone(), config.server_secret).await?;
    let cancel = CancellationToken::new();

    let cancel_task = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_task.cancel();
        }
    });

    frontdoor
        .run(cancel, move |stream: TcpStream, addr: SocketAddr| {
            tokio::spawn(async move {
                eprintln!("claimed tcp connection from {addr}");
                drop(stream);
            });
        })
        .await?;

    Ok(())
}
