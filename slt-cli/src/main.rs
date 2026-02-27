//! SLT VPN configuration CLI.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod config_io;

/// SLT VPN configuration management tool.
#[derive(Parser)]
#[command(name = "slt", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output in JSON format.
    #[arg(global = true, long)]
    json: bool,

    /// Suppress non-error output.
    #[arg(global = true, long, conflicts_with = "json")]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize server configuration.
    Init {
        /// Directory for config and certs.
        #[arg(long, value_name = "DIR")]
        config_dir: String,

        /// Server domain name.
        #[arg(long, value_name = "DOMAIN")]
        domain: String,

        /// Embed certificates in config instead of file references.
        #[arg(long)]
        inline_certs: bool,
    },

    /// Validate deployed server setup.
    CheckServer {
        /// Server domain to check.
        domain: String,

        /// Client config for VPN auth test.
        #[arg(long, value_name = "FILE")]
        client_config: Option<String>,
    },

    /// Display server configuration summary.
    ShowServer {
        /// Path to server config file.
        #[arg(long, value_name = "FILE")]
        config: String,

        /// Show secrets in output.
        #[arg(long)]
        reveal_secrets: bool,
    },

    /// Add a new client.
    AddClient {
        /// Path to server config file.
        #[arg(long, value_name = "FILE")]
        config: String,

        /// Directory to write client config.
        #[arg(long, value_name = "DIR")]
        output_dir: String,

        /// Assigned IPv4 address (auto-assigned if not specified).
        #[arg(long, value_name = "IP")]
        ip: Option<String>,
    },

    /// List all clients.
    ListClients {
        /// Path to server config file.
        #[arg(long, value_name = "FILE")]
        config: String,
    },

    /// Display client details.
    ShowClient {
        /// Client ID (hex).
        client_id: String,

        /// Path to server config file.
        #[arg(long, value_name = "FILE")]
        config: String,
    },

    /// Output client configuration file.
    ShowClientConfig {
        /// Client ID (hex).
        client_id: String,

        /// Path to server config file.
        #[arg(long, value_name = "FILE")]
        config: String,
    },

    /// Remove a client.
    RemoveClient {
        /// Client ID (hex).
        client_id: String,

        /// Path to server config file.
        #[arg(long, value_name = "FILE")]
        config: String,
    },

    /// Generate CA and server certificates.
    GenerateCerts {
        /// Directory for config and certs.
        #[arg(long, value_name = "DIR")]
        config_dir: String,

        /// Server domain name.
        #[arg(long, value_name = "DOMAIN")]
        domain: Option<String>,
    },

    /// Generate Ed25519 keypair.
    GenerateKeys,

    /// Validate a configuration file.
    Validate {
        /// Path to config file (server or client).
        config: String,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Init { .. } => {
            todo!("init")
        }
        Commands::CheckServer { .. } => {
            todo!("check-server")
        }
        Commands::ShowServer { .. } => {
            todo!("show-server")
        }
        Commands::AddClient { .. } => {
            todo!("add-client")
        }
        Commands::ListClients { .. } => {
            todo!("list-clients")
        }
        Commands::ShowClient { .. } => {
            todo!("show-client")
        }
        Commands::ShowClientConfig { .. } => {
            todo!("show-client-config")
        }
        Commands::RemoveClient { .. } => {
            todo!("remove-client")
        }
        Commands::GenerateCerts { .. } => {
            todo!("generate-certs")
        }
        Commands::GenerateKeys => {
            todo!("generate-keys")
        }
        Commands::Validate { config } => {
            todo!("validate: {config}")
        }
    }
}
