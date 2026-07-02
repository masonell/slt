//! SLT VPN configuration CLI.

// Test code is exempt from clippy's code-quality groups (`style`, `complexity`,
// `perf`, `pedantic`, `nursery`); the bug-catching `correctness`/`suspicious`
// groups stay enforced under `#[cfg(test)]`.
#![cfg_attr(
    test,
    allow(
        clippy::style,
        clippy::complexity,
        clippy::perf,
        clippy::pedantic,
        clippy::nursery,
    )
)]

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod add_client;
mod cert;
mod check_server;
mod client_config;
mod client_id;
mod config_io;
mod generate_certs;
mod generate_keys;
mod http_probe;
mod init;
mod list_clients;
mod remove_client;
mod show_client;
mod show_client_config;
mod show_server;
mod validate;

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

        /// Server domain name for client config (extracted from cert if not provided).
        #[arg(long, value_name = "DOMAIN")]
        domain: Option<String>,

        /// Assigned IPv4 address for the client's TUN interface.
        #[arg(long, value_name = "IP")]
        ip: String,
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

        /// Server domain name (extracted from cert if not provided).
        #[arg(long, value_name = "DOMAIN")]
        domain: Option<String>,
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
        domain: String,
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
        Commands::Init {
            config_dir,
            domain,
            inline_certs,
        } => {
            let config_path = PathBuf::from(&config_dir);
            init::init(&config_path, &domain, inline_certs, cli.quiet)
        }
        Commands::CheckServer {
            domain,
            client_config,
        } => {
            let client_config_path = client_config.as_deref().map(PathBuf::from);
            check_server::check_server(&domain, client_config_path.as_deref(), cli.quiet)
        }
        Commands::ShowServer {
            config,
            reveal_secrets,
        } => {
            let config_path = PathBuf::from(&config);
            show_server::show_server(&config_path, reveal_secrets)
        }
        Commands::AddClient {
            config,
            output_dir,
            domain,
            ip,
        } => {
            let config_path = PathBuf::from(&config);
            let output_path = PathBuf::from(&output_dir);
            add_client::add_client(
                &config_path,
                &output_path,
                domain.as_deref(),
                &ip,
                cli.quiet,
            )
        }
        Commands::ListClients { config } => {
            let config_path = PathBuf::from(&config);
            list_clients::list_clients(&config_path, cli.quiet)
        }
        Commands::ShowClient { client_id, config } => {
            let config_path = PathBuf::from(&config);
            show_client::show_client(&config_path, &client_id, cli.quiet)
        }
        Commands::ShowClientConfig {
            client_id,
            config,
            domain,
        } => {
            let config_path = PathBuf::from(&config);
            show_client_config::show_client_config(
                &config_path,
                &client_id,
                domain.as_deref(),
                cli.quiet,
            )
        }
        Commands::RemoveClient { client_id, config } => {
            let config_path = PathBuf::from(&config);
            remove_client::remove_client(&config_path, &client_id, cli.quiet)
        }
        Commands::GenerateCerts { config_dir, domain } => {
            let config_path = PathBuf::from(&config_dir);
            generate_certs::generate_certs(&config_path, &domain, cli.quiet)
        }
        Commands::GenerateKeys => {
            generate_keys::generate_keys();
            Ok(())
        }
        Commands::Validate { config } => {
            let path = PathBuf::from(&config);
            validate::validate(&path, !cli.quiet)
        }
    }
}
