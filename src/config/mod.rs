//! Configuration types for client and server.

pub mod client;
mod serde_hex;
mod serde_secret;
pub mod server;

pub use client::{ClientConfig, UpgradePreferences};
pub use server::{ServerClient, ServerConfig};
