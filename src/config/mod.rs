//! Configuration types for client and server.

pub mod client;
pub mod server;
mod serde_hex;

pub use client::{ClientConfig, UpgradePreferences};
pub use server::{ServerClient, ServerConfig};
