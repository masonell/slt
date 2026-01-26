#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::multiple_crate_versions)]

/// TCP `ClientHello` classifier and verdicts.
pub mod classifier;
pub mod crypto;
/// `ClientHello` parsing and `legacy_session_id` helpers.
pub use crypto::client_hello;
/// Static configuration types.
pub mod config;
/// VPN protocol framing and message definitions.
pub mod proto;
/// Server-side abstractions.
pub mod server;
