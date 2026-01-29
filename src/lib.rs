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
/// Common types used across the codebase.
pub mod types;
