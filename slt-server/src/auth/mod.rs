//! Client authentication and session management.
//!
//! This module handles the authentication phase of client connections, from TLS
//! handshake through successful authentication, and spawns client sessions.
//!
//! # Architecture
//!
//! The module is organized around three main components:
//!
//! - [`Authenticator`]: Simple allowlist-based client validation against server config.
//! - [`AuthHandlerBase`]: Handles TLS handshake and the AUTH protocol message exchange.
//! - [`SessionManager`]: Manages session creation and lifecycle resources.

mod authenticator;
mod errors;
mod handler;
mod session_manager;
mod types;

#[cfg(test)]
mod tests;

pub use authenticator::Authenticator;
pub use handler::{AuthHandler, AuthHandlerBase};
pub use session_manager::SessionManager;
