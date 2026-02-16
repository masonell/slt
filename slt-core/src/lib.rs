/// TCP `ClientHello` classifier and verdicts.
pub mod classifier;

pub mod crypto;
#[cfg(any(test, feature = "testing"))]
mod test_support;

/// Test support utilities for generating test fixtures.
///
/// Only available when compiled with `test` or `testing` feature.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    /// Re-export test support utilities.
    pub use crate::test_support::*;
}
/// `ClientHello` parsing and `legacy_session_id` helpers.
pub use crypto::client_hello;
/// Static configuration types.
pub mod config;
/// IPv4 packet parsing utilities.
pub mod packet;
/// VPN protocol framing and message definitions.
pub mod proto;
/// Shared transport building blocks.
pub mod transport;
/// Common types used across the codebase.
pub mod types;
