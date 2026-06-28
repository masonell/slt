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

/// TCP `ClientHello` classifier and verdicts.
pub mod classifier;

pub mod crypto;
/// Test-only fixtures; exempt from clippy's code-quality groups like other test code.
#[cfg(any(test, feature = "testing"))]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::perf,
    clippy::pedantic,
    clippy::nursery
)]
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
