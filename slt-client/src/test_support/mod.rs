//! Test support utilities for slt-client.
//!
//! Only compiled in test builds. Provides:
//! - Configuration fixtures (`config`)
//! - Crypto key helpers (`crypto`)
//! - Transport test utilities (`transport`)
//! - Protocol message helpers (`protocol`)

mod config;
mod crypto;
mod protocol;
mod transport;

pub use config::*;
pub use crypto::*;
pub use protocol::*;
pub use transport::*;
