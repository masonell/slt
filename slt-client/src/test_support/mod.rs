//! Test support utilities for slt-client.
//!
//! Only compiled in test builds. Provides:
//! - Configuration fixtures (`config`)
//! - Crypto key helpers (`crypto`)
//! - Transport test utilities (`transport`)
//! - Protocol message helpers (`protocol`)
//! - Mock TLS server (`server`)

mod config;
mod crypto;
mod protocol;
mod server;
mod transport;

pub use config::*;
pub use crypto::*;
pub use protocol::*;
// Re-export specific server items that are used by integration tests
#[allow(unused_imports)]
pub use server::{MockMessage, MockTlsServer, tls_client_channel_pair, tls_server_pair};
pub use transport::*;
