//! Test support utilities for slt-server.
//!
//! Only compiled in test builds. Provides:
//! - TUN device mocks (`tun`)

mod tun;

pub use tun::*;
