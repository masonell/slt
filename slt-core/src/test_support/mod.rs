//! Test support utilities for slt-core.
//!
//! Only compiled in test builds. Provides:
//! - ClientHello generation helpers (`client_hello`)

mod client_hello;

pub use client_hello::*;
