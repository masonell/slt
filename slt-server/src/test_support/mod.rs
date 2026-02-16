//! Test support utilities for slt-server.
//!
//! Only compiled in test builds. Provides:
//! - TUN device mocks (`tun`)
//! - UDP socket mocks (`udp`)
//! - TLS test utilities (`tls`)
//! - Auth handler test utilities (`auth`)

#[allow(unused)]
mod auth;
#[allow(unused)]
mod tls;
mod tun;
#[allow(unused)]
mod udp;

#[allow(unused_imports)]
pub use auth::*;
#[allow(unused_imports)]
pub use tls::*;
pub use tun::*;
#[allow(unused_imports)]
pub use udp::*;
