//! SLT client runtime library.
//!
//! Provides the embeddable client runtime backing the `client` binary. The
//! public entrypoint is [`run_client`], which drives connection establishment,
//! authentication, the TCP-to-UDP-QSP transport upgrade, and TUN packet
//! forwarding until shutdown is requested.
//!
//! The runtime is platform-agnostic: `run_client` consumes packet I/O injected
//! as [`TunHandles`] + [`TunChannels`]. The desktop backend is `spawn_desktop`
//! (Linux only); other platforms provide their own spawn function — for example
//! Android wraps a `VpnService` file descriptor.

#[cfg(target_os = "android")]
mod android;
mod auth;
mod metrics;
mod runtime;
mod transport;
mod tun;
mod wire;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod test_integration;

pub use runtime::run_client;
#[cfg(target_os = "linux")]
pub use tun::spawn_desktop;
pub use tun::{TunChannels, TunHandles};
