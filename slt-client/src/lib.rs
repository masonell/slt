//! SLT client runtime library.
//!
//! Provides the embeddable client runtime backing the `client` binary. The
//! public entrypoint is [`run_client`], which drives connection establishment,
//! authentication, the TCP-to-UDP-QSP transport upgrade, and TUN packet
//! forwarding until shutdown is requested.
//!
//! The runtime is currently desktop-only: it creates a local TUN device with
//! `tun-rs`. Injecting platform-specific packet I/O (for example an Android
//! `VpnService` file descriptor) is a later milestone.

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
