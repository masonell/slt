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

#[cfg(target_os = "android")]
uniffi::setup_scaffolding!();

#[cfg(target_os = "android")]
mod android;
mod auth;
mod error;
mod metrics;
mod runtime;
mod transport;
mod tun;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod test_integration;

pub use runtime::control::{
    ClientCommand, ClientCommandReceiver, ClientCommandSender, client_command_channel,
};
pub use runtime::observer::{
    ClientEvent, ClientEventKind, ClientObserver, NoopObserver, ObserverSink, Transport,
    TransportChangeReason,
};
pub use runtime::run_client;
pub use runtime::services::{ClientRuntimeServices, DesktopServices};
pub use transport::host_resolver::{HostResolver, TokioHostResolver};
pub use transport::socket_protector::{NoopSocketProtector, SocketKind, SocketProtector};
#[cfg(target_os = "linux")]
pub use tun::spawn_desktop;
#[cfg(target_os = "android")]
pub use tun::spawn_from_fd;
pub use tun::{TunChannels, TunHandles};
