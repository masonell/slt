//! Platform services injected into the client runtime.
//!
//! [`ClientRuntimeServices`] is a trait with associated types so the runtime is
//! monomorphized per concrete service bundle — there is no `dyn` dispatch and no
//! `Arc<dyn …>` indirection on the socket protector, host resolver, or observer.
//! The desktop CLI supplies [`DesktopServices`]; Android supplies
//! [`AndroidServices`]. Both are plain structs holding the concrete types, so
//! the runtime gets static dispatch while keeping a single generic entrypoint
//! ([`crate::runtime::run_client`]).

use crate::runtime::observer::{ClientObserver, ObserverSink};
use crate::transport::host_resolver::HostResolver;
use crate::transport::socket_protector::SocketProtector;

/// Platform services injected into the client runtime.
///
/// Grouped as a trait (with associated types) rather than a struct of
/// `Arc<dyn …>` so each concrete bundle is monomorphized: the socket
/// protector, host resolver, and observer are all statically dispatched. This
/// is appropriate because the concrete types are fixed per build (desktop vs
/// Android) — there is no runtime polymorphism to pay for.
///
/// `run_client` is generic over `S: ClientRuntimeServices`, so the bundle stays
/// one argument (Phase 3 grouping) without introducing `dyn`. The trait itself
/// carries no `dyn`, even though a concrete impl (Android) may use `Arc<dyn …>`
/// internally to bridge to its own platform callbacks.
pub trait ClientRuntimeServices: Send + Sync + 'static {
    /// Socket protector excluding transport sockets from VPN routing.
    /// `Clone` so it can be moved into spawned background tasks.
    type SocketProtector: SocketProtector + Clone + Send + Sync + 'static;
    /// Host resolver used for server hostname resolution.
    /// `Clone` so it can be moved into spawned background tasks.
    type HostResolver: HostResolver + Clone + Send + Sync + 'static;
    /// Observer receiving typed client lifecycle events.
    type Observer: ClientObserver + Send + Sync + 'static;

    /// Borrow the socket protector.
    fn socket_protector(&self) -> &Self::SocketProtector;
    /// Borrow the host resolver.
    fn host_resolver(&self) -> &Self::HostResolver;
    /// Borrow the event sink wrapping the observer.
    fn observer(&self) -> &ObserverSink<Self::Observer>;
}

// NOTE: the host-to-runtime control channel is intentionally NOT part of this
// trait. It is a single-owner command receiver whose lifetime spans reconnects
// and is polled with `&mut`, whereas this trait's accessors are `&self`
// borrows of cloneable hooks. Putting a receiver behind the trait would force
// interior mutability (a `Mutex`) just to poll it from the `&S` the session
// borrows. Instead the channel lives as a separate owned argument to
// `run_sessions` — wired in a later phase — keeping the trait about cloneable
// platform hooks. (This does mean `run_client`/`run_sessions` gain one param
// when the channel lands; that is accepted as the cleaner split.)

/// Desktop (CLI) platform services: no-op socket protection, Tokio DNS, and a
/// no-op observer.
pub struct DesktopServices {
    socket_protector: crate::transport::socket_protector::NoopSocketProtector,
    host_resolver: crate::transport::host_resolver::TokioHostResolver,
    observer: ObserverSink<crate::runtime::observer::NoopObserver>,
}

impl DesktopServices {
    /// Construct desktop services with a no-op event sink (handle `0`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            socket_protector: crate::transport::socket_protector::NoopSocketProtector,
            host_resolver: crate::transport::host_resolver::TokioHostResolver,
            observer: ObserverSink::new(0, crate::runtime::observer::NoopObserver),
        }
    }
}

impl Default for DesktopServices {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientRuntimeServices for DesktopServices {
    type SocketProtector = crate::transport::socket_protector::NoopSocketProtector;
    type HostResolver = crate::transport::host_resolver::TokioHostResolver;
    type Observer = crate::runtime::observer::NoopObserver;

    fn socket_protector(&self) -> &Self::SocketProtector {
        &self.socket_protector
    }
    fn host_resolver(&self) -> &Self::HostResolver {
        &self.host_resolver
    }
    fn observer(&self) -> &ObserverSink<Self::Observer> {
        &self.observer
    }
}
