//! Runtime observer: typed client lifecycle and protocol events.
//!
//! The runtime owns the canonical event types ([`ClientEventKind`],
//! [`ClientEvent`]) and emits them through the [`ClientObserver`] trait. The
//! Android bridge supplies an observer that forwards each event to its `UniFFI`
//! callback; the CLI uses [`NoopObserver`].
//!
//! On Android the same types carry `uniffi` derives (via `cfg_attr`) so Kotlin
//! bindings are generated directly from the Rust definitions — there is no
//! parallel hand-maintained DTO. The derives are absent off-Android so the
//! runtime core stays free of `UniFFI` scaffolding for the CLI build.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// Active transport reported by an event, when applicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_os = "android", derive(uniffi::Enum))]
pub enum Transport {
    /// TCP control/data transport.
    Tcp,
    /// UDP-QSP transport.
    UdpQsp,
}

/// Why the active transport changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_os = "android", derive(uniffi::Enum))]
pub enum TransportChangeReason {
    /// UDP-QSP idle timeout elapsed; fell back to TCP.
    IdleTimeout,
    /// UDP-QSP I/O error; fell back to TCP.
    UdpError,
    /// Server sent traffic on TCP while UDP-QSP was active.
    ServerInitiated,
    /// TCP-to-UDP upgrade commit barrier completed.
    UpgradeCommitted,
}

/// Typed client event emitted by the runtime.
///
/// Non-secret only: never carries keys, tokens, connection IDs, or packet
/// payloads. Detail strings are human-oriented diagnostics.
#[derive(Debug, Clone)]
#[cfg_attr(target_os = "android", derive(uniffi::Enum))]
pub enum ClientEventKind {
    // --- Session lifecycle -------------------------------------------------
    /// Native session is starting (before the runtime begins connecting).
    Starting,
    /// TUN device is ready and the runtime is about to connect.
    TunReady,
    /// Native session is stopping (tearing down).
    Stopping,
    /// Native session stopped cleanly.
    Stopped,
    /// Native session failed terminally.
    Error {
        /// Human-readable error detail.
        detail: String,
    },

    // --- TCP / auth --------------------------------------------------------
    /// Beginning connection attempt `attempt` (1 is the initial connect).
    Connecting {
        /// Reconnect attempt number, starting at 1.
        attempt: u64,
    },
    /// TCP + TLS handshake completed.
    ConnectedTcp {
        /// Server peer address, if known.
        peer: Option<String>,
    },
    /// Sending credentials and awaiting `AUTH_OK`.
    Authenticating,
    /// Server accepted authentication.
    Authenticated,

    // --- Reconnect loop ----------------------------------------------------
    /// Scheduled a reconnect attempt after a failure.
    ReconnectScheduled {
        /// The upcoming attempt number.
        attempt: u64,
        /// Backoff delay before the attempt, in milliseconds.
        delay_ms: u64,
    },
    /// A connect/auth attempt failed (recoverable; will retry or give up).
    ReconnectFailed {
        /// The attempt number that failed.
        attempt: u64,
        /// Human-readable failure detail.
        detail: String,
    },

    // --- UDP registration --------------------------------------------------
    /// Started QUIC DCID discovery.
    UdpDiscoveryStarted,
    /// QUIC DCID discovery failed.
    UdpDiscoveryFailed {
        /// Human-readable failure detail.
        detail: String,
    },
    /// Sent `REGISTER_CID`; awaiting server response.
    UdpRegisterStarted,
    /// `REGISTER_OK` received; UDP-QSP transport installed.
    UdpRegistered,
    /// UDP-QSP registration failed or was rejected.
    UdpRegisterFailed {
        /// Human-readable failure detail.
        detail: String,
    },

    // --- UDP upgrade -------------------------------------------------------
    /// Began a TCP-to-UDP-QSP upgrade attempt.
    UdpUpgradeStarted {
        /// Upgrade attempt identifier.
        upgrade_id: u64,
    },
    /// UDP path validated via probe/ack (about to send `UDP_READY`).
    UdpPathValidated {
        /// Upgrade attempt identifier.
        upgrade_id: u64,
    },
    /// Transport committed to UDP-QSP after the switch barrier.
    UdpSwitchCommitted {
        /// Upgrade attempt identifier.
        upgrade_id: u64,
    },

    // --- Transport ---------------------------------------------------------
    /// Active transport changed.
    TransportChanged {
        /// Previous transport.
        from: Transport,
        /// New transport.
        to: Transport,
        /// Why the transport changed.
        reason: TransportChangeReason,
    },

    // --- Network handoff ---------------------------------------------------
    /// Underlying network changed (Android reports a handoff).
    NetworkChanged {
        /// Human-readable detail.
        detail: String,
    },
    /// Started refreshing the UDP-QSP path on the current socket.
    UdpPathRefreshStarted,
    /// UDP-QSP path refresh succeeded (server peer updated).
    UdpPathRefreshSucceeded,
    /// UDP-QSP path refresh failed.
    UdpPathRefreshFailed {
        /// Human-readable failure detail.
        detail: String,
    },
}

/// Envelope delivered to a [`ClientObserver`].
///
/// Carries the native session handle, a monotonically increasing sequence
/// number (assigned by [`ObserverSink`]), the active data-path transport at
/// event time, and the typed event kind.
#[derive(Debug, Clone)]
#[cfg_attr(target_os = "android", derive(uniffi::Record))]
pub struct ClientEvent {
    /// Native session handle owning this event.
    pub handle: u64,
    /// Monotonic per-session sequence number for ordering / stale rejection.
    pub seq: u64,
    /// Active data-path transport carrying user packets when the event fired.
    ///
    /// This reflects where packets actually travel, not UDP-QSP *availability*:
    /// it stays `Tcp` during the upgrade handshake (`UdpRegistered`,
    /// `UdpUpgradeStarted`, `UdpPathValidated`) because data still flows over
    /// TCP until the switch barrier commits, then flips to `UdpQsp` via
    /// [`ClientEventKind::TransportChanged`].
    pub transport: Option<Transport>,
    /// Typed event payload.
    pub kind: ClientEventKind,
}

/// Receiver of typed client events.
///
/// Stored by value inside [`ObserverSink`], which shares it via its inner
/// `Arc`, so implementations need only be `Send + Sync` (not `Clone`). The
/// runtime calls [`ClientObserver::on_event`] from worker threads;
/// implementors are responsible for thread-safe delivery (e.g. marshalling to
/// a UI thread on Android).
pub trait ClientObserver: Send + Sync {
    /// Handle one typed client event.
    fn on_event(&self, event: &ClientEvent);
}

/// Observer that discards every event.
///
/// Used by the desktop services bundle, which has no foreign callback to
/// forward to.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl ClientObserver for NoopObserver {
    fn on_event(&self, _event: &ClientEvent) {}
}

const TRANSPORT_NONE: u8 = 0;
const TRANSPORT_TCP: u8 = 1;
const TRANSPORT_UDP_QSP: u8 = 2;

const fn transport_to_u8(transport: Option<Transport>) -> u8 {
    match transport {
        None => TRANSPORT_NONE,
        Some(Transport::Tcp) => TRANSPORT_TCP,
        Some(Transport::UdpQsp) => TRANSPORT_UDP_QSP,
    }
}

const fn transport_from_u8(value: u8) -> Option<Transport> {
    match value {
        TRANSPORT_TCP => Some(Transport::Tcp),
        TRANSPORT_UDP_QSP => Some(Transport::UdpQsp),
        _ => None,
    }
}

/// Per-session event emitter owning the handle, monotonic sequence counter,
/// tracked active transport, and the underlying [`ClientObserver`].
///
/// Generic over the observer type `O` so the runtime is monomorphized per
/// concrete observer (no `dyn` dispatch). Cheaply clonable (inner `Arc`);
/// clones share the same sequence counter and transport state so events
/// emitted across the connect flow and the session loop stay ordered and
/// consistent. The observer is shared via the inner `Arc`, so `O` need not be
/// `Clone`.
pub struct ObserverSink<O: ClientObserver> {
    inner: Arc<ObserverSinkInner<O>>,
}

struct ObserverSinkInner<O: ClientObserver> {
    handle: u64,
    seq: AtomicU64,
    transport: AtomicU8,
    observer: O,
}

impl<O: ClientObserver> Clone for ObserverSink<O> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<O: ClientObserver> ObserverSink<O> {
    /// Create a sink for session `handle` that forwards events to `observer`.
    #[must_use]
    pub fn new(handle: u64, observer: O) -> Self {
        Self {
            inner: Arc::new(ObserverSinkInner {
                handle,
                seq: AtomicU64::new(1),
                transport: AtomicU8::new(transport_to_u8(Some(Transport::Tcp))),
                observer,
            }),
        }
    }

    /// Native session handle carried by every emitted event.
    #[must_use]
    pub fn handle(&self) -> u64 {
        self.inner.handle
    }

    /// Record the current active transport so subsequent events report it.
    pub fn set_transport(&self, transport: Transport) {
        self.inner
            .transport
            .store(transport_to_u8(Some(transport)), Ordering::Relaxed);
    }

    /// Emit a typed event to the observer, assigning the next sequence number.
    pub fn emit(&self, kind: ClientEventKind) {
        let event = ClientEvent {
            handle: self.inner.handle,
            seq: self.inner.seq.fetch_add(1, Ordering::Relaxed),
            transport: transport_from_u8(self.inner.transport.load(Ordering::Relaxed)),
            kind,
        };
        self.inner.observer.on_event(&event);
    }
}

impl ObserverSink<NoopObserver> {
    /// Create a no-op sink (handle `0`, [`NoopObserver`]) for runtimes without
    /// a foreign callback, such as the desktop CLI.
    #[must_use]
    pub fn noop() -> Self {
        Self::new(0, NoopObserver)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Recording observer that snapshots every event it receives.
    ///
    /// `Clone` shares the underlying event buffer (via `Arc<Mutex<…>>`) so a
    /// test can hold a clone to read events while the sink owns another.
    #[derive(Default, Clone)]
    struct RecordingObserver {
        events: Arc<Mutex<Vec<ClientEvent>>>,
    }

    impl RecordingObserver {
        /// Clone out the recorded events so assertions don't hold a guard.
        fn snapshot(&self) -> Vec<ClientEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    impl ClientObserver for RecordingObserver {
        fn on_event(&self, event: &ClientEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    fn recording() -> (ObserverSink<RecordingObserver>, RecordingObserver) {
        let observer = RecordingObserver::default();
        let sink = ObserverSink::new(42, observer.clone());
        (sink, observer)
    }

    #[test]
    fn emit_assigns_monotonic_sequence() {
        let (sink, observer) = recording();
        sink.emit(ClientEventKind::Starting);
        sink.emit(ClientEventKind::TunReady);
        sink.emit(ClientEventKind::ConnectedTcp { peer: None });

        let events = observer.snapshot();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].seq, 2);
        assert_eq!(events[2].seq, 3);
        assert!(events[0].seq < events[1].seq);
        assert!(events[1].seq < events[2].seq);
    }

    #[test]
    fn emit_carries_handle_and_default_transport() {
        let (sink, observer) = recording();
        sink.emit(ClientEventKind::Starting);

        let event = &observer.snapshot()[0];
        assert_eq!(event.handle, 42);
        assert_eq!(event.transport, Some(Transport::Tcp));
        assert!(matches!(event.kind, ClientEventKind::Starting));
    }

    #[test]
    fn set_transport_is_reflected_in_subsequent_events() {
        let (sink, observer) = recording();
        sink.emit(ClientEventKind::ConnectedTcp { peer: None });
        sink.set_transport(Transport::UdpQsp);
        sink.emit(ClientEventKind::UdpRegistered);

        let events = observer.snapshot();
        assert_eq!(events[0].transport, Some(Transport::Tcp));
        assert_eq!(events[1].transport, Some(Transport::UdpQsp));
    }

    #[test]
    fn clones_share_sequence_counter() {
        let (sink, observer) = recording();
        let sink_clone = sink.clone();
        sink.emit(ClientEventKind::Starting);
        sink_clone.emit(ClientEventKind::TunReady);

        let events = observer.snapshot();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].seq, 2);
    }

    #[test]
    fn noop_sink_does_not_panic() {
        let sink = ObserverSink::noop();
        sink.emit(ClientEventKind::Error {
            detail: "ignored".to_string(),
        });
        assert_eq!(sink.handle(), 0);
    }

    #[test]
    fn event_kind_variants_carry_associated_data() {
        let (sink, observer) = recording();
        sink.emit(ClientEventKind::TransportChanged {
            from: Transport::Tcp,
            to: Transport::UdpQsp,
            reason: TransportChangeReason::UpgradeCommitted,
        });
        sink.emit(ClientEventKind::UdpUpgradeStarted { upgrade_id: 7 });
        sink.emit(ClientEventKind::ReconnectFailed {
            attempt: 3,
            detail: "timeout".to_string(),
        });

        let events = observer.snapshot();
        assert!(matches!(
            events[0].kind,
            ClientEventKind::TransportChanged {
                from: Transport::Tcp,
                to: Transport::UdpQsp,
                reason: TransportChangeReason::UpgradeCommitted,
            }
        ));
        assert!(matches!(
            events[1].kind,
            ClientEventKind::UdpUpgradeStarted { upgrade_id: 7 }
        ));
        assert!(matches!(
            events[2].kind,
            ClientEventKind::ReconnectFailed { attempt: 3, .. }
        ));
    }
}
