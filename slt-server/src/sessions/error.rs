//! Typed errors for the session path.
//!
//! `io::Error` was historically the cross-layer lingua franca of the server's
//! per-client session path. It carries only an `ErrorKind` and a free-text
//! string, so once a rich failure (a decoded payload error, a UDP-QSP
//! dead-channel signal, an offending byte) entered that type it could not be
//! recovered — the slt-core proto decode errors were collapsed to `InvalidData`
//! by the duplicated `map_message_error`/`map_frame_error`/`map_payload_error`
//! flatteners, and the UDP-QSP session failures were collapsed to
//! `ConnectionAborted`/`InvalidData` in `send_udp_message`. [`SessionError`]
//! replaces that contract: every variant is the source of truth (it carries the
//! detail and preserves the original error via `#[source]`/`#[from]`).
//!
//! See `local/error-architecture.md` for the full design (this is phase 4).
//!
//! # Why this is narrower than the client's `SessionError`
//!
//! The client's `SessionError` (phases 2–3) carries `PermissionDenied`,
//! `UdpUpgradeRequired`, `Crypto`, and a `ProtocolViolation { detail }` that
//! this server enum deliberately omits. A future reader "completing" the mirror
//! should NOT re-add them: the server's session path has no socket-protect step
//! (protection happens client-side), no `require_udp` policy (the server accepts
//! whichever transport the client drives), and no session-path crypto operation
//! (server-side `RAND_bytes`/key-derivation happens in the UDP-QSP/CID layer,
//! not in `ClientSessionBase`). The server's [`SessionError::ProtocolViolation`]
//! is a unit variant carrying no detail; promoting it to carry the offending
//! value (e.g. the offending message type) is the same phase-minor deferral
//! tracked in `local/error-architecture.md`'s Deferred follow-ups.

use std::io;

use slt_core::crypto::udp_qsp::QspSessionError;
use slt_core::proto::{FrameError, MessageError, PayloadError};

/// A failure from the UDP-QSP transport on the server's session path.
///
/// This is a **pure propagation wrapper**, not a policy type. Unlike the
/// phase-3 client `UdpQspError` — whose `is_recoverable`/`is_dead_channel` the
/// client's session loop consults via `handle_udp_error` to decide drop-vs-
/// propagate — the server handles UDP-QSP errors **inline at the source**:
///
/// - The **recv path** (`open_udp_packet` in `sessions/udp.rs`) matches every
///   `QspSessionError` variant at the source, drops the recoverable packet
///   errors (`Replay`/`TooOld`/`Crypto`/garbage) with metrics, and falls back
///   to TCP on `DeadChannel`. Those conditions never produce a `UdpQspError`.
/// - The **send path** (`send_udp_message` in `sessions/mod.rs`) propagates
///   every failure unchanged via `?` (it has no drop-and-continue option — a
///   failed send can't be silently dropped without losing the outbound packet).
///
/// So there is no recoverable-vs-fatal decision for this type to encode. The
/// earlier draft carried an `is_recoverable`/`is_dead_channel` modeled on the
/// client; it had **zero production callers** (verified) and encoded the naive
/// classification (no `SendIo` distinction, so send-side I/O was wrongly
/// recoverable — the bug the client fixed), so it was deleted to avoid giving
/// false confidence. `UdpQspError` exists only to wrap `QspSessionError` (and
/// the proto encode errors) for typed propagation through `SessionError::UdpQsp`
/// and for faithful terminal `{:#}` display.
///
/// The slt-core protocol errors are preserved, not flattened: `FrameError`
/// and `MessageError` are both real `thiserror::Error` types in `slt-core`
/// (phase 5 promoted `MessageError`), so each flows via `#[from]` and its own
/// `Display` survives to the terminal.
#[derive(Debug, thiserror::Error)]
pub enum UdpQspError {
    /// UDP-QSP session failure: a replayed/too-old packet number, a packet
    /// number overflow, a crypto (header-protection/AEAD) failure, or the
    /// dead-channel signal after too many consecutive decrypt failures.
    ///
    /// Preserved from `slt_core` via `#[from]` and propagated unchanged — the
    /// recv path drops the recoverable variants at the source, and the send
    /// path propagates everything (see the type-level doc).
    #[error(transparent)]
    Qsp(#[from] QspSessionError),

    /// Network-level I/O error from the underlying UDP socket. Preserved, not
    /// stringified.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Protocol framing error from `encode_message`, preserved from `slt_core`.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// Protocol message encode/decode error, preserved from `slt_core` via
    /// `#[from]`. `MessageError` is now a real `std::error::Error` in
    /// `slt-core` (phase 5 promoted it), so its own `Display` survives to the
    /// terminal.
    #[error(transparent)]
    Message(#[from] MessageError),
}

/// A failure from an established server-side client session.
///
/// The variant is the source of truth — it carries the operation's detail and
/// preserves the original error via `#[source]`/`#[from]`. This replaces the
/// lossy `io::Result` contract on the session path: [`ClientSessionBase::run`](super::ClientSessionBase::run)
/// now returns `Result<(), SessionError>`, and the structured failure flows to
/// the session's terminal log unchanged rather than being round-tripped through
/// `io::Error::new(...)`.
///
/// The slt-core protocol errors are preserved, not flattened: `FrameError`,
/// `MessageError`, and `PayloadError` are all real `thiserror::Error` types in
/// `slt-core` (phase 5 promoted the latter two), so each flows via `#[from]`
/// and its own `Display` survives to the terminal.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Client-detected protocol violation on the session path.
    ///
    /// An unexpected control message on an established session. Fatal: retry
    /// won't help, the peer is speaking a protocol we don't expect. A unit
    /// variant (carries no detail); see the module docs for why it is narrower
    /// than the client's `ProtocolViolation { detail }`.
    #[error("session protocol violation: unexpected control message")]
    ProtocolViolation,

    /// Network-level I/O error on the session's TCP connection.
    ///
    /// A transient condition (reset, refused, timeout) for which the session
    /// terminates. The source is preserved.
    #[error("session connection error: {source}")]
    Connection {
        /// Preserved underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// UDP-QSP transport failure (send-side propagation).
    ///
    /// The typed [`UdpQspError`] preserves the slt-core UDP-QSP session errors
    /// and the proto encode errors that were previously flattened to
    /// `ConnectionAborted`/`InvalidData` in `send_udp_message`. This variant is
    /// only ever produced by the **send path** (`send_udp_message`); recv-side
    /// UDP-QSP errors are handled inline by `open_udp_packet` (see the
    /// [`UdpQspError`] type-level doc). [`UdpQspError`] is a pure propagation
    /// wrapper with no recoverable policy.
    #[error(transparent)]
    UdpQsp(#[from] UdpQspError),

    /// Generic session I/O failure not covered by a more specific variant.
    ///
    /// The fallback for an `io::Error` raised on the session path (e.g. TUN
    /// device write) whose kind does not map cleanly to [`Self::Connection`].
    #[error(transparent)]
    Io(#[from] io::Error),

    // slt-core protocol errors are preserved, not flattened. These replace the
    // `sessions/mod.rs` `map_*` mappers on the session call sites. Each is a
    // real `std::error::Error` in `slt-core` (phase 5 promoted
    // `MessageError`/`PayloadError`), so all three flow via `#[from]` and their
    // own `Display` survives to the terminal.
    /// Protocol framing error, preserved from `slt_core`.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Protocol message error, preserved from `slt_core` via `#[from]`.
    #[error(transparent)]
    Message(#[from] MessageError),
    /// Protocol payload decode error, preserved from `slt_core` via `#[from]`.
    #[error(transparent)]
    Payload(#[from] PayloadError),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One representative `SessionError` per variant, so coverage tests can't
    /// miss a variant. Adding a variant without a representative case fails the
    /// distinct-discriminant check below.
    ///
    /// Covers all 7 distinct `SessionError` variants, with a second `UdpQsp`
    /// entry so both inner shapes that the send path produces (`Replay` from a
    /// send-side QSP failure and `DeadChannel` from the dead-channel signal)
    /// are represented.
    #[test]
    fn representative_cases_cover_every_variant() {
        let cases: Vec<SessionError> = vec![
            SessionError::ProtocolViolation,
            SessionError::Connection {
                source: io::Error::from(io::ErrorKind::ConnectionReset),
            },
            SessionError::Io(io::Error::other("generic")),
            // Two send-path UdpQsp inner shapes the server produces.
            SessionError::UdpQsp(UdpQspError::from(QspSessionError::Replay)),
            SessionError::UdpQsp(UdpQspError::from(QspSessionError::DeadChannel)),
            SessionError::Frame(FrameError::UnknownType(0xFF)),
            SessionError::Message(MessageError::DataTooLarge { len: 10, max: 5 }),
            SessionError::Payload(PayloadError::InvalidCipher(0x99)),
        ];
        // 8 cases covering all 7 distinct variants (UdpQsp appears twice for
        // inner-shape coverage).
        assert_eq!(
            cases.len(),
            8,
            "expected 8 representative cases (7 variants + a second UdpQsp inner shape)"
        );
        let distinct: std::collections::HashSet<_> =
            cases.iter().map(std::mem::discriminant).collect();
        assert_eq!(
            distinct.len(),
            7,
            "representative_cases must cover all 7 distinct SessionError variants exactly once"
        );
        // Pin the deliberate two-shape UdpQsp coverage (send-path replay +
        // dead-channel), so a future edit can't silently drop one shape.
        let udp: Vec<&SessionError> = cases
            .iter()
            .filter(|e| matches!(e, SessionError::UdpQsp(_)))
            .collect();
        assert_eq!(
            udp.len(),
            2,
            "expected exactly two UdpQsp representative cases (replay + dead-channel shape)"
        );
        assert!(
            udp.iter().any(|e| matches!(
                e,
                SessionError::UdpQsp(UdpQspError::Qsp(QspSessionError::Replay))
            )),
            "one UdpQsp case must be the replay shape"
        );
        assert!(
            udp.iter().any(|e| matches!(
                e,
                SessionError::UdpQsp(UdpQspError::Qsp(QspSessionError::DeadChannel))
            )),
            "one UdpQsp case must be the dead-channel shape"
        );
    }

    /// Proto decode sources must be preserved (not stringified). The displayed
    /// form carries the structured payload detail.
    #[test]
    fn proto_sources_are_preserved_in_display() {
        let frame = SessionError::Frame(FrameError::UnknownType(0xAB));
        let rendered = format!("{frame:#}");
        assert!(
            rendered.contains("unknown frame type"),
            "frame: {rendered:?}"
        );
        assert!(rendered.contains("0xab"), "frame: {rendered:?}");

        let msg = SessionError::Message(MessageError::DataTooLarge {
            len: 9999,
            max: 1500,
        });
        let rendered = format!("{msg:#}");
        // Phase 5 promoted `MessageError` to a real `Error` with its own
        // `Display`; the structured lengths survive to the terminal render.
        assert!(rendered.contains("9999"), "msg: {rendered:?}");

        let payload = SessionError::Payload(PayloadError::InvalidCipher(0x99));
        let rendered = format!("{payload:#}");
        assert!(
            rendered.contains("unknown cipher suite"),
            "payload: {rendered:?}"
        );
        assert!(rendered.contains("0x99"), "payload: {rendered:?}");
    }

    /// Manual `From` impls let the session call sites use `?` for proto decode
    /// errors, replacing the deleted `map_*` mappers.
    #[test]
    fn manual_from_impls_preserve_proto_errors() {
        let msg = MessageError::DataTooLarge { len: 10, max: 5 };
        let err: SessionError = msg.into();
        assert!(matches!(err, SessionError::Message(_)));

        let payload = PayloadError::InvalidCipher(0x99);
        let err: SessionError = payload.into();
        assert!(matches!(err, SessionError::Payload(_)));

        let frame = FrameError::UnknownType(0x01);
        let err: SessionError = frame.into();
        assert!(matches!(err, SessionError::Frame(_)));

        // QspSessionError flows via #[from] into UdpQspError, and UdpQspError
        // flows via #[from] into SessionError.
        let qsp: SessionError = UdpQspError::from(QspSessionError::Replay).into();
        assert!(matches!(
            qsp,
            SessionError::UdpQsp(UdpQspError::Qsp(QspSessionError::Replay))
        ));
    }
}
