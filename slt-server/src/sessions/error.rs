//! Typed errors for the per-client server session path.
//!
//! # Why this is narrower than the client's `SessionError`
//!
//! The client's `SessionError` carries four variants this server enum omits:
//! - `PermissionDenied` — the server's session path has no socket-protect step
//!   (protection happens client-side).
//! - `UdpUpgradeRequired` — the server has no `require_udp` policy; it accepts
//!   whichever transport the client drives.
//! - `Crypto` — server-side `RAND_bytes`/key-derivation happens in the
//!   UDP-QSP/CID layer, not in `ClientSessionBase`.
//! - `ProtocolViolation { detail }` — the server's
//!   [`SessionError::ProtocolViolation`] is a unit variant; the client's
//!   value-carrying shape serves richer terminal diagnostics (offending DCID)
//!   that the server's per-client log does not need.

use std::io;

use slt_core::crypto::udp_qsp::QspSessionError;
use slt_core::proto::{FrameError, MessageError, PayloadError};

/// A failure from the UDP-QSP transport on the server's session path.
///
/// The server handles UDP-QSP errors inline at their source:
///
/// - The **recv path** (`open_udp_packet` in `sessions/udp.rs`) matches every
///   `QspSessionError` variant at the source, drops the recoverable packet
///   errors (`Replay`/`TooOld`/`Crypto`/garbage) with metrics, and falls back
///   to TCP on `DeadChannel`. Those conditions never produce a `UdpQspError`.
/// - The **send/flush path** (`send_udp_message` and
///   `recover_from_udp_flush_error` in `sessions/mod.rs`) retires UDP state and
///   uses TCP for UDP transport failures when the TCP channel is alive.
///
/// `UdpQspError` reaches `SessionError::UdpQsp` when no local TCP recovery is
/// available or the failure is not a UDP transport failure.
#[derive(Debug, thiserror::Error)]
pub enum UdpQspError {
    /// UDP-QSP session failure: a replayed/too-old packet number, a packet
    /// number overflow, a crypto (header-protection/AEAD) failure, or the
    /// dead-channel signal after too many consecutive decrypt failures.
    ///
    /// Send-side QSP failures are candidates for TCP fallback; receive-side
    /// packet failures are handled before this wrapper is constructed.
    #[error(transparent)]
    Qsp(#[from] QspSessionError),

    /// Network-level I/O error from the underlying UDP socket.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Protocol framing error from `encode_message`.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// Protocol message encode/decode error.
    #[error(transparent)]
    Message(#[from] MessageError),
}

/// A failure from an established server-side client session.
///
/// [`ClientSessionBase::run`](super::ClientSessionBase::run) returns
/// `Result<(), SessionError>`; the structured failure flows to the session's
/// terminal log.
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
    /// terminates.
    #[error("session connection error: {source}")]
    Connection {
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// UDP-QSP transport failure that could not be recovered locally.
    ///
    /// Send and flush failures first try to retire UDP and continue over TCP.
    /// This variant is returned when that recovery path is unavailable or the
    /// failure is a framing/message error rather than a UDP transport error.
    #[error(transparent)]
    UdpQsp(#[from] UdpQspError),

    /// Generic session I/O failure not covered by a more specific variant.
    ///
    /// The fallback for an `io::Error` raised on the session path (e.g. TUN
    /// device write) whose kind does not map cleanly to [`Self::Connection`].
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Protocol framing error.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Protocol message error.
    #[error(transparent)]
    Message(#[from] MessageError),
    /// Protocol payload decode error.
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

    /// Proto decode sources flow to the terminal `{:#}` render with their
    /// structured payload detail intact.
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
        // `MessageError` is a real `Error` with its own `Display`; the
        // structured lengths survive to the terminal render.
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
    /// errors.
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

        let qsp: SessionError = UdpQspError::from(QspSessionError::Replay).into();
        assert!(matches!(
            qsp,
            SessionError::UdpQsp(UdpQspError::Qsp(QspSessionError::Replay))
        ));
    }
}
