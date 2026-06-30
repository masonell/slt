//! Typed errors for the established-session path.
//!
//! Where [`crate::error::ConnectError`] is the typed error for the connect/auth
//! sequence, [`SessionError`] is its counterpart for the established-session
//! path: TCP/UDP message handling, payload decoding, and the UDP-upgrade FSM.
//!
//! [`SessionExit`](super::SessionExit) remains the control-flow reason used by
//! the runtime to decide reconnect policy (it stays `Clone + Copy`); a
//! [`SessionError`] carries the rich failure that produced an error exit.

use std::borrow::Cow;
use std::io;

use boring::error::ErrorStack;
use slt_core::crypto::udp_qsp::QspCryptoError;
use slt_core::proto::{FrameError, MessageError, PayloadError};
use slt_core::transport::tcp::TcpWriteError;

use crate::transport::udp_qsp::UdpQspError;

/// A failure from an established session.
///
/// [`Self::exit`] is a derived projection onto the reconnect-policy enum
/// [`SessionExit`](super::SessionExit); like [`crate::error::ConnectError::stage`]
/// it can never disagree with the variant because it is derived from it.
///
/// The UDP-QSP transport failure flows via [`Self::UdpQsp`]: the typed
/// [`UdpQspError`] carries its own recoverable-vs-fatal classification via
/// [`UdpQspError::is_recoverable`] / [`UdpQspError::is_dead_channel`].
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Client-detected protocol violation on the session path.
    ///
    /// An unexpected control message on an established session, a
    /// `register_ok` DCID mismatch, or a missing pre-built UDP-QSP session —
    /// conditions the client detects locally and that retry will not fix.
    /// Distinct from a proto decode failure ([`Self::Frame`]/[`Self::Message`]/
    /// [`Self::Payload`]) and from a server-sent rejection.
    ///
    /// `detail` is a [`Cow<'static, str>`] so string-literal construction sites
    /// stay zero-alloc ([`Cow::Borrowed`]) while the value-carrying sites (e.g.
    /// the `register_ok` DCID-mismatch, which formats the offending value into
    /// the detail) use [`Cow::Owned`]. This keeps the offending value in the
    /// terminal `{:#}` render rather than discarding it.
    #[error("session protocol violation: {detail}")]
    ProtocolViolation {
        /// Stage-specific description of the violation, possibly carrying the
        /// offending value (e.g. a mismatched DCID).
        detail: Cow<'static, str>,
    },

    /// Local OS or network policy denied an operation (e.g. socket protect).
    ///
    /// Fatal: a capability/permission problem won't self-heal across a retry.
    ///
    /// No session-path producer constructs this today (socket protection
    /// happens on the connect path, owned by [`crate::error::ConnectError`]); it
    /// is reserved for a future UDP-protect denial on the session path.
    #[error("session operation denied: {source}")]
    PermissionDenied {
        /// Underlying I/O error from the denied operation.
        #[source]
        source: io::Error,
    },

    /// A required UDP upgrade failed (`require_udp` policy).
    ///
    /// The session exited because the mandatory transport could not be
    /// established. Distinct from a transient connection error (which retries).
    #[error("required udp upgrade failed")]
    UdpUpgradeRequired,

    /// Network-level I/O error on the session's TCP connection.
    ///
    /// A transient condition (reset, refused, timeout) for which the runtime
    /// reconnects.
    #[error("session connection error: {source}")]
    Connection {
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Generic session I/O failure not covered by a more specific variant.
    ///
    /// The fallback for an `io::Error` raised on the session path whose kind
    /// does not map cleanly to [`Self::PermissionDenied`] or
    /// [`Self::Connection`]; primarily reached from the TCP path, which still
    /// returns `io::Result` from `slt_core::transport::TcpChannel`.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// UDP-QSP transport failure.
    ///
    /// The typed [`UdpQspError`] preserves the slt-core UDP-QSP session/crypto
    /// errors and the proto encode errors. The recoverable-vs-fatal decision
    /// lives on the inner type ([`UdpQspError::is_recoverable`] /
    /// [`UdpQspError::is_dead_channel`]): recoverable failures (replay,
    /// too-old, single crypto failure, proto decode, partial packet, transient
    /// socket I/O) are dropped by the session and keep the UDP path alive; the
    /// dead-channel signal and packet-number overflow propagate (see
    /// [`UdpQspError::is_recoverable`] for the policy).
    #[error(transparent)]
    UdpQsp(#[from] UdpQspError),

    /// Cryptographic operation failure on the session path (e.g. `RAND_bytes`
    /// during UDP-QSP registration key generation). Fatal: local crypto state.
    #[error("session crypto error: {0}")]
    Crypto(#[from] ErrorStack),

    /// UDP-QSP key derivation failed at session-setup time (`UdpQspKeys::new`
    /// during `REGISTER_CID` preparation). Preserves the typed
    /// [`QspCryptoError`] so the cause survives.
    ///
    /// Distinct from [`Self::Crypto`] (which carries the boring `ErrorStack`
    /// from `RAND_bytes`): `QspCryptoError` is the slt-core UDP-QSP crypto
    /// error for cipher/key-material construction, not the OS-level RNG.
    /// Fatal: local key state, retry won't help.
    #[error("udp-qsp key derivation failed: {0}")]
    UdpQspKeys(#[from] QspCryptoError),

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

impl From<TcpWriteError> for SessionError {
    /// Thread `TcpChannel::write_message`'s typed write error into the session
    /// error.
    ///
    /// - **`Io` → [`SessionError::Io`]**: a network-level write failure on the
    ///   session path reconnects (`exit() == ConnectionError`).
    /// - **`Frame` → [`SessionError::Frame`]**: fatal
    ///   (`exit() == ProtocolError`). A `FrameError` from encoding a
    ///   locally-constructed `Message` is a logic/config bug (an unknown
    ///   message type, or a payload oversized despite the TUN-layer
    ///   pre-check) — reconnecting won't fix it, so routing it to the typed
    ///   `Frame` variant surfaces it as fatal.
    fn from(err: TcpWriteError) -> Self {
        match err {
            TcpWriteError::Frame(frame) => Self::Frame(frame),
            TcpWriteError::Io(io) => Self::Io(io),
        }
    }
}

impl SessionError {
    /// Reconnect/fatal policy projection onto [`SessionExit`](super::SessionExit).
    ///
    /// Derived from the variant via a `match`, so it can never disagree with
    /// the variant. The typed error is built at the failure site, and the
    /// control-flow reason is derived from it here.
    ///
    /// Mapping:
    /// - [`Self::ProtocolViolation`] / proto errors ([`Self::Frame`]/
    ///   [`Self::Message`]/[`Self::Payload`]) / [`Self::Crypto`] /
    ///   [`Self::UdpQspKeys`] → `ProtocolError` (fatal).
    /// - [`Self::PermissionDenied`] → `PermissionDenied` (fatal).
    /// - [`Self::UdpUpgradeRequired`] → `UdpUpgradeRequired` (fatal).
    /// - [`Self::Connection`] / generic [`Self::Io`] / [`Self::UdpQsp`] →
    ///   `ConnectionError` (reconnect). [`Self::UdpQsp`] buckets here because
    ///   the recoverable-vs-fatal *transport* decision (drop & continue vs.
    ///   dead-channel) is made before reaching `exit()`: a dropped recoverable
    ///   failure never produces a `SessionError` at all, and the dead-channel
    ///   signal routes through `exit()` as a reconnect.
    ///
    /// Proto decode failures all map to `ProtocolError` (fatal). Per-variant
    /// exit policy may be revisited separately if warranted.
    #[must_use]
    pub const fn exit(&self) -> super::SessionExit {
        match self {
            Self::ProtocolViolation { .. }
            | Self::Frame(_)
            | Self::Message(_)
            | Self::Payload(_)
            | Self::Crypto(_)
            | Self::UdpQspKeys(_) => super::SessionExit::ProtocolError,
            Self::PermissionDenied { .. } => super::SessionExit::PermissionDenied,
            Self::UdpUpgradeRequired => super::SessionExit::UdpUpgradeRequired,
            Self::Connection { .. } | Self::Io(_) | Self::UdpQsp(_) => {
                super::SessionExit::ConnectionError
            }
        }
    }

    /// Whether this is the UDP-QSP dead-channel signal — the one fatal
    /// non-I/O condition on the UDP-QSP transport path.
    ///
    /// The typed [`UdpQspError`] carries the classification directly. Returns
    /// `false` for every non-`UdpQsp` variant and for non-dead-channel `UdpQsp`
    /// failures.
    #[must_use]
    pub const fn is_udp_qsp_dead_channel(&self) -> bool {
        match self {
            Self::UdpQsp(err) => err.is_dead_channel(),
            _ => false,
        }
    }

    /// Whether this is a recoverable UDP-QSP transport failure (drop &
    /// continue, keeping the UDP path alive).
    ///
    /// Returns `false` for every non-`UdpQsp` variant, since those are typed
    /// session/proto errors that propagate (the UDP transport's recoverable
    /// classification does not apply to them).
    #[must_use]
    pub fn is_udp_qsp_recoverable(&self) -> bool {
        match self {
            Self::UdpQsp(err) => err.is_recoverable(),
            _ => false,
        }
    }

    /// Whether this is a UDP-path transport condition eligible for the
    /// `handle_udp_error` recover/fallback decision (rather than a typed
    /// session/proto error that propagates).
    ///
    /// True for [`Self::UdpQsp`] (the typed UDP-QSP transport failure carrying
    /// its own recoverable/dead-channel classification) and for [`Self::Io`]
    /// when reached on the UDP path (a raw socket I/O error from
    /// `udp.flush()`). False for the typed protocol/violation/crypto variants,
    /// which the UDP write/flush handlers propagate unchanged.
    #[must_use]
    pub const fn is_udp_path_transport_error(&self) -> bool {
        matches!(self, Self::UdpQsp(_) | Self::Io(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::session::SessionExit;

    /// Pins both arms of `From<TcpWriteError>` so the routing cannot silently
    /// regress.
    #[test]
    fn from_tcp_write_error_routes_frame_fatal_and_io_reconnect() {
        use slt_core::transport::tcp::TcpWriteError;

        let frame: SessionError = TcpWriteError::Frame(FrameError::UnknownType(1)).into();
        assert!(
            matches!(frame, SessionError::Frame(_)),
            "Frame arm must route to SessionError::Frame, got {frame:?}"
        );
        assert_eq!(
            frame.exit(),
            SessionExit::ProtocolError,
            "SessionError::Frame from TcpWriteError must be fatal (ProtocolError)"
        );

        let io: SessionError =
            TcpWriteError::Io(io::Error::from(io::ErrorKind::ConnectionReset)).into();
        assert!(
            matches!(io, SessionError::Io(_)),
            "Io arm must route to SessionError::Io, got {io:?}"
        );
        assert_eq!(
            io.exit(),
            SessionExit::ConnectionError,
            "SessionError::Io from TcpWriteError must reconnect (ConnectionError)"
        );
    }

    /// One representative `SessionError` per variant, so coverage tests can't
    /// miss a variant. The asserted length is the number of `SessionError`
    /// variants; adding a variant without a representative case fails loudly.
    fn representative_cases() -> Vec<SessionError> {
        let cases: Vec<SessionError> = vec![
            SessionError::ProtocolViolation {
                detail: "unexpected control message".into(),
            },
            SessionError::PermissionDenied {
                source: io::Error::from(io::ErrorKind::PermissionDenied),
            },
            SessionError::UdpUpgradeRequired,
            SessionError::Connection {
                source: io::Error::from(io::ErrorKind::ConnectionReset),
            },
            SessionError::Io(io::Error::other("generic")),
            // Recoverable UDP-QSP shape (replay) and fatal shape (dead channel).
            SessionError::UdpQsp(UdpQspError::from(
                slt_core::crypto::udp_qsp::QspSessionError::Replay,
            )),
            SessionError::UdpQsp(UdpQspError::from(
                slt_core::crypto::udp_qsp::QspSessionError::DeadChannel,
            )),
            SessionError::Crypto(ErrorStack::internal_error(io::Error::other("rand"))),
            SessionError::UdpQspKeys(slt_core::crypto::udp_qsp::QspCryptoError::CryptoFail),
            SessionError::Frame(FrameError::UnknownType(0xFF)),
            SessionError::Message(MessageError::DataTooLarge { len: 10, max: 5 }),
            SessionError::Payload(PayloadError::InvalidCipher(0x99)),
        ];
        // 12 cases covering all 11 distinct SessionError variants, with a
        // second `UdpQsp` entry (the variant has two behaviorally-distinct
        // inner shapes that `is_udp_qsp_recoverable()` / `is_udp_qsp_dead_channel()`
        // distinguish): one recoverable shape (Replay) and one fatal shape
        // (DeadChannel). Adding a variant without a representative case fails
        // the distinct-discriminant check below.
        assert_eq!(
            cases.len(),
            12,
            "representative_cases must contain exactly 12 cases \
             (11 variants + a second UdpQsp inner shape); update when adding a variant"
        );
        // Distinct variants via a HashSet of Discriminant values (a `Vec::dedup`
        // would only catch *adjacent* duplicates and so could miss a misplaced
        // case). 11 = the number of SessionError variants.
        let distinct: std::collections::HashSet<_> =
            cases.iter().map(std::mem::discriminant).collect();
        assert_eq!(
            distinct.len(),
            11,
            "representative_cases must cover all 11 distinct SessionError variants exactly once"
        );
        // Pin the deliberate second `UdpQsp` case so the intent is explicit:
        // the two entries must cover both the recoverable and the fatal
        // transport shapes.
        let udp: Vec<&SessionError> = cases
            .iter()
            .filter(|e| matches!(e, SessionError::UdpQsp(_)))
            .collect();
        assert_eq!(
            udp.len(),
            2,
            "expected exactly two UdpQsp representative cases (recoverable + fatal shape)"
        );
        assert!(
            udp.iter().any(|e| e.is_udp_qsp_recoverable()),
            "one UdpQsp case must be the recoverable shape"
        );
        assert!(
            udp.iter().any(|e| e.is_udp_qsp_dead_channel()),
            "one UdpQsp case must be the fatal (dead-channel) shape"
        );
        cases
    }

    /// Every variant must project to one of the known `SessionExit` reasons.
    /// Pins the `exit()` mapping so a careless edit is caught loudly.
    #[test]
    fn exit_is_defined_for_every_variant() {
        for err in representative_cases() {
            let exit = err.exit();
            assert!(
                matches!(
                    exit,
                    SessionExit::ProtocolError
                        | SessionExit::PermissionDenied
                        | SessionExit::UdpUpgradeRequired
                        | SessionExit::ConnectionError
                ),
                "variant {err:?} projected to unexpected exit {exit:?}"
            );
        }
    }

    /// The fatal-vs-reconnect projection, pinned per variant. Guardrail against
    /// re-introducing `ErrorKind`-based guesswork on the session path.
    #[test]
    fn exit_matches_policy_table() {
        // Fatal exits.
        assert_eq!(
            SessionError::ProtocolViolation { detail: "x".into() }.exit(),
            SessionExit::ProtocolError
        );
        assert_eq!(
            SessionError::PermissionDenied {
                source: io::Error::from(io::ErrorKind::PermissionDenied)
            }
            .exit(),
            SessionExit::PermissionDenied
        );
        assert_eq!(
            SessionError::UdpUpgradeRequired.exit(),
            SessionExit::UdpUpgradeRequired
        );
        assert_eq!(
            SessionError::Frame(FrameError::UnknownType(1)).exit(),
            SessionExit::ProtocolError
        );
        assert_eq!(
            SessionError::Message(MessageError::DataTooLarge { len: 9, max: 1 }).exit(),
            SessionExit::ProtocolError
        );
        assert_eq!(
            SessionError::Crypto(ErrorStack::internal_error(io::Error::other("x"))).exit(),
            SessionExit::ProtocolError
        );
        // UdpQspKeys (construction-time key derivation failure) is fatal: local
        // key state, retry won't help.
        assert_eq!(
            SessionError::UdpQspKeys(slt_core::crypto::udp_qsp::QspCryptoError::CryptoFail).exit(),
            SessionExit::ProtocolError
        );

        // Reconnect exits.
        assert_eq!(
            SessionError::Connection {
                source: io::Error::from(io::ErrorKind::ConnectionReset)
            }
            .exit(),
            SessionExit::ConnectionError
        );
        assert_eq!(
            SessionError::Io(io::Error::other("x")).exit(),
            SessionExit::ConnectionError
        );
        // PayloadError buckets under ProtocolError (fatal). `PayloadError` is
        // a real `Error` type; per-variant exit policy is not revisited here.
        assert_eq!(
            SessionError::Payload(PayloadError::InvalidCipher(0x99)).exit(),
            SessionExit::ProtocolError
        );
        // UdpQsp buckets under ConnectionError (reconnect): see exit() docs for
        // why the recoverable-vs-fatal transport decision is made earlier.
        assert_eq!(
            SessionError::UdpQsp(UdpQspError::from(
                slt_core::crypto::udp_qsp::QspSessionError::DeadChannel
            ))
            .exit(),
            SessionExit::ConnectionError
        );
    }

    /// A protocol error must be distinct from a connection error: classification
    /// is by stage, not by `ErrorKind`.
    #[test]
    fn protocol_and_connection_errors_are_distinct() {
        assert_ne!(
            SessionError::ProtocolViolation { detail: "x".into() }.exit(),
            SessionError::Connection {
                source: io::Error::other("net")
            }
            .exit()
        );
    }

    /// The typed UDP-QSP recoverable/dead-channel projections must classify
    /// each `UdpQspError` shape correctly. Also pins
    /// [`SessionError::is_udp_path_transport_error`] — the gate used at the
    /// UDP write / flush / tun-packet / upgrade-probe call sites to separate
    /// "UDP-path transport condition -> fall back" from "typed session error
    /// -> propagate".
    #[test]
    fn udp_qsp_projections_classify_each_shape() {
        use slt_core::crypto::udp_qsp::{QspCryptoError, QspSessionError};

        // Recoverable.
        let recoverable: SessionError = UdpQspError::from(QspSessionError::Replay).into();
        assert!(recoverable.is_udp_qsp_recoverable());
        assert!(!recoverable.is_udp_qsp_dead_channel());
        let too_old: SessionError = UdpQspError::from(QspSessionError::TooOld).into();
        assert!(too_old.is_udp_qsp_recoverable());
        let crypto: SessionError =
            UdpQspError::from(QspSessionError::Crypto(QspCryptoError::CryptoFail)).into();
        assert!(crypto.is_udp_qsp_recoverable());

        // Fatal (dead channel): peer keys diverged beyond recovery.
        let dead: SessionError = UdpQspError::from(QspSessionError::DeadChannel).into();
        assert!(!dead.is_udp_qsp_recoverable());
        assert!(dead.is_udp_qsp_dead_channel());

        // Fatal (packet-number overflow): TX pn space exhausted, session cannot
        // send again on this UDP path — propagates to TCP fallback, not a drop.
        // Not the dead-channel signal.
        let overflow: SessionError =
            UdpQspError::from(QspSessionError::PacketNumberOverflow).into();
        assert!(!overflow.is_udp_qsp_recoverable());
        assert!(!overflow.is_udp_qsp_dead_channel());

        // Fatal (send-side I/O): a send failure is never droppable — it falls
        // back to TCP (or closes), not dropped like a recv-side transient.
        let send_io: SessionError = UdpQspError::SendIo {
            source: io::Error::from(io::ErrorKind::TimedOut),
        }
        .into();
        assert!(!send_io.is_udp_qsp_recoverable());
        assert!(!send_io.is_udp_qsp_dead_channel());
        assert!(send_io.is_udp_path_transport_error());

        // Non-UdpQsp variants never report as UDP-QSP transport conditions.
        let proto = SessionError::Payload(PayloadError::InvalidCipher(0x99));
        assert!(!proto.is_udp_qsp_recoverable());
        assert!(!proto.is_udp_qsp_dead_channel());

        // `is_udp_path_transport_error` is the gate for the UDP write /
        // flush / tun-packet / upgrade-probe fallback decision. True for the
        // UDP-QSP typed failure and for a raw socket `io::Error` (UDP flush);
        // false for typed proto/violation/crypto conditions, which propagate.
        assert!(recoverable.is_udp_path_transport_error());
        assert!(dead.is_udp_path_transport_error());
        assert!(overflow.is_udp_path_transport_error());
        assert!(
            SessionError::from(io::Error::other("udp flush socket I/O"))
                .is_udp_path_transport_error()
        );
        // Typed non-transport conditions propagate (NOT UDP-path transport
        // conditions eligible for the fallback decision).
        assert!(!proto.is_udp_path_transport_error());
        assert!(
            !SessionError::ProtocolViolation { detail: "x".into() }.is_udp_path_transport_error()
        );
        assert!(
            !SessionError::Crypto(ErrorStack::internal_error(io::Error::other("rand")))
                .is_udp_path_transport_error()
        );
        assert!(
            !SessionError::UdpQspKeys(slt_core::crypto::udp_qsp::QspCryptoError::CryptoFail)
                .is_udp_path_transport_error()
        );
        assert!(!SessionError::Frame(FrameError::UnknownType(0x01)).is_udp_path_transport_error());
    }

    /// The proto decode sources flow to the terminal `{:#}` render with their
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
        // `MessageError` is a real `Error` with its own `Display`, so the
        // structured values (lengths) survive to the terminal render rather
        // than a `Debug`-format variant name.
        assert!(
            rendered.contains("data payload length"),
            "msg: {rendered:?}"
        );
        assert!(rendered.contains("9999"), "msg: {rendered:?}");
        assert!(rendered.contains("1500"), "msg: {rendered:?}");

        let payload = SessionError::Payload(PayloadError::InvalidCipher(0x99));
        let rendered = format!("{payload:#}");
        assert!(
            rendered.contains("unknown cipher suite"),
            "payload: {rendered:?}"
        );
        assert!(rendered.contains("0x99"), "payload: {rendered:?}");
    }

    /// The terminal renders useful, stage-specific detail (peer-relevant
    /// values, the offending byte, etc.).
    #[test]
    fn terminal_renders_useful_detail() {
        let err = SessionError::Connection {
            source: io::Error::other("connection reset by peer"),
        };
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("session connection error"),
            "connection detail missing stage: {rendered:?}"
        );
        assert!(
            rendered.contains("connection reset"),
            "connection detail missing source: {rendered:?}"
        );

        let err = SessionError::PermissionDenied {
            source: io::Error::other("protectSocket returned false"),
        };
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("denied"),
            "permission detail missing stage: {rendered:?}"
        );
        assert!(
            rendered.contains("protectSocket"),
            "permission detail missing source: {rendered:?}"
        );
    }

    /// Composed parity: each `SessionError`'s effective runtime action —
    /// obtained by composing `SessionError::exit()` (tested by
    /// `exit_matches_policy_table`) with `handle_session_exit` (the
    /// `SessionExit -> SessionAction` mapping in `runtime/mod.rs`) — must match
    /// the intended fatal/reconnect policy.
    ///
    /// Without this, the two tables could drift independently: e.g.
    /// `SessionError::exit()` could classify a variant as `ConnectionError`
    /// while `handle_session_exit` quietly treated `ConnectionError` as fatal,
    /// and neither half-test would notice. This test pins the composition.
    #[test]
    fn session_error_effective_action_matches_policy() {
        use tokio_util::sync::CancellationToken;

        use super::super::super::{SessionAction, handle_session_exit};
        use super::super::SessionOutcome;

        let cancel = CancellationToken::new();
        // Token is NOT cancelled — exercises the real exit→action mapping.
        for err in representative_cases() {
            // Capture the discriminant + exit reason before `err` is moved into
            // `SessionOutcome::from_error`, for clear failure messages.
            let disc = std::mem::discriminant(&err);
            let exit = err.exit();
            let outcome = SessionOutcome::from_error(err);
            let action = handle_session_exit(outcome, &cancel);
            let is_fatal = matches!(action, SessionAction::Fatal(_));
            let is_reconnect = matches!(action, SessionAction::Reconnect);

            // Derive the expected policy from the exit reason, the same source
            // of truth `handle_session_exit` uses. Fatal exits: ProtocolError,
            // PermissionDenied, UdpUpgradeRequired. Reconnect exits:
            // ConnectionError. (Break/ReconnectNow exits are not reachable from
            // `from_error`, which only produces the four error exits.)
            let expected_fatal = matches!(
                exit,
                SessionExit::ProtocolError
                    | SessionExit::PermissionDenied
                    | SessionExit::UdpUpgradeRequired
            );
            let expected_reconnect = matches!(exit, SessionExit::ConnectionError);

            assert!(
                expected_fatal != expected_reconnect,
                "test harness bug: exit {exit:?} is neither fatal nor reconnect"
            );
            assert_eq!(
                is_fatal, expected_fatal,
                "variant {disc:?} fatal-policy mismatch (is_fatal={is_fatal}, exit={exit:?})"
            );
            assert_eq!(
                is_reconnect, expected_reconnect,
                "variant {disc:?} reconnect-policy mismatch \
                 (is_reconnect={is_reconnect}, exit={exit:?})"
            );
        }
    }

    /// Composed routing for `UdpQsp(Qsp(PacketNumberOverflow))`, pinned
    /// directly. `representative_cases()` covers only the `Replay` (recoverable)
    /// and `DeadChannel` (fatal) `UdpQsp` shapes by design — overflow is a
    /// distinct shape whose doc/code drift went uncaught in earlier review, so
    /// it gets a dedicated assertion here rather than disturbing the
    /// `representative_cases` invariant.
    ///
    /// Overflow is a UDP-path transport error that is fatal (non-recoverable)
    /// and NOT the dead-channel signal — i.e. at the session layer it reaches
    /// the `handle_udp_error` branch that does TCP fallback (when TCP is alive)
    /// or session close (otherwise).
    /// The session-level exit (`ConnectionError`) reconnects only once the
    /// session re-establishes; the overflow itself is not an immediate
    /// reconnect trigger.
    #[test]
    fn overflow_routes_to_non_dead_channel_fatal_transport_path() {
        use slt_core::crypto::udp_qsp::QspSessionError;

        let overflow: SessionError =
            UdpQspError::from(QspSessionError::PacketNumberOverflow).into();

        // It is a UDP-path transport condition (eligible for the fallback
        // decision at the UDP write/flush/tun/probe sites).
        assert!(
            overflow.is_udp_path_transport_error(),
            "overflow must be a UDP-path transport error"
        );
        // It is fatal (non-recoverable): NOT dropped & continued.
        assert!(
            !overflow.is_udp_qsp_recoverable(),
            "overflow must NOT be recoverable (would silently drop packets)"
        );
        // It is distinct from the dead-channel signal — the other fatal
        // non-recoverable UDP-QSP shape — so the session's
        // `is_udp_qsp_dead_channel()` short-circuit does not fire for it.
        assert!(
            !overflow.is_udp_qsp_dead_channel(),
            "overflow must not look like the dead-channel signal"
        );
        // Composed exit: UdpQsp buckets under ConnectionError (reconnect),
        // consistent with the other UdpQsp shapes — see `exit()` docs.
        assert_eq!(overflow.exit(), SessionExit::ConnectionError);
    }

    /// `QspCryptoError` from `UdpQspKeys::new` (the construction-time key
    /// derivation in `prepare_udp_qsp_registration`) routes to
    /// [`SessionError::UdpQspKeys`]; its `Display` survives to the terminal
    /// `{:#}` render, and the variant is fatal.
    #[test]
    fn udp_qsp_keys_error_preserves_qsp_crypto_error() {
        use slt_core::crypto::udp_qsp::QspCryptoError;

        for err in [
            QspCryptoError::UnsupportedCipher,
            QspCryptoError::CryptoFail,
            QspCryptoError::InvalidHeader,
        ] {
            let rendered_err: SessionError = err.into();
            assert!(
                matches!(rendered_err, SessionError::UdpQspKeys(_)),
                "QspCryptoError must route to UdpQspKeys, got {rendered_err:?}"
            );
            assert_eq!(
                rendered_err.exit(),
                SessionExit::ProtocolError,
                "UdpQspKeys must be fatal"
            );
            // The typed cause survives in the render.
            let rendered = format!("{rendered_err:#}");
            let cause = format!("{err}");
            assert!(
                rendered.contains(&cause),
                "QspCryptoError cause missing from render: {rendered:?}"
            );
            assert!(
                rendered.contains("udp-qsp key derivation failed"),
                "missing stage framing: {rendered:?}"
            );
        }
    }
}
