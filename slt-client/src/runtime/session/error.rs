//! Typed errors for the session path.
//!
//! Where [`crate::error::ConnectError`] is the typed error for the connect/auth
//! sequence, [`SessionError`] is its counterpart for the established-session
//! path: TCP/UDP message handling, payload decoding, and the UDP-upgrade FSM.
//! It replaces the lossy `classify_error(io::Error) -> SessionExit` derivation,
//! which guessed a failure's meaning from `io::ErrorKind` at a distance and
//! discarded the structured detail (decoded payload error, offending byte,
//! peer address) that existed at the failure site.
//!
//! [`SessionExit`](super::SessionExit) remains the control-flow reason used by
//! the runtime to decide reconnect policy (it stays `Clone + Copy`); a
//! [`SessionError`] carries the rich, source-preserving failure that produced
//! an error exit, and flows to the terminal unchanged rather than being
//! round-tripped through `io::Error::new(...)`.
//!
//! See `local/error-architecture.md` for the full design (phases 2 and 3).

use std::io;

use boring::error::ErrorStack;
use slt_core::proto::{FrameError, MessageError, PayloadError};

use crate::transport::udp_qsp::UdpQspError;

/// A failure from an established session.
///
/// The variant is the source of truth — it carries the operation's detail and
/// preserves the original error via `#[source]`/`#[from]`. [`Self::exit`] is a
/// derived projection onto the reconnect-policy enum
/// [`SessionExit`](super::SessionExit); like [`crate::error::ConnectError::stage`]
/// it can never disagree with the variant because it is derived from it.
///
/// The slt-core protocol errors are preserved, not flattened: `FrameError`,
/// `MessageError`, and `PayloadError` are all real `thiserror::Error` types in
/// `slt-core` (phase 5 promoted the latter two), so each flows via `#[from]`
/// and its own `Display` survives to the terminal — mirroring the phase-1
/// [`crate::error::ConnectError`] handling. (Before phase 5, `MessageError`/
/// `PayloadError` were plain `Copy` enums stored by value with a `Debug`-format
/// `Display`; phase 5 made them real `Error` types and switched these variants
/// to `#[from]`.)
///
/// The UDP-QSP transport failure flows via [`Self::UdpQsp`] (phase 3): the typed
/// [`UdpQspError`] preserves the `slt-core` `QspSessionError`/`QspCryptoError`
/// and the proto encode errors, and carries its own recoverable-vs-fatal
/// classification via [`UdpQspError::is_recoverable`] / [`UdpQspError::is_dead_channel`].
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
    // TODO(phase-minor): carry the offending value (e.g. the mismatched DCID)
    // rather than only a `&'static str` detail, so the terminal report can
    // surface it. Out of scope for the phase-2 pass.
    #[error("session protocol violation: {detail}")]
    ProtocolViolation {
        /// Short, stage-specific description of the violation.
        detail: &'static str,
    },

    /// Local OS or network policy denied an operation (e.g. socket protect).
    ///
    /// Preserves the underlying I/O error rather than stringifying it. Fatal:
    /// a capability/permission problem won't self-heal across a retry.
    ///
    /// No session-path producer constructs this today (socket protection
    /// happens on the connect path, owned by phase 1's `ConnectError`); it is
    /// reserved for a future UDP-protect denial on the session path. Not a
    /// regression — the old `classify_error` `PermissionDenied` branch was
    /// likewise unreachable on the session path.
    #[error("session operation denied: {source}")]
    PermissionDenied {
        /// Preserved underlying I/O error from the denied operation.
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
    /// reconnects. The source is preserved.
    #[error("session connection error: {source}")]
    Connection {
        /// Preserved underlying I/O error.
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

    /// UDP-QSP transport failure (phase 3).
    ///
    /// The typed [`UdpQspError`] preserves the slt-core UDP-QSP session/crypto
    /// errors and the proto encode errors that were previously flattened to
    /// `io::ErrorKind::InvalidData` by the deleted `map_qsp_error`. The
    /// recoverable-vs-fatal decision lives on the inner type
    /// ([`UdpQspError::is_recoverable`] / [`UdpQspError::is_dead_channel`]):
    /// recoverable failures (replay, too-old, single crypto failure, proto
    /// decode, partial packet, transient socket I/O) are dropped by the session
    /// and keep the UDP path alive; the dead-channel signal and packet-number
    /// overflow propagate (see [`UdpQspError::is_recoverable`] for the policy,
    /// including the deliberate changes from the old kind-based path).
    #[error(transparent)]
    UdpQsp(#[from] UdpQspError),

    /// Cryptographic operation failure on the session path (e.g. `RAND_bytes`
    /// during UDP-QSP registration key generation). Preserves the boring
    /// `ErrorStack` rather than stringifying it. Fatal: local crypto state.
    #[error("session crypto error: {0}")]
    Crypto(#[from] ErrorStack),

    // slt-core protocol errors are preserved, not flattened. These replace the
    // `wire.rs` `map_*` mappers on the session call sites. Each is a real
    // `std::error::Error` in `slt-core` (phase 5 promoted
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

impl SessionError {
    /// Reconnect/fatal policy projection onto [`SessionExit`](super::SessionExit).
    ///
    /// Derived from the variant via a `match`, so it can never disagree with
    /// the variant (unlike the old `classify_error(io::Error)` that guessed
    /// from `ErrorKind`). This is the replacement for `classify_error`: the
    /// typed error is built at the failure site, and the control-flow reason
    /// is derived from it here.
    ///
    /// Mapping (preserves today's reconnect decisions — see the policy table
    /// in `local/error-architecture.md`):
    /// - [`Self::ProtocolViolation`] / proto errors ([`Self::Frame`]/
    ///   [`Self::Message`]/[`Self::Payload`]) / [`Self::Crypto`] →
    ///   `ProtocolError` (fatal).
    /// - [`Self::PermissionDenied`] → `PermissionDenied` (fatal).
    /// - [`Self::UdpUpgradeRequired`] → `UdpUpgradeRequired` (fatal).
    /// - [`Self::Connection`] / generic [`Self::Io`] / [`Self::UdpQsp`] →
    ///   `ConnectionError` (reconnect). [`Self::UdpQsp`] buckets here because
    ///   the recoverable-vs-fatal *transport* decision (drop & continue vs.
    ///   dead-channel) is made before reaching `exit()`: a dropped recoverable
    ///   failure never produces a `SessionError` at all, and the dead-channel
    ///   signal routes through `exit()` as a reconnect (matching the old
    ///   `ConnectionAborted` → reconnect behaviour).
    ///
    /// Proto decode failures all map to `ProtocolError` to match the old
    /// `classify_error` behaviour, where `map_*_error` produced
    /// `io::ErrorKind::InvalidData` and `classify_error` bucketed that as
    /// `ProtocolError`. Phase 5 (promoting `MessageError`/`PayloadError` to
    /// real `Error` types) can revisit per-variant policy if warranted.
    #[must_use]
    pub const fn exit(&self) -> super::SessionExit {
        match self {
            Self::ProtocolViolation { .. }
            | Self::Frame(_)
            | Self::Message(_)
            | Self::Payload(_)
            | Self::Crypto(_) => super::SessionExit::ProtocolError,
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
    /// Phase-3 replacement for the old `io_kind() == Some(ConnectionAborted)`
    /// check on the UDP path: the typed [`UdpQspError`] carries the
    /// classification directly. Returns `false` for every non-`UdpQsp` variant
    /// and for non-dead-channel `UdpQsp` failures.
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
    /// Phase-3 replacement for the old `io_kind() == Some(InvalidData)` drop
    /// check on the UDP path. Returns `false` for every non-`UdpQsp` variant,
    /// since those are typed session/proto errors that propagate (the UDP
    /// transport's recoverable classification does not apply to them).
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
    /// which the UDP write/flush handlers propagate unchanged. This is the
    /// phase-3 replacement for the old `err.as_io().is_some()` check that
    /// separated "I/O from the UDP path → fall back" from "typed session error
    /// → propagate".
    #[must_use]
    pub const fn is_udp_path_transport_error(&self) -> bool {
        matches!(self, Self::UdpQsp(_) | Self::Io(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::session::SessionExit;

    /// One representative `SessionError` per variant, so coverage tests can't
    /// miss a variant. The asserted length is the number of `SessionError`
    /// variants; adding a variant without a representative case fails loudly.
    fn representative_cases() -> Vec<SessionError> {
        let cases: Vec<SessionError> = vec![
            SessionError::ProtocolViolation {
                detail: "unexpected control message",
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
            SessionError::Frame(FrameError::UnknownType(0xFF)),
            SessionError::Message(MessageError::DataTooLarge { len: 10, max: 5 }),
            SessionError::Payload(PayloadError::InvalidCipher(0x99)),
        ];
        // 11 cases covering all 10 distinct SessionError variants, with a
        // second `UdpQsp` entry (the variant has two behaviorally-distinct
        // inner shapes that `is_udp_qsp_recoverable()` / `is_udp_qsp_dead_channel()`
        // distinguish): one recoverable shape (Replay) and one fatal shape
        // (DeadChannel). Adding a variant without a representative case fails
        // the distinct-discriminant check below.
        assert_eq!(
            cases.len(),
            11,
            "representative_cases must contain exactly 11 cases \
             (10 variants + a second UdpQsp inner shape); update when adding a variant"
        );
        // Distinct variants via a HashSet of Discriminant values (a `Vec::dedup`
        // would only catch *adjacent* duplicates and so could miss a misplaced
        // case). 10 = the number of SessionError variants.
        let distinct: std::collections::HashSet<_> =
            cases.iter().map(std::mem::discriminant).collect();
        assert_eq!(
            distinct.len(),
            10,
            "representative_cases must cover all 10 distinct SessionError variants exactly once"
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

    /// The fatal-vs-reconnect projection must match the policy table. This is
    /// the guardrail against re-introducing `ErrorKind`-based guesswork on the
    /// session path.
    #[test]
    fn exit_matches_policy_table() {
        // Fatal exits.
        assert_eq!(
            SessionError::ProtocolViolation { detail: "x" }.exit(),
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
        // PayloadError buckets under ProtocolError (fatal) to preserve the
        // pre-refactor behaviour. Phase 5 promoted `PayloadError` to a real
        // `Error` type but deliberately did not revisit per-variant exit policy
        // (behaviour-preserving representation change only).
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

    /// A protocol error must be distinct from a connection error: this is the
    /// "classified by stage, not by ErrorKind" property from the design note.
    #[test]
    fn protocol_and_connection_errors_are_distinct() {
        assert_ne!(
            SessionError::ProtocolViolation { detail: "x" }.exit(),
            SessionError::Connection {
                source: io::Error::other("net")
            }
            .exit()
        );
    }

    /// The typed UDP-QSP recoverable/dead-channel projections must classify
    /// each `UdpQspError` shape correctly: this is the phase-3 replacement for
    /// the old `io_kind() == Some(InvalidData)` / `ConnectionAborted` checks.
    /// Also pins [`SessionError::is_udp_path_transport_error`] — the phase-3
    /// replacement for the old `as_io().is_some()` gate used at the UDP write /
    /// flush / tun-packet / upgrade-probe call sites to separate "UDP-path
    /// transport condition -> fall back" from "typed session error -> propagate".
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
        // send again on this UDP path — propagates to TCP fallback (the old
        // `QuotaExceeded` routing), not a drop. Not the dead-channel signal.
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

        // `is_udp_path_transport_error` is the phase-3 gate for the UDP write /
        // flush / tun-packet / upgrade-probe fallback decision (replaces the old
        // `err.as_io().is_some()` check). True for the UDP-QSP typed failure and
        // for a raw socket `io::Error` (UDP flush); false for typed
        // proto/violation/crypto conditions, which propagate.
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
        assert!(!SessionError::ProtocolViolation { detail: "x" }.is_udp_path_transport_error());
        assert!(
            !SessionError::Crypto(ErrorStack::internal_error(io::Error::other("rand")))
                .is_udp_path_transport_error()
        );
        assert!(!SessionError::Frame(FrameError::UnknownType(0x01)).is_udp_path_transport_error());
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
        // `Display`, so the structured values (lengths) survive to the terminal
        // render rather than a `Debug`-format variant name.
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
    /// values, the offending byte, etc.) — the property the design note
    /// requires of the terminal `{:#}` format.
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
    /// or session close (otherwise), matching the old `QuotaExceeded` routing.
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
}
