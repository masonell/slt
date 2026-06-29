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
//! See `local/error-architecture.md` for the full design (this is phase 2).

use std::io;

use slt_core::proto::{FrameError, MessageError, PayloadError};

/// A failure from an established session.
///
/// The variant is the source of truth — it carries the operation's detail and
/// preserves the original error via `#[source]`/`#[from]`. [`Self::exit`] is a
/// derived projection onto the reconnect-policy enum
/// [`SessionExit`](super::SessionExit); like [`crate::error::ConnectError::stage`]
/// it can never disagree with the variant because it is derived from it.
///
/// The slt-core protocol errors are preserved, not flattened: `FrameError`
/// flows via `#[from]` (it is a `thiserror::Error` type), while `MessageError`
/// and `PayloadError` are plain `Copy` enums in `slt-core` without
/// `Display`/`Error` impls, so they are stored by value with a `Debug`-format
/// `Display` — mirroring the phase-1 [`crate::error::ConnectError`] handling.
/// Promoting them to proper `Error` types is phase 5; the by-value + manual
/// `From` impls here switch to `#[from]` then.
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
    /// reserved for a future UDP-protect denial on the session path, e.g. when
    /// phase 3 types the UDP-QSP transport. Not a regression — the old
    /// `classify_error` `PermissionDenied` branch was likewise unreachable on
    /// the session path.
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
    /// [`Self::Connection`]; expected to shrink as later phases (3+) make the
    /// UDP-QSP transport path typed.
    #[error(transparent)]
    Io(#[from] io::Error),

    // slt-core protocol errors are preserved, not flattened. These replace the
    // `wire.rs` `map_*` mappers on the session call sites. See the module docs
    // for why `MessageError`/`PayloadError` are by-value rather than `#[from]`.
    /// Protocol framing error, preserved from `slt_core`.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Protocol message error, preserved from `slt_core` by value.
    #[error("protocol message error: {0:?}")]
    Message(MessageError),
    /// Protocol payload decode error, preserved from `slt_core` by value.
    #[error("protocol payload error: {0:?}")]
    Payload(PayloadError),
}

// Manual `From` impls so session call sites can use `?` to preserve proto
// decode errors without the `wire.rs` `map_*` mappers. These mirror the phase-1
// `ConnectError` handling: `MessageError`/`PayloadError` do not implement
// `std::error::Error` in `slt-core` (they are plain `Copy` enums), so they
// cannot use `#[from]`; they are `Copy`, so the conversion is trivial.
impl From<MessageError> for SessionError {
    fn from(err: MessageError) -> Self {
        Self::Message(err)
    }
}

impl From<PayloadError> for SessionError {
    fn from(err: PayloadError) -> Self {
        Self::Payload(err)
    }
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
    ///   [`Self::Message`]/[`Self::Payload`]) → `ProtocolError` (fatal).
    /// - [`Self::PermissionDenied`] → `PermissionDenied` (fatal).
    /// - [`Self::UdpUpgradeRequired`] → `UdpUpgradeRequired` (fatal).
    /// - [`Self::Connection`] / generic [`Self::Io`] → `ConnectionError`
    ///   (reconnect).
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
            | Self::Payload(_) => super::SessionExit::ProtocolError,
            Self::PermissionDenied { .. } => super::SessionExit::PermissionDenied,
            Self::UdpUpgradeRequired => super::SessionExit::UdpUpgradeRequired,
            Self::Connection { .. } | Self::Io(_) => super::SessionExit::ConnectionError,
        }
    }

    /// The `io::ErrorKind` of a wrapped I/O source, if any.
    ///
    /// Used only at the UDP-QSP transport boundary (`handle_udp_error`,
    /// `should_drop_refresh_udp_error`, the `ConnectionAborted` dead-channel
    /// check), which still classifies by kind pending the phase-3 UDP-QSP
    /// transport typing. Everywhere else the variant is the classifier. Returns
    /// `None` for proto errors and the non-I/O typed variants.
    #[must_use]
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io(source) | Self::Connection { source } | Self::PermissionDenied { source } => {
                Some(source.kind())
            }
            Self::ProtocolViolation { .. }
            | Self::UdpUpgradeRequired
            | Self::Frame(_)
            | Self::Message(_)
            | Self::Payload(_) => None,
        }
    }

    /// The wrapped I/O source, if any.
    ///
    /// Used only at the UDP-QSP transport boundary (notably `handle_udp_error`,
    /// which still takes `&io::Error` pending the phase-3 UDP-QSP transport
    /// typing). Returns `None` for proto errors and the non-I/O typed variants.
    #[must_use]
    // Returning `Option<&io::Error>` is not yet `const`-stable on stable Rust
    // (would need `const_refs_to_cell`/const-`Drop` for `io::Error`), so this
    // stays a non-`const` `fn` despite the pure match.
    #[allow(clippy::missing_const_for_fn)]
    pub fn as_io(&self) -> Option<&io::Error> {
        match self {
            Self::Io(source) | Self::Connection { source } | Self::PermissionDenied { source } => {
                Some(source)
            }
            Self::ProtocolViolation { .. }
            | Self::UdpUpgradeRequired
            | Self::Frame(_)
            | Self::Message(_)
            | Self::Payload(_) => None,
        }
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
            SessionError::Frame(FrameError::UnknownType(0xFF)),
            SessionError::Message(MessageError::DataTooLarge { len: 10, max: 5 }),
            SessionError::Payload(PayloadError::InvalidCipher(0x99)),
        ];
        // 8 variants: ProtocolViolation, PermissionDenied, UdpUpgradeRequired,
        // Connection, Io, Frame, Message, Payload.
        assert_eq!(
            cases.len(),
            8,
            "representative_cases must cover every SessionError variant; \
             update this count when adding a variant"
        );
        let distinct = cases
            .iter()
            .map(std::mem::discriminant)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            distinct.len(),
            cases.len(),
            "representative_cases has duplicate variants; \
             each entry must be a distinct SessionError variant"
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
        // pre-refactor behaviour; phase 5 can revisit per-variant policy once
        // PayloadError is a real `Error` type.
        assert_eq!(
            SessionError::Payload(PayloadError::InvalidCipher(0x99)).exit(),
            SessionExit::ProtocolError
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
        assert!(rendered.contains("DataTooLarge"), "msg: {rendered:?}");
        assert!(rendered.contains("9999"), "msg: {rendered:?}");

        let payload = SessionError::Payload(PayloadError::InvalidCipher(0x99));
        let rendered = format!("{payload:#}");
        assert!(rendered.contains("InvalidCipher"), "payload: {rendered:?}");
        assert!(
            rendered.contains("0x99") || rendered.contains("153"),
            "payload: {rendered:?}"
        );
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
}
