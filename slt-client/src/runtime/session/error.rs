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
use slt_core::proto::{FrameError, MessageError, MessageValidationError, PayloadError};
use slt_core::transport::tcp::TcpWriteError;

use crate::transport::udp_qsp::UdpQspError;

/// A failure from an established session.
///
/// [`Self::exit`] is a derived projection onto the reconnect-policy enum
/// [`SessionExit`](super::SessionExit); like [`crate::error::ConnectError::stage`]
/// it can never disagree with the variant because it is derived from it.
///
/// UDP-QSP packet and path failures flow via [`Self::UdpQsp`]. Protocol
/// encode/decode failures are normalized into the protocol variants so they
/// cannot enter UDP path fallback handling.
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
    /// Most network-level errors here are transient conditions (reset, refused,
    /// timeout) for which the runtime reconnects. `PermissionDenied` projects to
    /// a fatal permission failure.
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
    /// [`Self::exit`] maps a wrapped `PermissionDenied` kind to a fatal
    /// permission-denied exit.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// UDP-QSP transport failure.
    ///
    /// The typed [`UdpQspError`] preserves UDP-QSP packet protection and socket
    /// failures. Recoverable failures (replay, too-old, receive-side crypto
    /// failure, transient socket I/O) are dropped by the session; path failures
    /// such as packet-number overflow propagate to fallback handling.
    /// Protocol encode/decode failures are converted into
    /// [`Self::Frame`], [`Self::Message`], or [`Self::ProtocolViolation`].
    #[error(transparent)]
    UdpQsp(UdpQspError),

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
    ///   session path. Transient I/O reconnects (`exit() == ConnectionError`);
    ///   `PermissionDenied` exits fatally (`exit() == PermissionDenied`).
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

impl From<MessageValidationError> for SessionError {
    fn from(err: MessageValidationError) -> Self {
        match err {
            MessageValidationError::InvalidPayload { source, .. } => Self::Payload(source),
            MessageValidationError::InvalidDirection { .. }
            | MessageValidationError::InvalidPhase { .. }
            | MessageValidationError::InvalidTransport { .. } => Self::ProtocolViolation {
                detail: err.to_string().into(),
            },
        }
    }
}

impl From<UdpQspError> for SessionError {
    /// Separates authenticated protocol failures from UDP packet/path failures.
    ///
    /// `Message` and `IncompleteMessage` are produced only after inbound packet
    /// protection and replay validation succeed. `Frame` is an outbound encode
    /// failure. None is a recoverable UDP path condition; the remaining variants
    /// retain the path recovery policy carried by [`Self::UdpQsp`].
    fn from(err: UdpQspError) -> Self {
        match err {
            UdpQspError::Frame(source) => Self::Frame(source),
            UdpQspError::Message(source) => Self::Message(source),
            UdpQspError::IncompleteMessage => Self::ProtocolViolation {
                detail: "authenticated udp-qsp datagram contained an incomplete message".into(),
            },
            transport => Self::UdpQsp(transport),
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
    ///   `ConnectionError` (reconnect), except `PermissionDenied` wrapped by
    ///   `Connection`/`Io`, which projects to `PermissionDenied` (fatal).
    ///   [`Self::UdpQsp`] contains only packet/path failures because its protocol
    ///   variants are normalized by `From<UdpQspError>`. The transport decision
    ///   (drop & continue vs. fallback) is made before reaching `exit()`.
    ///
    /// Proto decode failures all map to `ProtocolError` (fatal). Per-variant
    /// exit policy may be revisited separately if warranted.
    #[must_use]
    pub fn exit(&self) -> super::SessionExit {
        match self {
            Self::ProtocolViolation { .. }
            | Self::Frame(_)
            | Self::Message(_)
            | Self::Payload(_)
            | Self::Crypto(_)
            | Self::UdpQspKeys(_) => super::SessionExit::ProtocolError,
            Self::PermissionDenied { .. } => super::SessionExit::PermissionDenied,
            Self::UdpUpgradeRequired => super::SessionExit::UdpUpgradeRequired,
            Self::Connection { source } | Self::Io(source)
                if source.kind() == io::ErrorKind::PermissionDenied =>
            {
                super::SessionExit::PermissionDenied
            }
            Self::Connection { .. } | Self::Io(_) | Self::UdpQsp(_) => {
                super::SessionExit::ConnectionError
            }
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
mod tests;
