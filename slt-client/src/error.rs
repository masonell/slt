//! Typed errors for the connect/auth sequence.
//!
//! [`ConnectError`] classifies each failure by *where it happened and what it
//! was* — not by guessing an `io::ErrorKind` at a distant call site.
//! [`ConnectError::stage`] is a coarse projection for log grouping and UI
//! summaries; [`ConnectError::is_retriable`] is the typed retry/fatal policy.
//! Both are derived from the variant, so they can never disagree with it.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use boring::error::ErrorStack;
use boring::ssl::ErrorCode;
use boring::x509::X509VerifyError;
use slt_core::proto::{
    AuthFailCode, FrameError, MessageError, MessageValidationError, PayloadError,
};
use slt_core::transport::tcp::TcpWriteError;
use slt_core::types::ClientId;

use crate::transport::socket_protector::SocketKind;

/// Coarse projection of where a failure originated, for log grouping and UI
/// summaries.
///
/// `Stage` is derived from a [`ConnectError`] variant via
/// [`ConnectError::stage`]; it is never stored separately, so the two can never
/// disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Setup/configuration (e.g. empty hostname) before any I/O.
    Config,
    /// TCP socket allocation (`TcpSocket::new_v4`/`new_v6`).
    TcpSocketCreate,
    /// Platform socket protection (`SocketProtector::protect`).
    SocketProtect,
    /// TCP `connect(2)` to the peer (including timeout).
    TcpConnect,
    /// TLS handshake / setup.
    TlsHandshake,
    /// Auth exchange (`AUTH`/`AUTH_OK`/`AUTH_FAIL` and surrounding I/O).
    Auth,
    /// Cancellation of the connect/auth sequence.
    Cancelled,
}

/// A wrapper that preserves a boring TLS handshake failure, decoupled from the
/// underlying stream type.
///
/// `tokio_boring::HandshakeError<S>` is parameterized by the stream type and
/// keeps its inner `boring::ssl::HandshakeError` private, so it cannot be
/// stored directly in a stream-agnostic error type. `TlsError` instead captures
/// the structured information that is extractable independent of the stream:
/// the boring [`ErrorCode`] (for a mid-handshake failure) or the setup
/// [`ErrorStack`] (for a pre-handshake setup failure), plus — when available —
/// the captured X.509 verification error and underlying I/O error so cert
/// failures can be distinguished from transient transport loss in
/// [`ConnectError::is_retriable`].
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// TLS setup failed before the handshake could run (context build, CA
    /// store, `Ssl::new`, hostname configuration).
    #[error("tls setup failed: {0}")]
    Setup(#[source] ErrorStack),

    /// The TLS handshake failed or was interrupted. Carries the structured
    /// boring error code and, when the failure happened after a certificate was
    /// received, the captured X.509 verification error and any underlying I/O
    /// error kind reported by boring.
    // Display drops the "tls handshake failed:" prefix because this variant is
    // always rendered as the `#[source]` of `ConnectError::TlsHandshake`, which
    // already provides that framing — repeating it would double the prefix.
    #[error("code={code} verify_error={verify_error:?} io_error_kind={io_error_kind:?}")]
    Handshake {
        /// The boring `SSL_ERROR_*` code reported for the handshake failure.
        code: ErrorCode,
        /// Captured X.509 verification error, if one was reported on the
        /// mid-handshake stream. Its presence forces a fatal retry policy.
        verify_error: Option<X509VerifyError>,
        /// `ErrorKind` of the underlying I/O error boring associated with the
        /// handshake failure, if any (e.g. connection reset mid-handshake).
        /// Only the kind is kept because `tokio_boring::HandshakeError` lends
        /// the `io::Error` by `&` and `io::Error` is not `Clone`; the kind is
        /// the retry-relevant part, consumed by [`Self::is_transient_io`].
        io_error_kind: Option<io::ErrorKind>,
    },
}

impl TlsError {
    /// Whether this TLS failure looks like a transient network condition rather
    /// than a cert/handshake fault.
    ///
    /// Used by [`ConnectError::is_retriable`]. A certificate error is fatal:
    /// it never self-heals, so it must not be retried alongside transient TLS
    /// I/O. A captured X.509 verification error is therefore always fatal.
    /// Otherwise an underlying boring I/O error, `SSL_ERROR_SYSCALL`, or a
    /// clean close mid-handshake is treated as transient. Everything else
    /// (including SSL protocol errors and an absent cause) is treated as a
    /// fatal handshake fault — the safer default, since a retried cert error
    /// would loop forever without recovering.
    #[must_use]
    pub fn is_transient_io(&self) -> bool {
        match self {
            // Setup failures are config/capability problems; not transient I/O.
            Self::Setup(_) => false,
            Self::Handshake {
                code,
                verify_error,
                io_error_kind,
            } => {
                // A certificate verification failure is never transient.
                if verify_error.is_some() {
                    return false;
                }
                // An underlying io::Error (e.g. connection reset mid-handshake)
                // is transient. Boring may also report transport loss as
                // SYSCALL/ZERO_RETURN without exposing an io::Error through
                // tokio-boring, notably on weak mobile links.
                io_error_kind.is_some()
                    || *code == ErrorCode::SYSCALL
                    || *code == ErrorCode::ZERO_RETURN
            }
        }
    }
}

/// A failure from the connect/auth sequence.
///
/// [`Stage`] is a derived projection ([`Self::stage`]); retry/fatal policy is
/// derived from the variant ([`Self::is_retriable`]).
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// The connect sequence was cancelled before completing.
    ///
    /// The runtime checks `cancel.is_cancelled()` first, so this variant is
    /// mostly defensive — it exists so cancellation paths can return the typed
    /// error instead of synthesizing an `io::Error`.
    #[error("connect sequence cancelled")]
    Cancelled,

    /// Empty hostname in the client configuration.
    #[error("hostname is empty")]
    EmptyHostname,

    /// TCP socket allocation failed (`TcpSocket::new_v4`/`new_v6`).
    #[error("tcp socket create failed: peer={peer}: {source}")]
    TcpSocketCreate {
        /// Peer address that was being connected to.
        peer: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Platform socket protection (`SocketProtector::protect`) was rejected.
    #[error("tcp socket protect failed: fd={fd} kind={kind:?} peer={peer}: {source}")]
    SocketProtect {
        /// Raw file descriptor passed to the protector.
        fd: i32,
        /// Transport socket kind passed to the protector.
        kind: SocketKind,
        /// Peer address associated with the socket.
        peer: SocketAddr,
        /// Underlying I/O error from the protector.
        #[source]
        source: io::Error,
    },

    /// TCP `connect(2)` timed out.
    #[error("tcp connect timed out: peer={peer} timeout={timeout:?}")]
    TcpConnectTimeout {
        /// Peer address that was being connected to.
        peer: SocketAddr,
        /// Configured connect timeout that elapsed.
        timeout: Duration,
    },

    /// TCP `connect(2)` failed (refused, unreachable, etc.).
    #[error("tcp connect failed: peer={peer}: {source}")]
    TcpConnect {
        /// Peer address that was being connected to.
        peer: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// TLS handshake timed out.
    #[error("tls handshake timed out: sni={sni} timeout={timeout:?}")]
    TlsHandshakeTimeout {
        /// SNI hostname used for the handshake.
        sni: String,
        /// Configured handshake timeout that elapsed.
        timeout: Duration,
    },

    /// TLS handshake / setup failed.
    #[error("tls handshake failed: sni={sni}: {source}")]
    TlsHandshake {
        /// SNI hostname used for the handshake.
        sni: String,
        /// Underlying boring TLS failure.
        #[source]
        source: TlsError,
    },

    /// Server rejected authentication with a concrete `AUTH_FAIL` code.
    ///
    /// Carries the [`AuthFailCode`] the server chose to send, so the caller
    /// (retry policy, UI) sees the actual rejection reason.
    #[error("auth rejected: code={code:?} client_id={client_id} assigned_ipv4={assigned_ipv4}")]
    AuthRejected {
        /// Failure code reported by the server.
        code: AuthFailCode,
        /// Client identity that was rejected.
        client_id: ClientId,
        /// Assigned IPv4 from the client identity.
        assigned_ipv4: Ipv4Addr,
    },

    /// Authentication exchange or one of its TCP writes timed out.
    #[error("auth timed out")]
    AuthTimeout,

    /// Server closed the connection during authentication (EOF/reset/close).
    #[error("auth connection closed by server")]
    AuthDisconnected,

    /// Server terminated the authentication exchange because of a protocol
    /// violation. Fatal because retrying the same protocol exchange will not
    /// make it valid.
    #[error("server reported protocol error during auth")]
    AuthProtocolError,

    /// Client received an unexpected protocol message during the auth exchange.
    ///
    /// This is a client-detected direction, phase, or transport violation, as
    /// opposed to [`Self::AuthRejected`], which only ever carries a code the
    /// server actually sent inside a decoded `AUTH_FAIL`. Fatal: the server is
    /// speaking a protocol we don't expect, so retry won't help.
    #[error("unexpected message during auth")]
    AuthUnexpectedMessage,

    /// TLS keying-material export failed during auth challenge derivation.
    ///
    /// Local TLS state; retry will not help.
    #[error("auth tls key export failed: {source}")]
    AuthTlsExport {
        /// `ErrorStack` from `export_keying_material`.
        #[source]
        #[from]
        source: ErrorStack,
    },

    /// Hostname resolution failed or yielded no usable addresses.
    #[error("dns resolution failed for {hostname}: {source}")]
    DnsResolution {
        /// Hostname that failed to resolve.
        hostname: String,
        /// Underlying I/O error from the resolver.
        #[source]
        source: io::Error,
    },

    /// Generic I/O failure on the connect/auth path not covered by a more
    /// specific variant.
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

impl From<TcpWriteError> for ConnectError {
    /// Thread `TcpChannel::write_message`'s typed write error into the
    /// connect/auth error without flattening either source.
    ///
    /// - **`Io` → [`ConnectError::Io`]**: a network-level write failure on the
    ///   connect/auth path. Transient I/O is retryable; `PermissionDenied` is a
    ///   local policy/capability failure and is fatal.
    /// - **`Frame` → [`ConnectError::Frame`]**: fatal. A `FrameError` from
    ///   encoding a locally-constructed `Message` is a logic/config bug (an
    ///   unknown message type, or a payload oversized despite the TUN-layer
    ///   pre-check) — retrying won't fix it, so routing it to the typed `Frame`
    ///   variant surfaces it as fatal (`is_retriable() == false`).
    fn from(err: TcpWriteError) -> Self {
        match err {
            TcpWriteError::Frame(frame) => Self::Frame(frame),
            TcpWriteError::Io(io) => Self::Io(io),
        }
    }
}

impl From<MessageValidationError> for ConnectError {
    fn from(err: MessageValidationError) -> Self {
        match err {
            MessageValidationError::InvalidPayload { source, .. } => Self::Payload(source),
            MessageValidationError::InvalidDirection { .. }
            | MessageValidationError::InvalidPhase { .. }
            | MessageValidationError::InvalidTransport { .. } => Self::AuthUnexpectedMessage,
        }
    }
}

impl ConnectError {
    /// Coarse origin of the failure.
    ///
    /// Derived from the variant via a `match`, so it can never disagree with
    /// the variant (unlike an `ErrorKind`-based classifier at a distant call
    /// site). Intended for log grouping and UI summaries.
    #[must_use]
    pub const fn stage(&self) -> Stage {
        match self {
            Self::Cancelled => Stage::Cancelled,
            Self::EmptyHostname | Self::DnsResolution { .. } => Stage::Config,
            Self::TcpSocketCreate { .. } => Stage::TcpSocketCreate,
            Self::SocketProtect { .. } => Stage::SocketProtect,
            // Generic I/O on the connect/auth path has no single origin; bucket
            // it under TcpConnect (the closest "transport" stage). This is a
            // fallback that should become more specific as variants are added;
            // the Io catch-all is expected to shrink as more specific variants
            // are added.
            Self::TcpConnectTimeout { .. } | Self::TcpConnect { .. } | Self::Io(_) => {
                Stage::TcpConnect
            }
            Self::TlsHandshakeTimeout { .. } | Self::TlsHandshake { .. } => Stage::TlsHandshake,
            Self::AuthRejected { .. }
            | Self::AuthTimeout
            | Self::AuthDisconnected
            | Self::AuthProtocolError
            | Self::AuthUnexpectedMessage
            | Self::AuthTlsExport { .. }
            | Self::Frame(_)
            | Self::Message(_)
            | Self::Payload(_) => Stage::Auth,
        }
    }

    /// Retry/fatal policy for the connect/auth path.
    ///
    /// Matches on the variant — some stages need detail (e.g. TLS cert vs.
    /// transient I/O) that only the variant carries.
    ///
    /// - **Fatal** (won't self-heal): `EmptyHostname`, `TcpSocketCreate`,
    ///   `SocketProtect` (permission/platform fault), `TlsHandshake` (cert/setup fault),
    ///   `AuthRejected`, `AuthProtocolError`, `AuthUnexpectedMessage`,
    ///   `AuthTlsExport`, protocol errors.
    /// - **Retry**: `SocketProtect` (transient network state),
    ///   `TcpConnectTimeout`, transient `TcpConnect`, `AuthTimeout`,
    ///   `AuthDisconnected`, `TlsHandshakeTimeout`, `DnsResolution`,
    ///   `TlsHandshake` (transient I/O), and transient generic `Io`.
    ///   `PermissionDenied` from `TcpConnect` or generic `Io` is a
    ///   firewall/platform policy block and is fatal.
    /// - **Not a real failure**: `Cancelled`.
    ///
    /// Arms are grouped by policy (`false` / `true`) for reviewability;
    /// `match_same_arms` is allowed on this method.
    #[allow(clippy::match_same_arms)]
    #[must_use]
    pub fn is_retriable(&self) -> bool {
        match self {
            // Cancellation is not a failure; the runtime checks the cancel
            // token first. Treat as non-retriable so it never loops.
            Self::Cancelled => false,
            // Config / capability problems: credentials/config won't change
            // across a retry.
            Self::EmptyHostname
            | Self::TcpSocketCreate { .. }
            | Self::AuthRejected { .. }
            | Self::AuthProtocolError
            | Self::AuthUnexpectedMessage
            | Self::AuthTlsExport { .. }
            | Self::Frame(_)
            | Self::Message(_)
            | Self::Payload(_) => false,
            // Transient network conditions. DNS is retriable because the
            // resolver cannot distinguish a permanent typo from a transient
            // failure; retry-with-backoff is the safer default.
            Self::TcpConnectTimeout { .. }
            | Self::AuthTimeout
            | Self::AuthDisconnected
            | Self::TlsHandshakeTimeout { .. }
            | Self::DnsResolution { .. } => true,
            // Android reports an absent or stale underlying network through
            // NotConnected/NetworkUnreachable. Local protection rejection and
            // unexpected platform failures remain fatal.
            Self::SocketProtect { source, .. } => matches!(
                source.kind(),
                io::ErrorKind::NotConnected | io::ErrorKind::NetworkUnreachable
            ),
            // TCP connect(2): most failures are transient (refused, reset,
            // unreachable) and worth retrying. PermissionDenied (EACCES) is a
            // firewall/platform policy block that won't self-heal, so treat it
            // as fatal rather than retrying forever.
            Self::TcpConnect { source, .. } => source.kind() != io::ErrorKind::PermissionDenied,
            // TLS: distinguish cert/setup fault (fatal) from transient I/O.
            Self::TlsHandshake { source, .. } => source.is_transient_io(),
            // Generic fallback: transient by default, except for local
            // policy/capability denial (EACCES/EPERM), which won't self-heal.
            Self::Io(source) => source.kind() != io::ErrorKind::PermissionDenied,
        }
    }
}

#[cfg(test)]
mod tests;
