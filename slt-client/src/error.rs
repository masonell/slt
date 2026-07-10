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
use slt_core::proto::{AuthFailCode, FrameError, MessageError, PayloadError};
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
    /// This is a client-detected protocol violation (a message that is not
    /// `AUTH_OK`/`AUTH_FAIL`/`PING`/`CLOSE` arrived while authenticating), as
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
mod tests {
    use super::*;
    use crate::transport::socket_protector::SocketProtectionResult;

    /// Build a boring `ErrorStack` for tests (preserves a cause string).
    fn test_error_stack() -> ErrorStack {
        ErrorStack::internal_error(io::Error::other("test boring error"))
    }

    /// A constructed `X509VerifyError` for tests (cert verification failure).
    fn test_verify_error() -> X509VerifyError {
        X509VerifyError::CERT_HAS_EXPIRED
    }

    /// Every variant's `stage()` must be one of the documented stages, and the
    /// match in `stage()` must be exhaustive (the compiler enforces this, but
    /// this test pins the mapping so a careless edit is caught loudly).
    #[test]
    fn stage_is_defined_for_a_representative_variant_per_branch() {
        for err in representative_cases() {
            // Every representative case must map to one of the known stages —
            // exhaustive coverage is enforced separately by `representative_cases`
            // asserting its length equals the variant count.
            let stage = err.stage();
            assert!(
                matches!(
                    stage,
                    Stage::Config
                        | Stage::TcpSocketCreate
                        | Stage::SocketProtect
                        | Stage::TcpConnect
                        | Stage::TlsHandshake
                        | Stage::Auth
                        | Stage::Cancelled
                ),
                "variant {err:?} mapped to unknown stage {stage:?}"
            );
        }

        // Spot-check a few specific mappings that matter for log grouping.
        let peer: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        assert_eq!(ConnectError::Cancelled.stage(), Stage::Cancelled);
        assert_eq!(ConnectError::EmptyHostname.stage(), Stage::Config);
        assert_eq!(
            ConnectError::TcpSocketCreate {
                peer,
                source: io::Error::other("x")
            }
            .stage(),
            Stage::TcpSocketCreate
        );
        assert_eq!(ConnectError::AuthProtocolError.stage(), Stage::Auth);
        assert_eq!(ConnectError::AuthUnexpectedMessage.stage(), Stage::Auth);
        assert_eq!(
            ConnectError::Io(io::Error::other("x")).stage(),
            Stage::TcpConnect
        );
    }

    /// The TLS cert/transient-IO split — the headline correctness win of the
    /// typed policy — must classify each `TlsError` shape correctly. A captured
    /// X.509 verification error is always fatal (even when accompanied by an
    /// I/O error); an I/O error or Boring transport-loss code without a cert
    /// fault is transient; everything else (setup, bare SSL protocol errors) is
    /// fatal.
    #[test]
    fn tls_error_is_transient_io_classifies_each_shape() {
        // Setup fault → fatal.
        assert!(!TlsError::Setup(test_error_stack()).is_transient_io());

        // Cert verification failure → fatal, regardless of I/O.
        assert!(
            !TlsError::Handshake {
                code: ErrorCode::SSL,
                verify_error: Some(test_verify_error()),
                io_error_kind: None,
            }
            .is_transient_io()
        );
        // Adversarial: cert fault AND an io error — cert wins, still fatal.
        assert!(
            !TlsError::Handshake {
                code: ErrorCode::SSL,
                verify_error: Some(test_verify_error()),
                io_error_kind: Some(io::ErrorKind::ConnectionReset),
            }
            .is_transient_io()
        );

        // Transient I/O, no cert fault → retriable.
        assert!(
            TlsError::Handshake {
                code: ErrorCode::SYSCALL,
                verify_error: None,
                io_error_kind: Some(io::ErrorKind::ConnectionReset),
            }
            .is_transient_io()
        );

        // Boring may report mobile-link transport loss without surfacing an
        // io::Error through tokio-boring.
        assert!(
            TlsError::Handshake {
                code: ErrorCode::SYSCALL,
                verify_error: None,
                io_error_kind: None,
            }
            .is_transient_io()
        );
        assert!(
            TlsError::Handshake {
                code: ErrorCode::ZERO_RETURN,
                verify_error: None,
                io_error_kind: None,
            }
            .is_transient_io()
        );

        // No cert fault, no I/O (bare SSL protocol error) → fatal (safe default).
        assert!(
            !TlsError::Handshake {
                code: ErrorCode::SSL,
                verify_error: None,
                io_error_kind: None,
            }
            .is_transient_io()
        );
    }

    /// The retry/fatal policy, pinned per variant and relevant source kind.
    #[test]
    fn is_retriable_matches_policy_table() {
        let peer: SocketAddr = "127.0.0.1:8443".parse().unwrap();

        // Fatal.
        assert!(!ConnectError::Cancelled.is_retriable());
        assert!(!ConnectError::EmptyHostname.is_retriable());
        assert!(
            !ConnectError::TcpSocketCreate {
                peer,
                source: io::Error::from(io::ErrorKind::PermissionDenied),
            }
            .is_retriable()
        );
        assert!(
            !ConnectError::SocketProtect {
                fd: 3,
                kind: SocketKind::Tcp,
                peer,
                source: SocketProtectionResult::ProtectRejected
                    .into_io_result(3, SocketKind::Tcp)
                    .unwrap_err(),
            }
            .is_retriable()
        );
        assert!(
            !ConnectError::SocketProtect {
                fd: 3,
                kind: SocketKind::Tcp,
                peer,
                source: SocketProtectionResult::PlatformFailure
                    .into_io_result(3, SocketKind::Tcp)
                    .unwrap_err(),
            }
            .is_retriable()
        );
        assert!(
            !ConnectError::AuthRejected {
                code: AuthFailCode::BadSignature,
                client_id: ClientId([0; 16]),
                assigned_ipv4: std::net::Ipv4Addr::new(10, 10, 0, 2),
            }
            .is_retriable()
        );
        assert!(!ConnectError::AuthProtocolError.is_retriable());
        assert!(!ConnectError::AuthUnexpectedMessage.is_retriable());
        assert!(
            !ConnectError::AuthTlsExport {
                source: test_error_stack(),
            }
            .is_retriable()
        );
        assert!(!ConnectError::Frame(FrameError::UnknownType(1)).is_retriable());
        assert!(
            !ConnectError::Message(slt_core::proto::MessageError::DataTooLarge { len: 10, max: 5 })
                .is_retriable()
        );
        assert!(!ConnectError::Payload(PayloadError::InvalidCipher(0x99)).is_retriable());

        // TLS: cert/setup fault (fatal).
        assert!(
            !ConnectError::TlsHandshake {
                sni: "h".into(),
                source: TlsError::Setup(test_error_stack()),
            }
            .is_retriable()
        );
        assert!(
            !ConnectError::TlsHandshake {
                sni: "h".into(),
                source: TlsError::Handshake {
                    code: ErrorCode::SSL,
                    verify_error: Some(test_verify_error()),
                    io_error_kind: None,
                },
            }
            .is_retriable()
        );
        // TLS: transient I/O (retriable).
        assert!(
            ConnectError::TlsHandshake {
                sni: "h".into(),
                source: TlsError::Handshake {
                    code: ErrorCode::SYSCALL,
                    verify_error: None,
                    io_error_kind: Some(io::ErrorKind::ConnectionReset),
                },
            }
            .is_retriable()
        );
        assert!(
            ConnectError::TlsHandshake {
                sni: "h".into(),
                source: TlsError::Handshake {
                    code: ErrorCode::SYSCALL,
                    verify_error: None,
                    io_error_kind: None,
                },
            }
            .is_retriable()
        );

        // Retry.
        assert!(
            ConnectError::SocketProtect {
                fd: 3,
                kind: SocketKind::Tcp,
                peer,
                source: SocketProtectionResult::NoUnderlyingNetwork
                    .into_io_result(3, SocketKind::Tcp)
                    .unwrap_err(),
            }
            .is_retriable()
        );
        assert!(
            ConnectError::SocketProtect {
                fd: 3,
                kind: SocketKind::Tcp,
                peer,
                source: SocketProtectionResult::BindFailed
                    .into_io_result(3, SocketKind::Tcp)
                    .unwrap_err(),
            }
            .is_retriable()
        );
        assert!(
            ConnectError::TcpConnectTimeout {
                peer,
                timeout: Duration::from_secs(30),
            }
            .is_retriable()
        );
        assert!(
            ConnectError::TcpConnect {
                peer,
                source: io::Error::from(io::ErrorKind::ConnectionRefused),
            }
            .is_retriable()
        );
        // PermissionDenied from connect(2) is a firewall/platform policy block
        // (non-transient) — fatal, not retried indefinitely.
        assert!(
            !ConnectError::TcpConnect {
                peer,
                source: io::Error::from(io::ErrorKind::PermissionDenied),
            }
            .is_retriable()
        );
        assert!(ConnectError::AuthTimeout.is_retriable());
        assert!(ConnectError::AuthDisconnected.is_retriable());
        assert!(
            ConnectError::TlsHandshakeTimeout {
                sni: "h".into(),
                timeout: Duration::from_secs(30),
            }
            .is_retriable()
        );
        // DNS is retriable: the resolver cannot distinguish a permanent typo
        // from a transient failure.
        assert!(
            ConnectError::DnsResolution {
                hostname: "example.com".into(),
                source: io::Error::from(io::ErrorKind::NotFound),
            }
            .is_retriable()
        );
        assert!(ConnectError::Io(io::Error::other("x")).is_retriable());
        assert!(!ConnectError::Io(io::Error::from(io::ErrorKind::PermissionDenied)).is_retriable());
    }

    /// Pins both arms of `From<TcpWriteError>` so the routing cannot silently
    /// regress.
    #[test]
    fn from_tcp_write_error_routes_frame_fatal_and_io_retriable() {
        use slt_core::transport::tcp::TcpWriteError;

        let frame: ConnectError = TcpWriteError::Frame(FrameError::UnknownType(1)).into();
        assert!(
            matches!(frame, ConnectError::Frame(_)),
            "Frame arm must route to ConnectError::Frame, got {frame:?}"
        );
        assert!(
            !frame.is_retriable(),
            "ConnectError::Frame from TcpWriteError must be fatal (non-retriable)"
        );

        let io: ConnectError =
            TcpWriteError::Io(io::Error::from(io::ErrorKind::ConnectionReset)).into();
        assert!(
            matches!(io, ConnectError::Io(_)),
            "Io arm must route to ConnectError::Io, got {io:?}"
        );
        assert!(
            io.is_retriable(),
            "ConnectError::Io from TcpWriteError must be retriable"
        );
    }

    /// One representative `ConnectError` per variant, so coverage tests can't
    /// miss a variant. The asserted length is the number of `ConnectError`
    /// variants: if a variant is added without a representative case here,
    /// this test fails loudly.
    fn representative_cases() -> Vec<ConnectError> {
        let peer: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let client_id = ClientId([0x11; 16]);
        let assigned_ipv4 = std::net::Ipv4Addr::new(10, 10, 0, 2);
        let cases: Vec<ConnectError> = vec![
            ConnectError::Cancelled,
            ConnectError::EmptyHostname,
            ConnectError::TcpSocketCreate {
                peer,
                source: io::Error::other("x"),
            },
            ConnectError::SocketProtect {
                fd: 3,
                kind: SocketKind::Tcp,
                peer,
                source: io::Error::other("x"),
            },
            ConnectError::TcpConnectTimeout {
                peer,
                timeout: Duration::from_secs(30),
            },
            ConnectError::TcpConnect {
                peer,
                source: io::Error::other("x"),
            },
            ConnectError::TlsHandshakeTimeout {
                sni: "example.com".into(),
                timeout: Duration::from_secs(30),
            },
            // Cert-fault shape.
            ConnectError::TlsHandshake {
                sni: "example.com".into(),
                source: TlsError::Handshake {
                    code: ErrorCode::SSL,
                    verify_error: Some(test_verify_error()),
                    io_error_kind: None,
                },
            },
            ConnectError::AuthRejected {
                code: AuthFailCode::BadSignature,
                client_id,
                assigned_ipv4,
            },
            ConnectError::AuthTimeout,
            ConnectError::AuthDisconnected,
            ConnectError::AuthProtocolError,
            ConnectError::AuthUnexpectedMessage,
            ConnectError::AuthTlsExport {
                source: test_error_stack(),
            },
            ConnectError::DnsResolution {
                hostname: "example.com".into(),
                source: io::Error::other("dns"),
            },
            ConnectError::Io(io::Error::other("x")),
            ConnectError::Frame(FrameError::UnknownType(0xFF)),
            ConnectError::Message(slt_core::proto::MessageError::DataTooLarge { len: 10, max: 5 }),
            ConnectError::Payload(PayloadError::InvalidCipher(0x99)),
        ];
        // 19 variants: Cancelled, EmptyHostname, TcpSocketCreate, SocketProtect,
        // TcpConnectTimeout, TcpConnect, TlsHandshakeTimeout, TlsHandshake,
        // AuthRejected, AuthTimeout, AuthDisconnected, AuthProtocolError,
        // AuthUnexpectedMessage, AuthTlsExport, DnsResolution, Io, Frame,
        // Message, Payload.
        assert_eq!(
            cases.len(),
            19,
            "representative_cases must cover every ConnectError variant; \
             update this count when adding a variant"
        );
        // `len == 18` alone would pass if a variant were duplicated and another
        // dropped. Require distinct discriminants so each entry is a different
        // variant; together with the length check this pins one-per-variant.
        let distinct = cases
            .iter()
            .map(std::mem::discriminant)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            distinct.len(),
            cases.len(),
            "representative_cases has duplicate variants; \
             each entry must be a distinct ConnectError variant"
        );
        cases
    }

    /// No `ConnectError` whose `stage() != Auth` may render the substring
    /// `auth`, and no `stage() == Auth` variant may render without carrying its
    /// auth-specific detail.
    ///
    /// Regression guard against a blanket "PermissionDenied => authentication
    /// rejected" branch reintroduced at any call site: the variant's own
    /// `Display` is the surface that flows to logs and the UI. Cases come from
    /// [`representative_cases`] so a future variant can't slip through untested.
    #[test]
    fn no_misleading_auth_messages() {
        for err in representative_cases() {
            let rendered = err.to_string();
            let lower = rendered.to_ascii_lowercase();
            if err.stage() != Stage::Auth {
                assert!(
                    !lower.contains("auth"),
                    "non-Auth stage {:?} rendered auth substring: {rendered:?}",
                    err.stage()
                );
            } else {
                // Auth-stage variants must carry their auth-specific detail.
                // AuthRejected carries its code; the other auth-specific
                // variants name auth or preserve their source. Proto errors are
                // version mismatch/corruption surfaced during the auth exchange
                // and render their own non-auth-keyword detail.
                match &err {
                    ConnectError::AuthRejected { code, .. } => {
                        assert!(
                            rendered.contains(&format!("{code:?}")),
                            "AuthRejected must render its code: {rendered:?}"
                        );
                    }
                    ConnectError::AuthTimeout
                    | ConnectError::AuthDisconnected
                    | ConnectError::AuthProtocolError
                    | ConnectError::AuthUnexpectedMessage
                    | ConnectError::AuthTlsExport { .. } => {
                        assert!(
                            lower.contains("auth"),
                            "Auth-stage variant must reference auth: {rendered:?}"
                        );
                    }
                    // Proto errors surface during the auth exchange; they don't
                    // carry an AuthFailCode and must not be forced to render
                    // "auth". They are exempt from the keyword check but stay
                    // fatal (asserted in is_retriable_matches_policy_table).
                    ConnectError::Frame(_)
                    | ConnectError::Message(_)
                    | ConnectError::Payload(_) => {}
                    _ => unreachable!("stage() said Auth for a non-auth variant: {rendered:?}"),
                }
            }
        }
    }
}
