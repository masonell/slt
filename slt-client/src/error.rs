//! Typed errors for the connect/auth sequence.
//!
//! `io::Error` was historically the cross-layer lingua franca of the connect
//! path. It carries only an `ErrorKind` and a free-text string, so once a rich
//! failure (an `AuthFailCode`, a peer address, an `ErrorStack`) entered that
//! type it could not be recovered — callers had to guess its meaning from
//! `ErrorKind`, which is how a socket-create `PermissionDenied` ended up logged
//! as "authentication rejected". [`ConnectError`] replaces that contract for the
//! connect/auth path: every variant is the source of truth (it carries the
//! detail and the preserved source), [`ConnectError::stage`] is a derived
//! projection that can never disagree with the variant, and
//! [`ConnectError::is_retriable`] is the typed retry/fatal policy.
//!
//! See `local/error-architecture.md` for the full design (this is phase 1).

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use boring::error::ErrorStack;
use boring::ssl::ErrorCode;
use boring::x509::X509VerifyError;
use slt_core::proto::{AuthFailCode, FrameError, MessageError, PayloadError};
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

/// A wrapper that preserves a boring TLS handshake failure without
/// stringifying it, decoupled from the underlying stream type.
///
/// `tokio_boring::HandshakeError<S>` is parameterized by the stream type and
/// keeps its inner `boring::ssl::HandshakeError` private, so it cannot be
/// stored directly in a stream-agnostic error type. `TlsError` instead captures
/// the structured information that is extractable independent of the stream:
/// the boring [`ErrorCode`] (for a mid-handshake failure) or the setup
/// [`ErrorStack`] (for a pre-handshake setup failure), plus — when available —
/// the captured X.509 verification error and underlying I/O error so cert
/// failures can be distinguished from transient I/O in
/// [`ConnectError::is_retriable`].
///
/// The requirement from the design note is "preserve, don't stringify", so the
/// structured values (error code, verify error, io error, error stack) survive
/// rather than being collapsed into a single opaque string.
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
        /// Only the kind is preserved because `io::Error` is not `Clone`; the
        /// kind is the retry-relevant part and is `Copy`/`Debug`. Preserving
        /// the full `io::Error` here is a phase-1 simplification tracked as a
        /// follow-up if a richer cause chain is needed.
        // TODO(phase-1): preserve the full `io::Error` cause if a richer chain
        // is needed later.
        io_error_kind: Option<io::ErrorKind>,
    },
}

impl TlsError {
    /// Whether this TLS failure looks like a transient I/O condition rather
    /// than a cert/handshake fault.
    ///
    /// Used by [`ConnectError::is_retriable`] to avoid the latent bug where a
    /// certificate error (fatal, won't self-heal) is retried forever alongside
    /// transient TLS I/O. A captured X.509 verification error is always fatal.
    /// Otherwise an underlying boring I/O error (e.g. connection reset
    /// mid-handshake) is treated as transient; everything else (including SSL
    /// protocol errors and an absent cause) is treated as a fatal handshake
    /// fault — the safer default, since a retried cert error is the bug being
    /// fixed.
    #[must_use]
    pub const fn is_transient_io(&self) -> bool {
        match self {
            // Setup failures are config/capability problems; not transient I/O.
            Self::Setup(_) => false,
            Self::Handshake {
                verify_error,
                io_error_kind,
                ..
            } => {
                // A certificate verification failure is never transient.
                if verify_error.is_some() {
                    return false;
                }
                // An underlying io::Error (e.g. connection reset mid-handshake)
                // is transient; absent cause defaults to fatal.
                io_error_kind.is_some()
            }
        }
    }
}

/// A failure from the connect/auth sequence.
///
/// The variant is the source of truth — it carries the operation's detail and
/// preserves the original error via `#[source]`/`#[from]`. [`Stage`] is a
/// derived projection ([`Self::stage`]); retry/fatal policy is derived from the
/// variant ([`Self::is_retriable`]). Nothing rich is stringified into
/// `io::Error` mid-stack.
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
        /// Preserved underlying I/O error.
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
        /// Preserved underlying I/O error from the protector.
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
        /// Preserved underlying I/O error.
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
        /// Preserved boring TLS error (do not stringify).
        #[source]
        source: TlsError,
    },

    /// Server rejected authentication with a concrete `AUTH_FAIL` code.
    ///
    /// Carries the [`AuthFailCode`] the server chose to send, closing the
    /// decode-then-discard hole where the code was logged and then dropped.
    #[error("auth rejected: code={code:?} client_id={client_id} assigned_ipv4={assigned_ipv4}")]
    AuthRejected {
        /// Failure code reported by the server.
        code: AuthFailCode,
        /// Client identity that was rejected.
        client_id: ClientId,
        /// Assigned IPv4 from the client identity.
        assigned_ipv4: Ipv4Addr,
    },

    /// Authentication exchange timed out waiting for `AUTH_OK`/`AUTH_FAIL`.
    #[error("auth timed out")]
    AuthTimeout,

    /// Server closed the connection during authentication (EOF/reset/close).
    #[error("auth connection closed by server")]
    AuthDisconnected,

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
    /// Local TLS state; retry will not help. Preserves the boring `ErrorStack`
    /// rather than stringifying it.
    #[error("auth tls key export failed: {source}")]
    AuthTlsExport {
        /// Preserved `ErrorStack` from `export_keying_material`.
        #[source]
        #[from]
        source: ErrorStack,
    },

    /// Hostname resolution failed or yielded no usable addresses.
    #[error("dns resolution failed for {hostname}: {source}")]
    DnsResolution {
        /// Hostname that failed to resolve.
        hostname: String,
        /// Preserved underlying I/O error from the resolver.
        #[source]
        source: io::Error,
    },

    /// Generic I/O failure on the connect/auth path not covered by a more
    /// specific variant.
    #[error(transparent)]
    Io(#[from] io::Error),

    // slt-core protocol errors are preserved, not flattened. These replace the
    // duplicated `wire.rs` `map_*` mappers on the auth call sites.
    //
    // `FrameError` implements `std::error::Error` (it derives `thiserror`),
    // so it flows via `#[from]`. `MessageError` and `PayloadError` do not (they
    // are plain `Copy` enums in `slt-core` without `Display`/`Error` impls);
    // they are preserved by value with a `Debug`-format `Display`, which keeps
    // their structured payload (lengths, invalid byte, etc.) instead of
    // collapsing them into a generic `io::Error`. Making `slt-core`'s proto
    // errors proper `Error` types is out of scope for phase 1; tracked as a
    // follow-up so these variants can switch to `#[from]`.
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

// Manual `From` impls so the auth call sites can use `?` to preserve proto
// errors without the `wire.rs` `map_*` mappers. These exist in addition to the
// `#[from]` on `FrameError`/`io::Error` because `MessageError`/`PayloadError`
// do not implement `std::error::Error` in `slt-core` (they are plain `Copy`
// enums). They are `Copy`, so the conversion is trivial.
impl From<MessageError> for ConnectError {
    fn from(err: MessageError) -> Self {
        Self::Message(err)
    }
}

impl From<PayloadError> for ConnectError {
    fn from(err: PayloadError) -> Self {
        Self::Payload(err)
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
            // the Io catch-all is expected to shrink across later phases.
            Self::TcpConnectTimeout { .. } | Self::TcpConnect { .. } | Self::Io(_) => {
                Stage::TcpConnect
            }
            Self::TlsHandshakeTimeout { .. } | Self::TlsHandshake { .. } => Stage::TlsHandshake,
            Self::AuthRejected { .. }
            | Self::AuthTimeout
            | Self::AuthDisconnected
            | Self::AuthUnexpectedMessage
            | Self::AuthTlsExport { .. }
            | Self::Frame(_)
            | Self::Message(_)
            | Self::Payload(_) => Stage::Auth,
        }
    }

    /// Retry/fatal policy for the connect/auth path.
    ///
    /// Replaces the `ErrorKind`-based `should_reconnect` table, which was
    /// correct only by luck (TLS errors flatten to `Uncategorized`, so a
    /// certificate error was retried forever alongside transient TLS I/O).
    /// Matches on the variant — some stages need detail (e.g. TLS cert vs.
    /// transient I/O) that only the variant carries. See the policy table in
    /// `local/error-architecture.md`.
    ///
    /// - **Fatal** (won't self-heal): `EmptyHostname`, `TcpSocketCreate`,
    ///   `SocketProtect`, `TlsHandshake` (cert/setup fault),
    ///   `AuthRejected`, `AuthUnexpectedMessage`, `AuthTlsExport`, protocol
    ///   errors.
    /// - **Retry**: `TcpConnectTimeout`, `TcpConnect` (transient kinds only;
    ///   `PermissionDenied` — a firewall/policy block — is fatal),
    ///   `AuthTimeout`, `AuthDisconnected`, `TlsHandshakeTimeout`,
    ///   `DnsResolution`, `TlsHandshake` (transient I/O), generic `Io`.
    /// - **Not a real failure**: `Cancelled`.
    ///
    /// The grouping of arms by policy (`false` / `true`) is deliberate: it
    /// mirrors the design-note policy table, so a reviewer can audit each
    /// variant's classification against the table at a glance. `match_same_arms`
    /// is therefore allowed on this method.
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
            | Self::SocketProtect { .. }
            | Self::AuthRejected { .. }
            | Self::AuthUnexpectedMessage
            | Self::AuthTlsExport { .. }
            | Self::Frame(_)
            | Self::Message(_)
            | Self::Payload(_) => false,
            // Transient network conditions. DNS is retriable because the
            // resolver cannot distinguish a permanent typo from a transient
            // failure, and the old code already retried these (as generic
            // `NotFound` io errors); retry-with-backoff is the safer default.
            Self::TcpConnectTimeout { .. }
            | Self::AuthTimeout
            | Self::AuthDisconnected
            | Self::TlsHandshakeTimeout { .. }
            | Self::DnsResolution { .. } => true,
            // TCP connect(2): most failures are transient (refused, reset,
            // unreachable) and worth retrying. PermissionDenied (EACCES) is a
            // firewall/platform policy block that won't self-heal, so treat it
            // as fatal — matching the old `should_reconnect` table, which
            // stopped on PermissionDenied rather than retrying forever.
            Self::TcpConnect { source, .. } => source.kind() != io::ErrorKind::PermissionDenied,
            // TLS: distinguish cert/setup fault (fatal) from transient I/O.
            Self::TlsHandshake { source, .. } => source.is_transient_io(),
            // Generic fallback: transient by default.
            Self::Io(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(ConnectError::AuthUnexpectedMessage.stage(), Stage::Auth);
        assert_eq!(
            ConnectError::Io(io::Error::other("x")).stage(),
            Stage::TcpConnect
        );
    }

    /// The TLS cert/transient-IO split — the headline correctness win of the
    /// typed policy — must classify each `TlsError` shape correctly. A captured
    /// X.509 verification error is always fatal (even when accompanied by an
    /// I/O error); an I/O error without a cert fault is transient; everything
    /// else (setup, bare SSL protocol errors) is fatal.
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

    /// The retry/fatal policy must match the design-note table. This is the
    /// real guardrail against re-introducing the `ErrorKind`-based guesswork.
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
                source: io::Error::from(io::ErrorKind::PermissionDenied),
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

        // Retry.
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
        // (non-transient) — fatal, not retried indefinitely. This restores the
        // old `should_reconnect` contract that the unconditional retry arm lost.
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
        // from a transient failure, and the old code retried these as generic
        // NotFound io errors.
        assert!(
            ConnectError::DnsResolution {
                hostname: "example.com".into(),
                source: io::Error::from(io::ErrorKind::NotFound),
            }
            .is_retriable()
        );
        assert!(ConnectError::Io(io::Error::other("x")).is_retriable());
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
        // 18 variants: Cancelled, EmptyHostname, TcpSocketCreate, SocketProtect,
        // TcpConnectTimeout, TcpConnect, TlsHandshakeTimeout, TlsHandshake,
        // AuthRejected, AuthTimeout, AuthDisconnected, AuthUnexpectedMessage,
        // AuthTlsExport, DnsResolution, Io, Frame, Message, Payload.
        assert_eq!(
            cases.len(),
            18,
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
    /// This is the "no misleading messages" regression guard from the design
    /// note: it catches a blanket "PermissionDenied => authentication rejected"
    /// branch reintroduced at any call site. The variant's own `Display` is the
    /// surface that flows to logs and the UI. Cases come from
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
                // AuthRejected carries its code; AuthTimeout/AuthDisconnected/
                // AuthUnexpectedMessage/AuthTlsExport name themselves or their
                // preserved source; proto errors are version mismatch/corruption
                // surfaced during the auth exchange and render their own
                // (non-auth-keyword) detail.
                match &err {
                    ConnectError::AuthRejected { code, .. } => {
                        assert!(
                            rendered.contains(&format!("{code:?}")),
                            "AuthRejected must render its code: {rendered:?}"
                        );
                    }
                    ConnectError::AuthTimeout
                    | ConnectError::AuthDisconnected
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
