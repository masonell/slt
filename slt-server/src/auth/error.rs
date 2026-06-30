//! Typed errors for the inbound authentication path.
//!
//! [`AuthError`] covers the genuine failure paths of the inbound TLS + auth
//! sequence: TLS handshake/setup faults, the auth-phase timeout, a peer
//! disconnect, socket I/O, and protocol decode errors.
//!
//! [`AuthPhaseResult`](super::types::AuthPhaseResult) is reserved for the auth
//! loop's *outcomes* — the code the server chose to send in `AUTH_FAIL`, or the
//! success/normal-completion outcomes — rather than for transport/decode
//! failures, which are typed `AuthError`.

use std::io;

use boring::error::ErrorStack;
use boring::ssl::ErrorCode;
use slt_core::proto::{FrameError, MessageError, PayloadError};

/// A wrapper that preserves a boring TLS handshake failure, decoupled from the
/// underlying stream type.
///
/// `tokio_boring::HandshakeError<S>` is parameterized by the stream type and
/// keeps its inner `boring::ssl::HandshakeError` private, so it cannot be stored
/// directly in a stream-agnostic error type. `TlsError` instead captures the
/// structured information that is extractable independent of the stream: the
/// boring [`ErrorCode`] (for a mid-handshake failure) or the setup
/// [`ErrorStack`] (for a pre-handshake setup failure), plus — when available —
/// the underlying I/O error kind so transient conditions can be distinguished
/// from handshake faults.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// TLS setup failed before the handshake could run (`Ssl::new`, acceptor
    /// build).
    ///
    /// Note: `tokio_boring::HandshakeError` does not expose the inner
    /// `ErrorStack` of a `SetupFailure` (it's private), so this variant
    /// captures a **placeholder** `ErrorStack` (see [`Self::from_handshake_error`])
    /// rather than the real one. This is a shared limitation with the client
    /// `ConnectError` path's `TlsError::Setup`. The variant still distinguishes
    /// a setup fault from a mid-handshake `Handshake` fault, which is the
    /// classification the boundary cares about.
    #[error("tls setup failed: {0}")]
    Setup(#[source] ErrorStack),

    /// The TLS handshake failed or was interrupted. Carries the structured
    /// boring error code and, when boring associated an underlying I/O error
    /// with the failure, its kind (e.g. connection reset mid-handshake).
    // Display drops the "tls handshake failed:" prefix because this variant is
    // always rendered as the `#[source]` of `AuthError::TlsHandshake`, which
    // already provides that framing — repeating it would double the prefix.
    #[error("code={code} io_error_kind={io_error_kind:?}")]
    Handshake {
        /// The boring `SSL_ERROR_*` code reported for the handshake failure.
        code: ErrorCode,
        /// `ErrorKind` of the underlying I/O error boring associated with the
        /// handshake failure, if any. Only the kind is preserved because
        /// `io::Error` is not `Clone`; the kind is the retry-relevant part and
        /// is `Copy`/`Debug`.
        io_error_kind: Option<io::ErrorKind>,
    },
}

impl TlsError {
    /// Construct from a `tokio_boring::HandshakeError`, extracting the
    /// stream-agnostic structured detail.
    ///
    /// A mid-handshake `Failure` (which exposes an `SslRef`) yields
    /// [`Self::Handshake`] with the `ErrorCode` and any underlying I/O error
    /// kind; a `SetupFailure` (no `SslRef`, no code) yields [`Self::Setup`].
    #[must_use]
    pub fn from_handshake_error<S>(err: &tokio_boring::HandshakeError<S>) -> Self {
        // `HandshakeError::code()` is `Some` only for a mid-handshake `Failure`;
        // a `SetupFailure` (ErrorStack, no SslRef) has no code.
        err.code().map_or_else(
            || {
                Self::Setup(ErrorStack::internal_error(io::Error::other(
                    "tls setup failure",
                )))
            },
            |code| Self::Handshake {
                code,
                io_error_kind: err.as_io_error().map(io::Error::kind),
            },
        )
    }
}

/// A failure from the inbound TLS + auth sequence on the server.
///
/// Distinct from [`super::types::AuthPhaseResult`], which represents the auth
/// loop's *decided outcomes*: an `AUTH_FAIL` the server chose to send
/// (`Rejected(code)`), successful authentication, or normal completion are all
/// `Ok` outcomes of the auth phase — they are not failures. [`AuthError`] covers
/// only the genuine failure paths: TLS handshake/setup faults, the auth-phase
/// timeout, a peer disconnect, socket I/O, and protocol decode errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// TLS handshake (server-side `accept`) failed.
    ///
    /// Carries the boring handshake failure via [`TlsError`]: the structured
    /// error code / setup stack survives for `{:#}` and the log.
    #[error("tls handshake failed: {source}")]
    TlsHandshake {
        /// Underlying boring TLS handshake failure (error code / setup stack).
        #[source]
        source: TlsError,
    },

    /// TLS handshake timed out.
    #[error("tls handshake timed out")]
    TlsHandshakeTimeout,

    /// TLS keying-material export failed during auth challenge derivation.
    ///
    /// Carries the boring `ErrorStack` from `export_keying_material`.
    #[error("auth challenge keying-material export failed: {source}")]
    ChallengeExport {
        /// `ErrorStack` from `export_keying_material`.
        #[source]
        source: ErrorStack,
    },

    /// Auth phase timed out waiting for a message from the client.
    #[error("auth phase timed out")]
    Timeout,

    /// Client closed the connection during the auth phase (EOF/reset).
    #[error("connection closed during auth phase")]
    ConnectionClosed,

    /// Network-level I/O failure on the auth path (socket read/write, send of
    /// `AUTH_OK`/`AUTH_FAIL`/`PONG`, etc.).
    #[error("auth connection error: {source}")]
    Connection {
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

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

impl AuthError {
    /// Coarse `io::ErrorKind` projection for this failure.
    ///
    /// Used only by the binary entry point to satisfy the `handle()` ->
    /// `io::Result<()>` contract (whose `ErrorKind` is asserted on by metrics
    /// tests). The kind is derived from the variant here, at the boundary, so it
    /// can never disagree with the structured error.
    #[must_use]
    pub fn io_kind(&self) -> io::ErrorKind {
        match self {
            Self::TlsHandshake { .. } | Self::ChallengeExport { .. } => io::ErrorKind::Other,
            Self::TlsHandshakeTimeout | Self::Timeout => io::ErrorKind::TimedOut,
            Self::ConnectionClosed => io::ErrorKind::ConnectionReset,
            Self::Connection { source } => source.kind(),
            Self::Frame(_) | Self::Message(_) | Self::Payload(_) => io::ErrorKind::InvalidData,
        }
    }
}

impl From<AuthError> for io::Error {
    /// Compose an `io::Error` from the typed failure at the binary boundary.
    ///
    /// This is the single conversion point where the typed `AuthError` meets
    /// `io::Error`: the structured error is preserved as the `io::Error`'s
    /// inner source (via `io::Error::new(kind, error)`), so the cause chain
    /// survives for `{:#}` and the kind matches the variant's
    /// `AuthError::io_kind`.
    fn from(err: AuthError) -> Self {
        let kind = err.io_kind();
        Self::new(kind, err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One representative `AuthError` per variant, so coverage tests can't miss
    /// a variant. The asserted length is the number of `AuthError` variants.
    fn representative_cases() -> Vec<AuthError> {
        let cases: Vec<AuthError> = vec![
            AuthError::TlsHandshake {
                source: TlsError::Handshake {
                    code: ErrorCode::SSL,
                    io_error_kind: None,
                },
            },
            AuthError::TlsHandshakeTimeout,
            AuthError::ChallengeExport {
                source: ErrorStack::internal_error(io::Error::other("export")),
            },
            AuthError::Timeout,
            AuthError::ConnectionClosed,
            AuthError::Connection {
                source: io::Error::from(io::ErrorKind::ConnectionReset),
            },
            AuthError::Frame(FrameError::UnknownType(0xFF)),
            AuthError::Message(MessageError::DataTooLarge { len: 10, max: 5 }),
            AuthError::Payload(PayloadError::InvalidCipher(0x99)),
        ];
        // 9 variants.
        assert_eq!(
            cases.len(),
            9,
            "representative_cases must cover every AuthError variant"
        );
        // Distinct variants via a HashSet of Discriminant values.
        let distinct: std::collections::HashSet<_> =
            cases.iter().map(std::mem::discriminant).collect();
        assert_eq!(
            distinct.len(),
            cases.len(),
            "representative_cases has duplicate variants"
        );
        cases
    }

    /// Every variant must project to a known `io::ErrorKind` at the boundary,
    /// and the `From<AuthError> for io::Error` conversion must agree with it.
    /// Pins the `io_kind` / `From` mapping so a careless edit is caught loudly.
    ///
    /// Also pins that the typed `AuthError`'s `Display` survives into the
    /// `io::Error`'s message (visible to the `warn!(error = %err)` log at the
    /// binary boundary).
    ///
    /// Note: `io::Error::source()` is NOT asserted here. `io::Error::new(kind,
    /// custom_err)` drops the source for some "simple" kinds (`TimedOut`, etc.)
    /// — a std quirk. What matters for the boundary log is
    /// that the structured `Display` survives in `to_string()`, asserted below.
    /// The typed error already reaches the session/log paths *before* this
    /// boundary conversion (the auth flow returns `Result<_, AuthError>`
    /// internally; only `handle()`/`handle_with_tls()` wrap it for the
    /// `io::Result`-typed binary entry point).
    #[test]
    fn io_kind_and_from_agree_for_every_variant() {
        for err in representative_cases() {
            let expected = err.io_kind();
            // Capture the AuthError Display before the move.
            let auth_display = err.to_string();
            let io_err: io::Error = err.into();
            assert_eq!(
                io_err.kind(),
                expected,
                "io::Error::from(AuthError) kind disagreed with io_kind()"
            );
            assert!(
                matches!(
                    expected,
                    io::ErrorKind::Other
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::InvalidData
                        | io::ErrorKind::ConnectionRefused
                ),
                "unexpected io_kind {expected:?}"
            );
            // The AuthError Display survives in the io::Error message — the
            // boundary log (`warn!(error = %err)`) sees the structured detail.
            let io_display = io_err.to_string();
            assert!(
                io_display.contains(&auth_display) || auth_display.contains(&io_display),
                "io::Error message lost the AuthError display: \
                 auth={auth_display:?} io={io_display:?}"
            );
        }
    }

    /// The structured proto detail must survive the `io::Error` boundary
    /// round-trip and be visible in the `io::Error` message. Specialized to a
    /// proto variant (whose offending byte is the load-bearing structured
    /// value): after `From<AuthError> for io::Error`, the message still carries
    /// "unknown frame type" and the offending byte.
    #[test]
    fn io_error_boundary_preserves_proto_detail() {
        let frame = AuthError::Frame(FrameError::UnknownType(0xAB));
        let io_err: io::Error = frame.into();
        // Kind is derived from the variant at the boundary.
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
        // The message carries the structured proto detail.
        let rendered = io_err.to_string();
        assert!(
            rendered.contains("unknown frame type"),
            "boundary message lost frame detail: {rendered:?}"
        );
        assert!(
            rendered.contains("0xab"),
            "boundary message lost offending byte: {rendered:?}"
        );
    }

    /// Proto decode sources flow to the terminal `{:#}` render with their
    /// structured payload detail intact, and the cause chain survives the
    /// `io::Error` round-trip at the boundary.
    #[test]
    fn proto_sources_are_preserved_in_display() {
        let frame = AuthError::Frame(FrameError::UnknownType(0xAB));
        let rendered = format!("{frame:#}");
        assert!(
            rendered.contains("unknown frame type"),
            "frame: {rendered:?}"
        );
        assert!(rendered.contains("0xab"), "frame: {rendered:?}");

        let msg = AuthError::Message(MessageError::DataTooLarge {
            len: 9999,
            max: 1500,
        });
        let rendered = format!("{msg:#}");
        // `MessageError` is a real `Error` with its own `Display`; the
        // structured lengths survive to the terminal render.
        // (Checking "data payload length" / "1500" too — not just "9999", which
        // a Debug-format rendering would also carry and so is not load-bearing
        // evidence of the `Display`.)
        assert!(
            rendered.contains("data payload length"),
            "msg: {rendered:?}"
        );
        assert!(rendered.contains("9999"), "msg: {rendered:?}");
        assert!(rendered.contains("1500"), "msg: {rendered:?}");

        let payload = AuthError::Payload(PayloadError::InvalidCipher(0x99));
        let rendered = format!("{payload:#}");
        assert!(
            rendered.contains("unknown cipher suite"),
            "payload: {rendered:?}"
        );
        assert!(rendered.contains("0x99"), "payload: {rendered:?}");

        // The boring ErrorStack rides as the source of ChallengeExport.
        let export = AuthError::ChallengeExport {
            source: ErrorStack::internal_error(io::Error::other("export-key")),
        };
        let rendered = format!("{export:#}");
        assert!(
            rendered.contains("keying-material export"),
            "export: {rendered:?}"
        );
    }

    /// Manual `From` impls let the auth call sites use `?` for proto decode
    /// errors.
    #[test]
    fn manual_from_impls_preserve_proto_errors() {
        let msg = MessageError::DataTooLarge { len: 10, max: 5 };
        let err: AuthError = msg.into();
        assert!(matches!(err, AuthError::Message(_)));

        let payload = PayloadError::InvalidCipher(0x99);
        let err: AuthError = payload.into();
        assert!(matches!(err, AuthError::Payload(_)));

        let frame = FrameError::UnknownType(0x01);
        let err: AuthError = frame.into();
        assert!(matches!(err, AuthError::Frame(_)));
    }
}
