use std::io::{self, ErrorKind};

use slt_core::proto::AuthFailCode;

/// Result of an authentication operation with explicit failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthPhaseResult {
    /// Authentication completed and a client session was created.
    Authenticated,
    /// Authentication phase ended without creating a session (for example, CLOSE).
    Completed,
    /// Authentication was rejected but handled on-protocol (`AUTH_FAIL` sent).
    Rejected(AuthFailCode),
    /// Authentication failed with a specific code.
    Failed(AuthFailCode),
    /// Operation timed out.
    Timeout,
    /// Connection was closed by peer.
    ConnectionClosed,
    /// TLS handshake failed.
    TlsHandshakeFailed,
    /// TLS handshake timed out.
    TlsHandshakeTimeout,
}

impl AuthPhaseResult {
    /// Converts the auth result to an IO result.
    ///
    /// Returns `Ok(())` for handled outcomes, appropriate `io::Error` for failures.
    pub(super) fn into_io_result(self) -> io::Result<()> {
        match self {
            Self::Authenticated | Self::Completed | Self::Rejected(_) => Ok(()),
            Self::Failed(code) => Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!("auth failed: {code:?}"),
            )),
            Self::Timeout => Err(io::Error::new(ErrorKind::TimedOut, "auth timed out")),
            Self::ConnectionClosed => Err(io::Error::new(
                ErrorKind::ConnectionReset,
                "connection closed",
            )),
            Self::TlsHandshakeFailed => Err(io::Error::other("tls handshake failed")),
            Self::TlsHandshakeTimeout => Err(io::Error::new(
                ErrorKind::TimedOut,
                "tls handshake timed out",
            )),
        }
    }

    /// Returns true if this result indicates a failure.
    pub(super) const fn is_failure(self) -> bool {
        matches!(
            self,
            Self::Rejected(_)
                | Self::Failed(_)
                | Self::Timeout
                | Self::ConnectionClosed
                | Self::TlsHandshakeFailed
                | Self::TlsHandshakeTimeout
        )
    }

    /// Returns true if this result indicates a successful authentication.
    pub(super) const fn is_authenticated(self) -> bool {
        matches!(self, Self::Authenticated)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthStep {
    Continue,
    Done(AuthPhaseResult),
}
