use std::io::{self, ErrorKind};

use slt_core::proto::AuthFailCode;

/// Result of an authentication operation with explicit failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthPhaseResult {
    /// Authentication completed successfully.
    Success,
    /// Authentication failed with a specific code.
    Failed(AuthFailCode),
    /// Operation timed out.
    Timeout,
    /// Connection was closed by peer.
    ConnectionClosed,
}

impl AuthPhaseResult {
    /// Converts the auth result to an IO result.
    ///
    /// Returns `Ok(())` for success, appropriate `io::Error` for failures.
    pub(super) fn into_io_result(self) -> io::Result<()> {
        match self {
            Self::Success => Ok(()),
            Self::Failed(code) => Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!("auth failed: {code:?}"),
            )),
            Self::Timeout => Err(io::Error::new(ErrorKind::TimedOut, "auth timed out")),
            Self::ConnectionClosed => Err(io::Error::new(
                ErrorKind::ConnectionReset,
                "connection closed",
            )),
        }
    }

    /// Returns true if this result indicates a failure.
    pub(super) const fn is_failure(self) -> bool {
        matches!(
            self,
            Self::Failed(_) | Self::Timeout | Self::ConnectionClosed
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthStep {
    Continue,
    Done,
}
