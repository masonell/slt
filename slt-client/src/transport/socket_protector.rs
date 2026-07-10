//! Platform hook for excluding SLT transport sockets from VPN routing.

use std::io;
#[cfg(unix)]
use std::os::fd::RawFd;

/// Transport socket type passed to [`SocketProtector`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_os = "android", derive(uniffi::Enum))]
pub enum SocketKind {
    /// TCP control/data socket.
    Tcp,
    /// UDP discovery / UDP-QSP socket.
    Udp,
}

/// Result of protecting a transport socket and binding it to a platform path.
///
/// Android returns this through the `UniFFI` platform callback so the runtime
/// can distinguish transient network availability from local permission or
/// platform failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_os = "android", derive(uniffi::Enum))]
#[cfg(any(target_os = "android", test))]
pub enum SocketProtectionResult {
    /// The socket is protected and bound to an underlying network.
    Protected,
    /// The platform rejected the request to exclude the socket from the VPN.
    ProtectRejected,
    /// No usable underlying network is currently available.
    NoUnderlyingNetwork,
    /// Binding to the selected underlying network failed.
    BindFailed,
    /// Socket setup failed outside the underlying-network bind operation.
    PlatformFailure,
}

#[cfg(any(target_os = "android", test))]
impl SocketProtectionResult {
    /// Convert the platform callback result into the transport hook contract.
    #[cfg(unix)]
    pub(crate) fn into_io_result(self, fd: RawFd, kind: SocketKind) -> io::Result<()> {
        let (error_kind, detail) = match self {
            Self::Protected => return Ok(()),
            Self::ProtectRejected => (
                io::ErrorKind::PermissionDenied,
                "platform rejected socket protection",
            ),
            Self::NoUnderlyingNetwork => (
                io::ErrorKind::NotConnected,
                "no underlying network is available for socket binding",
            ),
            Self::BindFailed => (
                io::ErrorKind::NetworkUnreachable,
                "failed to bind socket to the underlying network",
            ),
            Self::PlatformFailure => (
                io::ErrorKind::Other,
                "platform socket setup callback failed",
            ),
        };
        Err(io::Error::new(
            error_kind,
            format!("{detail}: kind={kind:?} fd={fd}"),
        ))
    }
}

/// Platform hook called after socket creation and before socket use.
///
/// Android implementations must call `VpnService.protect(fd)` so SLT's own
/// TCP/UDP traffic bypasses the VPN interface. Desktop implementations usually
/// use [`NoopSocketProtector`].
pub trait SocketProtector: Send + Sync {
    /// Protect `fd` from VPN routing.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform rejects or cannot apply protection.
    #[cfg(unix)]
    fn protect(&self, fd: RawFd, kind: SocketKind) -> io::Result<()>;
}

/// Socket protector that leaves sockets unchanged.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSocketProtector;

impl SocketProtector for NoopSocketProtector {
    #[cfg(unix)]
    fn protect(&self, _fd: RawFd, _kind: SocketKind) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_results_preserve_socket_setup_failure_kind() {
        let cases = [
            (
                SocketProtectionResult::ProtectRejected,
                io::ErrorKind::PermissionDenied,
            ),
            (
                SocketProtectionResult::NoUnderlyingNetwork,
                io::ErrorKind::NotConnected,
            ),
            (
                SocketProtectionResult::BindFailed,
                io::ErrorKind::NetworkUnreachable,
            ),
            (
                SocketProtectionResult::PlatformFailure,
                io::ErrorKind::Other,
            ),
        ];

        assert!(
            SocketProtectionResult::Protected
                .into_io_result(3, SocketKind::Tcp)
                .is_ok()
        );
        for (result, expected_kind) in cases {
            let error = result
                .into_io_result(3, SocketKind::Tcp)
                .expect_err("failure result must produce an I/O error");
            assert_eq!(error.kind(), expected_kind);
        }
    }
}
