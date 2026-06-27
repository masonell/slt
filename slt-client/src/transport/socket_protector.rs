//! Platform hook for excluding SLT transport sockets from VPN routing.

use std::io;
#[cfg(unix)]
use std::os::fd::RawFd;
use std::sync::Arc;

/// Transport socket type passed to [`SocketProtector`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_os = "android", derive(uniffi::Enum))]
pub enum SocketKind {
    /// TCP control/data socket.
    Tcp,
    /// UDP discovery / UDP-QSP socket.
    Udp,
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

/// Shared socket protector handle used by the client runtime.
pub type SharedSocketProtector = Arc<dyn SocketProtector>;

/// Socket protector that leaves sockets unchanged.
#[derive(Debug, Default)]
pub struct NoopSocketProtector;

impl SocketProtector for NoopSocketProtector {
    #[cfg(unix)]
    fn protect(&self, _fd: RawFd, _kind: SocketKind) -> io::Result<()> {
        Ok(())
    }
}

/// Construct a shared no-op socket protector.
#[must_use]
pub fn noop_socket_protector() -> SharedSocketProtector {
    Arc::new(NoopSocketProtector)
}
