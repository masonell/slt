//! Session event and control types.

use std::io;

use slt_core::proto::{CloseCode, OwnedMessageBuf};

use super::quic;

/// Session termination reason used by the runtime to decide reconnect behavior.
///
/// The runtime uses these variants to determine whether to reconnect, exit cleanly,
/// or fail fatally. See [`handle_session_exit`](crate::runtime::handle_session_exit)
/// for the mapping from exit reasons to actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExit {
    /// User requested shutdown via cancellation token.
    ///
    /// Runtime action: exit cleanly without reconnect.
    Shutdown,

    /// TCP connection closed by peer (read returned 0 bytes).
    ///
    /// Runtime action: reconnect.
    TcpClosed,

    /// TUN interface closed (channel sender dropped).
    ///
    /// Runtime action: exit cleanly without reconnect (VPN interface gone).
    TunClosed,

    /// No activity received within the configured idle timeout.
    ///
    /// Runtime action: reconnect.
    IdleTimeout,

    /// Server sent an explicit CLOSE frame.
    ///
    /// Runtime action: reconnect (server-initiated close).
    RemoteClose(CloseCode),

    /// Protocol violation: malformed message, decode failure, or unexpected message.
    ///
    /// Indicates a potential version mismatch or corrupted data.
    ///
    /// Runtime action: fatal exit (don't reconnect).
    ProtocolError,

    /// Permission denied by local OS/network policy.
    ///
    /// Runtime action: fatal exit (don't reconnect).
    PermissionDenied,

    /// Network-level I/O error on TCP connection.
    ///
    /// Runtime action: reconnect (transient network issue).
    ConnectionError,
}

/// Events polled by the session event loop.
pub(super) enum SessionEvent {
    Shutdown,
    TcpRead(usize),
    TunPacket(Option<Vec<u8>>),
    UdpResult(io::Result<OwnedMessageBuf>),
    PingTick,
    IdleTimeout,
    UdpReconnectTick,
    RegisterTimeout,
    DiscoveryResult(Option<quic::QuicIds>),
}

/// Control flow decision after handling an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionControl {
    /// Continue processing events.
    Continue,
    /// Close the session with the specified exit reason.
    Close(SessionExit),
}
