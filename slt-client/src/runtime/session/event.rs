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
///
/// These events represent all possible inputs to the session state machine,
/// including I/O events, timer expirations, and control signals.
pub(super) enum SessionEvent {
    /// Shutdown requested via cancellation token.
    Shutdown,
    /// TCP read completed with byte count (0 means connection closed).
    TcpRead(usize),
    /// TUN packet received (None means channel closed).
    TunPacket(Option<Vec<u8>>),
    /// UDP-QSP message read result.
    UdpResult(io::Result<OwnedMessageBuf>),
    /// Ping timer expired.
    PingTick,
    /// Idle timeout expired.
    IdleTimeout,
    /// UDP reconnect timer expired.
    UdpReconnectTick,
    /// Registration timeout expired.
    RegisterTimeout,
    /// QUIC discovery task completed.
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

#[cfg(test)]
mod tests {
    use super::*;

    mod session_exit {
        use super::*;

        #[test]
        fn variants_are_debug_clone_copy() {
            let shutdown = SessionExit::Shutdown;
            let _shutdown_copy: SessionExit = shutdown;
            assert!(format!("{shutdown:?}").contains("Shutdown"));
        }

        #[test]
        fn shutdown_is_shutdown() {
            assert_eq!(SessionExit::Shutdown, SessionExit::Shutdown);
        }

        #[test]
        fn tcp_closed_is_tcp_closed() {
            assert_eq!(SessionExit::TcpClosed, SessionExit::TcpClosed);
        }

        #[test]
        fn tun_closed_is_tun_closed() {
            assert_eq!(SessionExit::TunClosed, SessionExit::TunClosed);
        }

        #[test]
        fn idle_timeout_is_idle_timeout() {
            assert_eq!(SessionExit::IdleTimeout, SessionExit::IdleTimeout);
        }

        #[test]
        fn remote_close_carries_close_code() {
            use slt_core::proto::CloseCode;

            let close = SessionExit::RemoteClose(CloseCode::Normal);
            assert_eq!(close, SessionExit::RemoteClose(CloseCode::Normal));
            assert_ne!(close, SessionExit::RemoteClose(CloseCode::ProtocolError));
        }

        #[test]
        fn protocol_error_is_protocol_error() {
            assert_eq!(SessionExit::ProtocolError, SessionExit::ProtocolError);
        }

        #[test]
        fn permission_denied_is_permission_denied() {
            assert_eq!(SessionExit::PermissionDenied, SessionExit::PermissionDenied);
        }

        #[test]
        fn connection_error_is_connection_error() {
            assert_eq!(SessionExit::ConnectionError, SessionExit::ConnectionError);
        }

        #[test]
        fn different_variants_are_not_equal() {
            assert_ne!(SessionExit::Shutdown, SessionExit::TcpClosed);
            assert_ne!(SessionExit::TcpClosed, SessionExit::TunClosed);
            assert_ne!(SessionExit::IdleTimeout, SessionExit::ProtocolError);
        }
    }

    mod session_control {
        use super::*;

        #[test]
        fn continue_is_continue() {
            assert_eq!(SessionControl::Continue, SessionControl::Continue);
        }

        #[test]
        fn close_carries_session_exit() {
            let control = SessionControl::Close(SessionExit::Shutdown);
            assert_eq!(control, SessionControl::Close(SessionExit::Shutdown));
            assert_ne!(control, SessionControl::Close(SessionExit::TcpClosed));
        }

        #[test]
        fn continue_is_not_close() {
            assert_ne!(
                SessionControl::Continue,
                SessionControl::Close(SessionExit::Shutdown)
            );
        }

        #[test]
        fn variants_are_debug_clone_copy() {
            let control = SessionControl::Continue;
            let _control_copy: SessionControl = control;
            assert!(format!("{control:?}").contains("Continue"));
        }
    }
}
