//! Session event and control types.

use std::io;

use slt_core::proto::{CloseCode, OwnedMessageBuf};

use super::quic;

/// Session termination reason used by the runtime to decide reconnect behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExit {
    Shutdown,
    TcpClosed,
    TunClosed,
    IdleTimeout,
    RemoteClose(CloseCode),
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
    Continue,
    Close,
}
