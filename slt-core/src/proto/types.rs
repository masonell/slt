use num_enum::{IntoPrimitive, TryFromPrimitive};

/// Wire message types for the VPN protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum MessageType {
    /// Client authentication request.
    Auth = 0x01,
    /// Authentication accepted.
    AuthOk = 0x02,
    /// Authentication rejected.
    AuthFail = 0x03,
    /// Register a UDP-QSP CID and keys.
    RegisterCid = 0x04,
    /// CID registration accepted.
    RegisterOk = 0x05,
    /// CID registration rejected.
    RegisterFail = 0x06,
    /// Keepalive ping.
    Ping = 0x07,
    /// Keepalive pong.
    Pong = 0x08,
    /// Close the session.
    Close = 0x09,
    /// Tunnel data (raw IP packet).
    Data = 0x0a,
}
