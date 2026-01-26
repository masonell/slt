/// Wire message types for the VPN protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl MessageType {
    /// Convert a wire byte into a `MessageType`, if known.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Auth),
            0x02 => Some(Self::AuthOk),
            0x03 => Some(Self::AuthFail),
            0x04 => Some(Self::RegisterCid),
            0x05 => Some(Self::RegisterOk),
            0x06 => Some(Self::RegisterFail),
            0x07 => Some(Self::Ping),
            0x08 => Some(Self::Pong),
            0x09 => Some(Self::Close),
            0x0a => Some(Self::Data),
            _ => None,
        }
    }

    /// Return the wire byte for this message type.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}
