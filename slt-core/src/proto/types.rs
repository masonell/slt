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
    /// UDP path validation probe during upgrade.
    UpgradeProbe = 0x0b,
    /// UDP path validation probe acknowledgement.
    UpgradeProbeAck = 0x0c,
    /// Client indicates UDP path is validated.
    UdpReady = 0x0d,
    /// Server requests transport switch to UDP.
    SwitchToUdp = 0x0e,
    /// Client accepts the server's UDP switch request.
    SwitchAck = 0x0f,
    /// Request that both peers prefer TCP for outbound traffic.
    FallbackToTcp = 0x10,
    /// Acknowledge a TCP fallback request.
    FallbackOk = 0x11,
    /// Server confirms the UDP switch acknowledgement was processed.
    SwitchOk = 0x12,
}
