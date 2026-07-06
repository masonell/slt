use super::framing::{Frame, FrameError, decode_frame, encode_frame};
use super::payloads::MAX_CONTROL_FRAME_LEN;
use super::types::MessageType;

/// Application-layer message with a payload view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message<'a> {
    /// Client authentication request.
    Auth { payload: &'a [u8] },
    /// Authentication accepted.
    AuthOk { payload: &'a [u8] },
    /// Authentication rejected.
    AuthFail { payload: &'a [u8] },
    /// Register a UDP-QSP CID and keys.
    RegisterCid { payload: &'a [u8] },
    /// CID registration accepted.
    RegisterOk { payload: &'a [u8] },
    /// CID registration rejected.
    RegisterFail { payload: &'a [u8] },
    /// Keepalive ping.
    Ping { payload: &'a [u8] },
    /// Keepalive pong.
    Pong { payload: &'a [u8] },
    /// Close the session.
    Close { payload: &'a [u8] },
    /// Tunnel data (raw IP packet).
    Data { packet: &'a [u8] },
    /// UDP path validation probe during upgrade.
    UpgradeProbe { payload: &'a [u8] },
    /// UDP path validation probe acknowledgement.
    UpgradeProbeAck { payload: &'a [u8] },
    /// Client indicates UDP path is validated.
    UdpReady { payload: &'a [u8] },
    /// Server commits transport switch to UDP.
    SwitchToUdp { payload: &'a [u8] },
    /// Client acknowledges server's switch commit.
    SwitchAck { payload: &'a [u8] },
}

impl<'a> Message<'a> {
    /// Returns the message type.
    #[must_use]
    pub const fn ty(&self) -> MessageType {
        match self {
            Message::Auth { .. } => MessageType::Auth,
            Message::AuthOk { .. } => MessageType::AuthOk,
            Message::AuthFail { .. } => MessageType::AuthFail,
            Message::RegisterCid { .. } => MessageType::RegisterCid,
            Message::RegisterOk { .. } => MessageType::RegisterOk,
            Message::RegisterFail { .. } => MessageType::RegisterFail,
            Message::Ping { .. } => MessageType::Ping,
            Message::Pong { .. } => MessageType::Pong,
            Message::Close { .. } => MessageType::Close,
            Message::Data { .. } => MessageType::Data,
            Message::UpgradeProbe { .. } => MessageType::UpgradeProbe,
            Message::UpgradeProbeAck { .. } => MessageType::UpgradeProbeAck,
            Message::UdpReady { .. } => MessageType::UdpReady,
            Message::SwitchToUdp { .. } => MessageType::SwitchToUdp,
            Message::SwitchAck { .. } => MessageType::SwitchAck,
        }
    }

    /// Returns the payload bytes (or packet bytes for DATA).
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        match self {
            Message::Data { packet } => packet,
            Message::Auth { payload }
            | Message::AuthOk { payload }
            | Message::AuthFail { payload }
            | Message::RegisterCid { payload }
            | Message::RegisterOk { payload }
            | Message::RegisterFail { payload }
            | Message::Ping { payload }
            | Message::Pong { payload }
            | Message::Close { payload }
            | Message::UpgradeProbe { payload }
            | Message::UpgradeProbeAck { payload }
            | Message::UdpReady { payload }
            | Message::SwitchToUdp { payload }
            | Message::SwitchAck { payload } => payload,
        }
    }
}

impl<'a> From<Frame<'a>> for Message<'a> {
    fn from(frame: Frame<'a>) -> Self {
        match frame.ty {
            MessageType::Auth => Message::Auth {
                payload: frame.payload,
            },
            MessageType::AuthOk => Message::AuthOk {
                payload: frame.payload,
            },
            MessageType::AuthFail => Message::AuthFail {
                payload: frame.payload,
            },
            MessageType::RegisterCid => Message::RegisterCid {
                payload: frame.payload,
            },
            MessageType::RegisterOk => Message::RegisterOk {
                payload: frame.payload,
            },
            MessageType::RegisterFail => Message::RegisterFail {
                payload: frame.payload,
            },
            MessageType::Ping => Message::Ping {
                payload: frame.payload,
            },
            MessageType::Pong => Message::Pong {
                payload: frame.payload,
            },
            MessageType::Close => Message::Close {
                payload: frame.payload,
            },
            MessageType::Data => Message::Data {
                packet: frame.payload,
            },
            MessageType::UpgradeProbe => Message::UpgradeProbe {
                payload: frame.payload,
            },
            MessageType::UpgradeProbeAck => Message::UpgradeProbeAck {
                payload: frame.payload,
            },
            MessageType::UdpReady => Message::UdpReady {
                payload: frame.payload,
            },
            MessageType::SwitchToUdp => Message::SwitchToUdp {
                payload: frame.payload,
            },
            MessageType::SwitchAck => Message::SwitchAck {
                payload: frame.payload,
            },
        }
    }
}

impl<'a> From<Message<'a>> for Frame<'a> {
    fn from(message: Message<'a>) -> Self {
        Frame {
            ty: message.ty(),
            payload: message.payload(),
        }
    }
}

/// Bounds used when decoding protocol messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageLimits {
    /// Maximum frame payload length to accept.
    pub max_frame_len: usize,
    /// Maximum data payload length to accept for `DATA` messages.
    pub max_data_len: usize,
}

impl MessageLimits {
    /// Create message limits for a decoding context.
    #[must_use]
    pub const fn new(max_frame_len: usize, max_data_len: usize) -> Self {
        Self {
            max_frame_len,
            max_data_len,
        }
    }

    /// Compute message size limits based on TUN MTU.
    ///
    /// The frame buffer must accommodate the largest possible message, which is
    /// either a DATA packet (up to MTU bytes) or a control frame.
    #[must_use]
    pub fn from_mtu(mtu: u16) -> Self {
        let max_data_len = mtu as usize;
        let max_frame_len = max_data_len.max(MAX_CONTROL_FRAME_LEN);
        Self::new(max_frame_len, max_data_len)
    }
}

/// Message-level errors for encode/decode.
///
/// This is a real [`std::error::Error`] type (it derives [`thiserror::Error`])
/// so downstream layers can preserve it via `#[from]` rather than flattening it
/// into an `io::Error`. It stays `Copy` — callers rely on that, and `thiserror`
/// is compatible with `Copy` enums as long as every field is `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    /// Framing error while decoding.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// `DATA` payload length exceeds the allowed maximum.
    #[error("data payload length {len} exceeds maximum {max}")]
    DataTooLarge {
        /// Actual payload length decoded from the frame.
        len: usize,
        /// Configured maximum payload length for `DATA` messages.
        max: usize,
    },
}

/// Decode a single message from the provided buffer.
///
/// Returns `Ok(None)` if the buffer does not yet contain a full frame.
///
/// # Errors
///
/// Returns an error if:
/// - Frame decoding fails (see `decode_frame`)
/// - The message is DATA and payload exceeds `max_data_len`
pub fn decode_message(
    buf: &'_ [u8],
    limits: MessageLimits,
) -> Result<Option<(Message<'_>, usize)>, MessageError> {
    let Some((frame, consumed)) = decode_frame(buf, limits.max_frame_len)? else {
        return Ok(None);
    };

    if frame.ty == MessageType::Data && frame.payload.len() > limits.max_data_len {
        return Err(MessageError::DataTooLarge {
            len: frame.payload.len(),
            max: limits.max_data_len,
        });
    }

    Ok(Some((Message::from(frame), consumed)))
}

/// Encode a message into the provided output buffer.
///
/// # Errors
///
/// Propagates errors from `encode_frame` (e.g., payload length overflow).
pub fn encode_message(message: Message<'_>, out: &mut Vec<u8>) -> Result<(), FrameError> {
    encode_frame(message.ty(), message.payload(), out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(message: Message<'_>) {
        let mut buf = Vec::new();
        encode_message(message, &mut buf).unwrap();

        let limits = MessageLimits::new(1024, 1024);
        let (decoded, consumed) = decode_message(&buf, limits).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded, message);
    }

    #[test]
    fn ping_roundtrip() {
        roundtrip(Message::Ping { payload: b"ping" });
    }

    #[test]
    fn auth_roundtrip() {
        roundtrip(Message::Auth {
            payload: b"auth_payload",
        });
    }

    #[test]
    fn auth_ok_roundtrip() {
        roundtrip(Message::AuthOk {
            payload: b"auth_ok_payload",
        });
    }

    #[test]
    fn auth_fail_roundtrip() {
        roundtrip(Message::AuthFail {
            payload: b"auth_fail_payload",
        });
    }

    #[test]
    fn register_cid_roundtrip() {
        roundtrip(Message::RegisterCid {
            payload: b"register_cid_payload",
        });
    }

    #[test]
    fn register_ok_roundtrip() {
        roundtrip(Message::RegisterOk {
            payload: b"register_ok_payload",
        });
    }

    #[test]
    fn register_fail_roundtrip() {
        roundtrip(Message::RegisterFail {
            payload: b"register_fail_payload",
        });
    }

    #[test]
    fn pong_roundtrip() {
        roundtrip(Message::Pong { payload: b"pong" });
    }

    #[test]
    fn close_roundtrip() {
        roundtrip(Message::Close {
            payload: b"close_payload",
        });
    }

    #[test]
    fn upgrade_probe_roundtrip() {
        roundtrip(Message::UpgradeProbe {
            payload: b"upgrade_probe_payload",
        });
    }

    #[test]
    fn upgrade_probe_ack_roundtrip() {
        roundtrip(Message::UpgradeProbeAck {
            payload: b"upgrade_probe_ack_payload",
        });
    }

    #[test]
    fn udp_ready_roundtrip() {
        roundtrip(Message::UdpReady {
            payload: b"udp_ready_payload",
        });
    }

    #[test]
    fn switch_to_udp_roundtrip() {
        roundtrip(Message::SwitchToUdp {
            payload: b"switch_to_udp_payload",
        });
    }

    #[test]
    fn switch_ack_roundtrip() {
        roundtrip(Message::SwitchAck {
            payload: b"switch_ack_payload",
        });
    }

    #[test]
    fn data_roundtrip() {
        roundtrip(Message::Data {
            packet: b"ip_packet_data",
        });
    }

    #[test]
    fn decode_message_data_too_large() {
        let payload = [0u8; 16];
        let message = Message::Data { packet: &payload };
        let mut buf = Vec::new();
        encode_message(message, &mut buf).unwrap();

        let limits = MessageLimits::new(1024, 8);
        assert_eq!(
            decode_message(&buf, limits),
            Err(MessageError::DataTooLarge { len: 16, max: 8 })
        );
    }

    /// `MessageError` is a real `std::error::Error` and its `Frame` variant
    /// converts from `FrameError` via `#[from]`. Pins the conversion and the
    /// `Display` shape so downstream `#[from]` propagation stays valid and the
    /// structured detail reaches the terminal.
    #[test]
    fn frame_error_converts_to_message_error_via_from() {
        let frame_err = FrameError::UnknownType(0xAB);
        let err: MessageError = frame_err.into();
        assert!(
            matches!(err, MessageError::Frame(FrameError::UnknownType(0xAB))),
            "From<FrameError> must produce MessageError::Frame, got {err:?}"
        );
        // MessageError is an Error: its own Display carries the structured
        // detail (the variant is #[error(transparent)], so it delegates to
        // FrameError's Display). The structured values survive to the terminal
        // {:#} render — the property the design requires ("preserve, don't
        // stringify").
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("unknown frame type"),
            "MessageError Display must carry the frame detail: {rendered:?}"
        );
        assert!(
            rendered.contains("0xab"),
            "MessageError Display must carry the offending byte: {rendered:?}"
        );
        // Note: `source()` is intentionally `None` here. thiserror forbids
        // combining `#[error(transparent)]` with `#[source]` on the same
        // variant ("transparent variant can't contain #[source]"), so a
        // transparent `Copy` variant exposes its inner value via `Display`
        // only — not via the `source()` chain. The structured detail still
        // reaches logs/UI through `{:#}`, which is the load-bearing contract;
        // do NOT "fix" this by adding `#[source]`.
        assert!(
            std::error::Error::source(&err).is_none(),
            "transparent MessageError::Frame must not expose a source (thiserror rule)"
        );
    }

    #[test]
    fn message_limits_from_mtu_zero() {
        let limits = MessageLimits::from_mtu(0);
        assert_eq!(limits.max_data_len, 0);
        // max_frame_len should be at least MAX_CONTROL_FRAME_LEN
        assert!(limits.max_frame_len >= MAX_CONTROL_FRAME_LEN);
    }

    #[test]
    fn message_limits_from_mtu_one() {
        let limits = MessageLimits::from_mtu(1);
        assert_eq!(limits.max_data_len, 1);
        // max_frame_len should be at least MAX_CONTROL_FRAME_LEN
        assert!(limits.max_frame_len >= MAX_CONTROL_FRAME_LEN);
    }

    #[test]
    fn message_limits_from_mtu_max() {
        let limits = MessageLimits::from_mtu(65535);
        assert_eq!(limits.max_data_len, 65535);
        assert_eq!(limits.max_frame_len, 65535);
    }

    #[test]
    fn message_limits_from_mtu_default() {
        let default_mtu: u16 = 1500;
        let limits = MessageLimits::from_mtu(default_mtu);
        assert_eq!(limits.max_data_len, 1500);
        // max_frame_len should be at least MAX_CONTROL_FRAME_LEN
        assert!(limits.max_frame_len >= MAX_CONTROL_FRAME_LEN);
    }
}
