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
            | Message::Close { payload } => payload,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// Framing error while decoding.
    Frame(FrameError),
    /// `DATA` payload length exceeds the allowed maximum.
    DataTooLarge { len: usize, max: usize },
}

impl From<FrameError> for MessageError {
    fn from(err: FrameError) -> Self {
        Self::Frame(err)
    }
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
