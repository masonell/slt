use super::framing::{Frame, FrameError, decode_frame, encode_frame};
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
    pub fn ty(&self) -> MessageType {
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
    pub fn payload(&self) -> &'a [u8] {
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
    pub fn new(max_frame_len: usize, max_data_len: usize) -> Self {
        Self {
            max_frame_len,
            max_data_len,
        }
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
pub fn decode_message(
    buf: &'_ [u8],
    limits: MessageLimits,
) -> Result<Option<(Message<'_>, usize)>, MessageError> {
    let (frame, consumed) = match decode_frame(buf, limits.max_frame_len)? {
        Some(frame) => frame,
        None => return Ok(None),
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
pub fn encode_message(message: Message<'_>, out: &mut Vec<u8>) -> Result<(), FrameError> {
    encode_frame(message.ty(), message.payload(), out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_roundtrip_message() {
        let payload = b"ping";
        let message = Message::Ping { payload };
        let mut buf = Vec::new();
        encode_message(message, &mut buf).unwrap();

        let limits = MessageLimits::new(1024, 1024);
        let (decoded, consumed) = decode_message(&buf, limits).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded, message);
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
}
