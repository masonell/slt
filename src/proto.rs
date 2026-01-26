//! VPN protocol framing and message definitions.

/// Frame header length: 1 byte type + 4 bytes length.
pub const HEADER_LEN: usize = 5;

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
    /// Convert a wire byte into a MessageType, if known.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
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
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A decoded protocol frame referencing the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Frame message type.
    pub ty: MessageType,
    /// Frame payload bytes.
    pub payload: &'a [u8],
}

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

/// Framing errors for encode/decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The type byte is unknown.
    UnknownType(u8),
    /// Frame length exceeds the configured maximum.
    LengthTooLarge { len: usize, max: usize },
    /// Payload length does not fit in the u32 length field.
    LengthOverflow(usize),
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

/// Decode a single frame from the provided buffer.
///
/// Returns `Ok(None)` if the buffer does not yet contain a full frame.
pub fn decode_frame(
    buf: &'_ [u8],
    max_len: usize,
) -> Result<Option<(Frame<'_>, usize)>, FrameError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }

    let ty = MessageType::from_u8(buf[0]).ok_or(FrameError::UnknownType(buf[0]))?;
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > max_len {
        return Err(FrameError::LengthTooLarge { len, max: max_len });
    }

    let total_len = HEADER_LEN + len;
    if buf.len() < total_len {
        return Ok(None);
    }

    Ok(Some((
        Frame {
            ty,
            payload: &buf[HEADER_LEN..total_len],
        },
        total_len,
    )))
}

/// Encode a frame into the provided output buffer.
pub fn encode_frame(ty: MessageType, payload: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    let len = payload.len();
    if len > u32::MAX as usize {
        return Err(FrameError::LengthOverflow(len));
    }

    out.reserve(HEADER_LEN + len);
    out.push(ty.as_u8());
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
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
    fn decode_roundtrip_frame() {
        let payload = b"hello";
        let mut buf = Vec::new();
        encode_frame(MessageType::Ping, payload, &mut buf).unwrap();

        let (frame, consumed) = decode_frame(&buf, 1024).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(frame.ty, MessageType::Ping);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn decode_incomplete_header() {
        let buf = [MessageType::Auth.as_u8(), 0x00];
        assert!(decode_frame(&buf, 1024).unwrap().is_none());
    }

    #[test]
    fn decode_incomplete_payload() {
        let buf = [
            MessageType::Auth.as_u8(),
            0x00,
            0x00,
            0x00,
            0x05,
            0x01,
            0x02,
        ];
        assert!(decode_frame(&buf, 1024).unwrap().is_none());
    }

    #[test]
    fn decode_unknown_type() {
        let buf = [0xff, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode_frame(&buf, 1024), Err(FrameError::UnknownType(0xff)));
    }

    #[test]
    fn decode_length_too_large() {
        let buf = [MessageType::Auth.as_u8(), 0x00, 0x00, 0x10, 0x00];
        assert_eq!(
            decode_frame(&buf, 1024),
            Err(FrameError::LengthTooLarge {
                len: 4096,
                max: 1024
            })
        );
    }

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
