use super::message::Message;
use super::types::MessageType;

/// Frame header length: 1 byte type + 4 bytes length.
pub const HEADER_LEN: usize = 5;

/// A decoded protocol frame referencing the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Frame message type.
    pub ty: MessageType,
    /// Frame payload bytes.
    pub payload: &'a [u8],
}

/// An owned protocol frame buffer that can be reborrowed as a decoded `Message`.
#[derive(Debug)]
pub struct OwnedMessageBuf {
    ty: MessageType,
    buf: Vec<u8>,
}

impl OwnedMessageBuf {
    /// Create an owned message buffer from a frame type and full frame bytes.
    ///
    /// `buf` must contain the 5-byte header plus payload bytes.
    #[must_use]
    pub const fn new(ty: MessageType, buf: Vec<u8>) -> Self {
        Self { ty, buf }
    }

    /// Returns a decoded `Message` view into the owned frame buffer.
    #[must_use]
    pub fn message(&self) -> Message<'_> {
        debug_assert!(self.buf.len() >= HEADER_LEN);
        let payload = &self.buf[HEADER_LEN..];
        Message::from(Frame {
            ty: self.ty,
            payload,
        })
    }
}

/// Framing errors for encode/decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The type byte is unknown.
    #[error("unknown frame type: {0:#02x}")]
    UnknownType(u8),
    /// Frame length exceeds the configured maximum.
    #[error("frame length {len} exceeds maximum {max}")]
    LengthTooLarge {
        /// Frame length from header.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// Payload length does not fit in the u32 length field.
    #[error("payload length {0} overflows u32")]
    LengthOverflow(usize),
}

/// Decode a single frame from the provided buffer.
///
/// Returns `Ok(None)` if the buffer does not yet contain a full frame.
///
/// # Errors
///
/// Returns an error if:
/// - The message type byte is unknown
/// - The payload length exceeds `max_len`
pub fn decode_frame(
    buf: &'_ [u8],
    max_len: usize,
) -> Result<Option<(Frame<'_>, usize)>, FrameError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }

    let ty = MessageType::try_from(buf[0]).map_err(|_| FrameError::UnknownType(buf[0]))?;
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
///
/// # Errors
///
/// Returns `FrameError::LengthOverflow` if the payload length exceeds `u32::MAX`.
pub fn encode_frame(ty: MessageType, payload: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    let len = payload.len();
    let len_u32 = u32::try_from(len).map_err(|_| FrameError::LengthOverflow(len))?;

    out.reserve(HEADER_LEN + len);
    out.push(u8::from(ty));
    out.extend_from_slice(&len_u32.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
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
        let buf = [u8::from(MessageType::Auth), 0x00];
        assert!(decode_frame(&buf, 1024).unwrap().is_none());
    }

    #[test]
    fn decode_incomplete_payload() {
        let buf = [
            u8::from(MessageType::Auth),
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
        let buf = [u8::from(MessageType::Auth), 0x00, 0x00, 0x10, 0x00];
        assert_eq!(
            decode_frame(&buf, 1024),
            Err(FrameError::LengthTooLarge {
                len: 4096,
                max: 1024
            })
        );
    }
}
