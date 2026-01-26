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
}
