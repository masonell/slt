use slt_core::proto::{FrameError, MessageError, MessageLimits, MessageType, PayloadError};
use std::io;

/// An owned protocol frame buffer that can be reborrowed as a decoded `Message`.
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
    pub fn message(&self) -> slt_core::proto::Message<'_> {
        debug_assert!(self.buf.len() >= slt_core::proto::HEADER_LEN);
        let payload = &self.buf[slt_core::proto::HEADER_LEN..];
        slt_core::proto::Message::from(slt_core::proto::Frame {
            ty: self.ty,
            payload,
        })
    }
}

/// Pops the next full frame from `read_buf`, if present, and returns it as an owned buffer.
///
/// The returned buffer contains the full frame bytes (header plus payload), and enforces the
/// configured `DATA` size limit before removing bytes from `read_buf`.
pub fn pop_message_buf(
    read_buf: &mut Vec<u8>,
    limits: MessageLimits,
) -> Result<Option<OwnedMessageBuf>, MessageError> {
    let Some((frame, consumed)) = slt_core::proto::decode_frame(read_buf, limits.max_frame_len)?
    else {
        return Ok(None);
    };

    if frame.ty == MessageType::Data && frame.payload.len() > limits.max_data_len {
        return Err(MessageError::DataTooLarge {
            len: frame.payload.len(),
            max: limits.max_data_len,
        });
    }

    let ty = frame.ty;
    let rest = read_buf.split_off(consumed);
    let buf = std::mem::replace(read_buf, rest);
    Ok(Some(OwnedMessageBuf { ty, buf }))
}

/// Map a protocol framing error into an `io::Error`.
pub fn map_frame_error(err: FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("frame error: {err:?}"))
}

/// Map a protocol message error into an `io::Error`.
pub fn map_message_error(err: MessageError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("message error: {err:?}"),
    )
}

/// Map a protocol payload decode error into an `io::Error`.
pub fn map_payload_error(err: PayloadError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("payload error: {err:?}"),
    )
}
