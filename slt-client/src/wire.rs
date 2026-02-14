use std::io;

use slt_core::proto::{FrameError, MessageError, MessageType, PayloadError};

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
