use std::io;

use slt_core::proto::{FrameError, MessageError, PayloadError};

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
