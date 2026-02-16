use std::io;

#[cfg(test)]
use slt_core::proto::MessageError;
use slt_core::proto::PayloadError;

/// Converts a message error into an IO error.
///
/// Wraps the message error in an `InvalidData` IO error with a descriptive
/// message. Used primarily in test contexts for error propagation.
#[cfg(test)]
pub(super) fn map_message_error(err: MessageError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("message error: {err:?}"),
    )
}

/// Converts a payload error into an IO error.
///
/// Wraps the payload error in an `InvalidData` IO error with a descriptive
/// message. Used to propagate payload parsing failures through the
/// authentication flow.
pub(super) fn map_payload_error(err: PayloadError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("payload error: {err:?}"),
    )
}
