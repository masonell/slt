use std::io;

#[cfg(test)]
use slt_core::proto::MessageError;
use slt_core::proto::PayloadError;

#[cfg(test)]
pub(super) fn map_message_error(err: MessageError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("message error: {err:?}"),
    )
}

pub(super) fn map_payload_error(err: PayloadError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("payload error: {err:?}"),
    )
}
