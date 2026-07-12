use std::io;

use slt_core::proto::FrameError;
use slt_core::transport::tcp::TcpWriteError;

use crate::error::ConnectError;

/// Pins both arms of `From<TcpWriteError>` so the routing cannot silently
/// regress.
#[test]
fn from_tcp_write_error_routes_frame_fatal_and_io_retriable() {
    let frame: ConnectError = TcpWriteError::Frame(FrameError::UnknownType(1)).into();
    assert!(
        matches!(frame, ConnectError::Frame(_)),
        "Frame arm must route to ConnectError::Frame, got {frame:?}"
    );
    assert!(
        !frame.is_retriable(),
        "ConnectError::Frame from TcpWriteError must be fatal (non-retriable)"
    );

    let io: ConnectError =
        TcpWriteError::Io(io::Error::from(io::ErrorKind::ConnectionReset)).into();
    assert!(
        matches!(io, ConnectError::Io(_)),
        "Io arm must route to ConnectError::Io, got {io:?}"
    );
    assert!(
        io.is_retriable(),
        "ConnectError::Io from TcpWriteError must be retriable"
    );
}
