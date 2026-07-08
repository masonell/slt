use std::io::{self, ErrorKind};

use tokio::net::TcpStream;

#[cfg(unix)]
pub(super) fn peek_stream_now(stream: &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::fd::AsRawFd;

    let flags = libc::MSG_PEEK | libc::MSG_DONTWAIT;
    // Tokio's mio TCP readiness is level-triggered; MSG_PEEK does not consume
    // bytes, so this probe coexists with the async peek/read path.
    // SAFETY: `buf` points to writable memory for `buf.len()` bytes, and the
    // borrowed TCP file descriptor remains valid for the duration of this call.
    loop {
        let n = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                flags,
            )
        };

        if n >= 0 {
            return Ok(n.cast_unsigned());
        }

        let err = io::Error::last_os_error();
        if err.kind() != ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(not(unix))]
pub(super) fn peek_stream_now(_stream: &TcpStream, _buf: &mut [u8]) -> io::Result<usize> {
    Err(io::Error::from(ErrorKind::WouldBlock))
}

#[cfg(unix)]
pub(super) fn stream_has_no_buffered_data(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match peek_stream_now(stream, &mut buf) {
        Ok(0) => true,
        Err(err) if err.kind() == ErrorKind::WouldBlock => true,
        Ok(_) | Err(_) => false,
    }
}

#[cfg(not(unix))]
pub(super) fn stream_has_no_buffered_data(_stream: &TcpStream) -> bool {
    false
}
