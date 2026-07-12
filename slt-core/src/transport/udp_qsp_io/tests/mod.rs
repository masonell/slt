mod plain_io;
mod receive_behavior;
mod send_batching;
mod session_integration;

use std::io;
use std::net::{Ipv4Addr, UdpSocket};

fn socket_pair() -> io::Result<(UdpSocket, UdpSocket)> {
    let a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    a.set_nonblocking(true)?;
    b.set_nonblocking(true)?;
    Ok((a, b))
}
