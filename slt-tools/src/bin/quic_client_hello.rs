use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;

use clap::Parser;
use quiche::ConnectionId;
use slt_core::crypto::quic_client_chrome_config;

#[derive(Parser, Debug)]
#[command(about = "Emit a QUIC ClientHello over UDP.")]
struct Args {
    /// Destination address (host:port).
    addr: String,
    /// SNI hostname to send.
    #[arg(long)]
    sni: Option<String>,
    /// ALPN protocol.
    #[arg(long, default_value = "h3")]
    alpn: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let peer = args
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or("failed to resolve addr")?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    let local = socket.local_addr()?;

    let mut config = quic_client_chrome_config()?;
    config.set_application_protos(&[args.alpn.as_bytes()])?;

    let scid = ConnectionId::from_ref(&[]);

    let mut conn = quiche::connect(args.sni.as_deref(), &scid, local, peer, &mut config)?;

    let mut out = [0u8; 1350];
    loop {
        match conn.send(&mut out) {
            Ok((write, send_info)) => {
                socket.send_to(&out[..write], send_info.to)?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(Box::new(e)),
        }
    }

    std::thread::sleep(Duration::from_secs(1));

    Ok(())
}
