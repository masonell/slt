use boring::rand::rand_bytes;
use clap::Parser;
use slt::crypto::quic_client_chrome_config;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;
use quiche::ConnectionId;

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
    /// 8-byte SCID hex.
    #[arg(long = "scid-hex", value_parser = parse_hex_8)]
    scid_hex: Option<[u8; 8]>,
}

fn parse_hex_8(s: &str) -> Result<[u8; 8], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != 8 {
        return Err(format!(
            "expected 8 bytes (16 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes);
    Ok(out)
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

    let scid = if let Some(hex) = &args.scid_hex {
        ConnectionId::from_ref(hex)
    } else {
        ConnectionId::from_ref(&[])
    };

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

    std::thread::sleep(Duration::from_millis(1000));

    Ok(())
}
