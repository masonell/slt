use std::net::ToSocketAddrs;

use boring::rand::rand_bytes;
use boring::ssl::{HandshakeError, Ssl, SslVerifyMode};
use clap::Parser;
use slt_core::crypto::client_hello::client_hello_session_id_callback;
use slt_core::crypto::{configure_client_chrome_ssl, tcp_client_chrome_ctx_builder};
use slt_core::types::SharedSecret;

#[derive(Parser, Debug)]
#[command(about = "Emit a TLS ClientHello over TCP.")]
struct Args {
    /// Destination address (host:port).
    addr: String,
    /// SNI hostname to send.
    #[arg(long)]
    sni: Option<String>,
    /// 32-byte secret hex used to fill `legacy_session_id`.
    #[arg(long = "secret-hex", value_parser = parse_hex_32)]
    secret_hex: Option<[u8; 32]>,
    /// Disable `legacy_session_id` override.
    #[arg(long = "no-session-id")]
    no_session_id: bool,
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
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

    let mut ctx = tcp_client_chrome_ctx_builder()?;
    ctx.set_verify(SslVerifyMode::NONE);

    if !args.no_session_id {
        let secret = if let Some(hex) = args.secret_hex {
            SharedSecret(hex)
        } else {
            let mut buf = [0u8; 32];
            rand_bytes(&mut buf)?;
            SharedSecret(buf)
        };
        ctx.set_client_hello_session_id_callback(client_hello_session_id_callback(secret));
    }

    let ctx = ctx.build();
    let mut ssl = Ssl::new(&ctx)?;
    configure_client_chrome_ssl(&mut ssl)?;
    if let Some(name) = args.sni.as_deref() {
        ssl.set_hostname(name)?;
    }

    let stream = std::net::TcpStream::connect(peer)?;
    match ssl.connect(stream) {
        Ok(_) => eprintln!("handshake completed"),
        Err(HandshakeError::WouldBlock(_)) => {
            eprintln!("handshake would block");
        }
        Err(HandshakeError::Failure(mid)) => {
            eprintln!("handshake failed: {:?}", mid.error());
        }
        Err(HandshakeError::SetupFailure(err)) => {
            eprintln!("handshake setup failed: {err}");
        }
    }

    Ok(())
}
