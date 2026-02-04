use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslFiletype, SslMethod};
use boring::x509::X509;
use clap::Parser;
use slt::config::ServerConfig;
use slt::server::auth::{AuthHandler, Authenticator};
use slt::server::quic::QuicEndpoint;
use slt::server::registry::SessionRegistry;
use slt::server::router::PacketRouter;
use slt::server::sessions::SessionEvent;
use slt::server::sessions::{SessionTimeouts, message_limits_from_mtu};
use slt::server::tcp::TcpFrontDoor;
use slt::types::TlsMaterial;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tun_rs::DeviceBuilder;

#[derive(Parser, Debug)]
#[command(about = "Run the SLT server front door.")]
struct Args {
    /// Path to the server configuration file (TOML).
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let raw = fs::read_to_string(&args.config)?;
    let config: ServerConfig = toml::from_str(&raw)?;
    let config = Arc::new(config);

    let registry = Arc::new(SessionRegistry::new());
    let frontdoor = TcpFrontDoor::bind(&config).await?;
    let quic = QuicEndpoint::bind(&config, registry.clone()).await?;
    let acceptor = build_tls_acceptor(&config)?;
    let authenticator = Authenticator::from_config(&config);
    let tun = Arc::new(
        DeviceBuilder::new()
            .name(&config.tun_name)
            .mtu(config.tun_mtu)
            .build_async()?,
    );
    let session_timeouts = SessionTimeouts {
        ping_min: config.ping_min,
        ping_max: config.ping_max,
        idle_timeout: config.idle_timeout,
        udp_verify_timeout: config.udp_verify_timeout,
    };
    let limits = message_limits_from_mtu(config.tun_mtu);
    let auth_handler = Arc::new(AuthHandler::new(
        acceptor,
        authenticator,
        registry.clone(),
        tun.clone(),
        quic.socket().clone(),
        limits,
        session_timeouts,
        config.auth_timeout,
        config.session_queue_size,
    ));
    let cancel = CancellationToken::new();

    let cancel_task = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_task.cancel();
        }
    });

    let mut tcp_task = {
        let cancel = cancel.clone();
        let auth_handler = auth_handler.clone();
        tokio::spawn(async move {
            frontdoor
                .run(cancel, move |stream: TcpStream, addr| {
                    let auth_handler = auth_handler.clone();
                    tokio::spawn(async move {
                        if let Err(err) = auth_handler.handle(stream).await {
                            eprintln!("auth handler error for {addr}: {err}");
                        }
                    });
                })
                .await
        })
    };

    let mut udp_task = {
        let cancel = cancel.clone();
        tokio::spawn(async move { quic.run(cancel).await })
    };

    let mut tun_task = {
        let cancel = cancel.clone();
        let registry = registry.clone();
        let tun = tun.clone();
        let mtu = config.tun_mtu;
        tokio::spawn(async move { run_tun_reader(tun, registry, cancel, mtu).await })
    };

    tokio::select! {
        res = &mut tcp_task => {
            cancel.cancel();
            res??;
            let _ = udp_task.await;
            let _ = tun_task.await;
        }
        res = &mut udp_task => {
            cancel.cancel();
            res??;
            let _ = tcp_task.await;
            let _ = tun_task.await;
        }
        res = &mut tun_task => {
            cancel.cancel();
            res??;
            let _ = tcp_task.await;
            let _ = udp_task.await;
        }
        () = cancel.cancelled() => {
            let _ = tcp_task.await;
            let _ = udp_task.await;
            let _ = tun_task.await;
        }
    }

    Ok(())
}

fn build_tls_acceptor(config: &ServerConfig) -> Result<SslAcceptor, Box<dyn std::error::Error>> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    match &config.tls_cert {
        TlsMaterial::File { file } => builder.set_certificate_chain_file(file)?,
        TlsMaterial::Pem(pem) => {
            let mut certs = X509::stack_from_pem(pem.as_bytes())?;
            let leaf = certs
                .drain(..1)
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tls_cert is empty"))?;
            builder.set_certificate(&leaf)?;
            for cert in certs {
                builder.add_extra_chain_cert(cert)?;
            }
        }
    }
    match &config.tls_key {
        TlsMaterial::File { file } => builder.set_private_key_file(file, SslFiletype::PEM)?,
        TlsMaterial::Pem(pem) => {
            let key = PKey::private_key_from_pem(pem.as_bytes())?;
            builder.set_private_key(&key)?;
        }
    }
    builder.check_private_key()?;
    Ok(builder.build())
}

async fn run_tun_reader(
    tun: Arc<tun_rs::AsyncDevice>,
    registry: Arc<SessionRegistry>,
    cancel: CancellationToken,
    mtu: u16,
) -> io::Result<()> {
    let mut buf = vec![0u8; mtu as usize];
    loop {
        let n = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            res = tun.recv(&mut buf) => res?,
        };

        if n == 0 {
            continue;
        }

        let packet = &buf[..n];
        let Some(dst_ip) = PacketRouter::extract_dst_ipv4(packet) else {
            continue;
        };
        if let Some(tx) = registry.lookup_ip(dst_ip) {
            let _ = tx.try_send(SessionEvent::TunPacket(packet.to_vec()));
        }
    }
}
