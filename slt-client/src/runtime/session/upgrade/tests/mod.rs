use std::sync::Arc;

use slt_core::proto::OwnedMessageBuf;
use slt_core::transport::tcp::TcpChannel;
use tokio::io::DuplexStream;
use tokio::sync::mpsc;
use tokio_boring::SslStream;
use tokio_util::sync::CancellationToken;

use super::ClientSession;
use crate::metrics::Metrics;
use crate::runtime::services::DesktopServices;
use crate::test_support::{ParkableWriteStream, WriteGate, tls_pair_with_parkable_client_writes};
use crate::transport::tcp::{ClientKeyUpdater, TcpSession};
use crate::tun::TunChannels;

mod payload_validation;
mod probe_ack;
mod registration;
mod retry_timeout;

fn tun_channels() -> TunChannels {
    let (_to_session_tx, to_session_rx) = mpsc::channel::<Vec<u8>>(8);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(8);
    TunChannels {
        to_session_rx,
        to_tun_tx,
    }
}

async fn parkable_session<'a>(
    config: &'a slt_core::config::ClientConfig,
    tun: &'a mut TunChannels,
    services: &'a DesktopServices,
) -> (
    ClientSession<'a, DesktopServices, ParkableWriteStream>,
    SslStream<DuplexStream>,
    Arc<WriteGate>,
) {
    let metrics = Arc::new(Metrics::default());
    let updater = ClientKeyUpdater::new(metrics.clone());
    let (client_stream, server_stream, write_gate) = tls_pair_with_parkable_client_writes().await;
    let tcp_session = TcpSession {
        transport: TcpChannel::with_key_updater(client_stream, updater),
        peer: None,
        sni: None,
    };
    (
        ClientSession::new(
            config,
            tcp_session,
            tun,
            CancellationToken::new(),
            metrics,
            services,
            None,
        ),
        server_stream,
        write_gate,
    )
}
