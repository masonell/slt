use std::sync::Arc;
use std::time::Duration;

use slt_core::proto::{Message, MessageType, OwnedMessageBuf, encode_message};
use slt_core::transport::tcp::TcpChannel;
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::metrics::Metrics;
use crate::runtime::services::DesktopServices;
use crate::runtime::session::{ClientSession, SessionControl, SessionExit};
use crate::test_support::{test_config, tls_tcp_stream_pair};
use crate::transport::tcp::{ClientKeyUpdater, TcpSession, TcpTransport};
use crate::tun::TunChannels;

async fn loopback_tcp_transport() -> TcpTransport {
    let metrics = Arc::new(Metrics::default());
    let updater = ClientKeyUpdater::new(metrics);
    let (client_stream, _server_stream) = tls_tcp_stream_pair().await;
    TcpChannel::with_key_updater(client_stream, updater)
}

fn data_message(packet: &[u8]) -> OwnedMessageBuf {
    let mut frame = Vec::new();
    encode_message(Message::Data { packet }, &mut frame).unwrap();
    OwnedMessageBuf::new(MessageType::Data, frame)
}

#[tokio::test]
async fn send_to_tun_or_shutdown_exits_when_cancelled_while_tun_queue_full() {
    let config = test_config();
    let services = DesktopServices::new();
    let metrics = Arc::new(Metrics::default());
    let cancel = CancellationToken::new();
    let (_to_session_tx, to_session_rx) = mpsc::channel::<Vec<u8>>(1);
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(1);
    to_tun_tx
        .send(data_message(b"queued"))
        .await
        .expect("queue accepts first packet");
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let tcp_session = TcpSession {
        transport: loopback_tcp_transport().await,
        peer: None,
        sni: None,
    };
    let session = ClientSession::new(
        &config,
        tcp_session,
        &mut tun,
        cancel.clone(),
        metrics.clone(),
        &services,
        None,
    );

    let send = session.send_to_tun_or_shutdown(data_message(b"blocked"));
    tokio::pin!(send);
    tokio::select! {
        biased;

        control = &mut send => panic!("blocked TUN send completed before cancellation: {control:?}"),
        () = tokio::task::yield_now() => {}
    }

    cancel.cancel();
    let control = time::timeout(Duration::from_secs(1), &mut send)
        .await
        .expect("blocked TUN send observes cancellation");
    assert_eq!(control, SessionControl::Close(SessionExit::Shutdown));
    assert_eq!(metrics.snapshot().disconnect_shutdown, 1);

    match to_tun_rx
        .try_recv()
        .expect("queued packet remains")
        .message()
    {
        Message::Data { packet } => assert_eq!(packet, b"queued"),
        other => panic!("expected queued data packet, got {other:?}"),
    }
    assert!(matches!(
        to_tun_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}
