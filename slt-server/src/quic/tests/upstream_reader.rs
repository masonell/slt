use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

use super::super::QuicEndpoint;

#[tokio::test]
async fn spawn_upstream_reader_forwards_packets_and_reports_done() {
    let peer_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = peer_socket.local_addr().unwrap();

    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let downstream_addr = downstream.local_addr().unwrap();

    let upstream_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_server_addr = upstream_server.local_addr().unwrap();

    let upstream_client = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    upstream_client.connect(upstream_server_addr).await.unwrap();

    let token = 123u64;
    let cancel = CancellationToken::new();
    let (done_tx, mut done_rx) = mpsc::unbounded_channel();

    let handle = QuicEndpoint::spawn_upstream_reader(
        upstream_client.clone(),
        downstream.clone(),
        peer,
        token,
        cancel.clone(),
        done_tx,
    );

    tokio::time::sleep(Duration::from_millis(20)).await;

    let test_data = b"hello from upstream";
    upstream_server
        .send_to(test_data, upstream_client.local_addr().unwrap())
        .await
        .unwrap();

    let mut buf = vec![0u8; 256];
    let deadline = Instant::now() + Duration::from_millis(500);
    let (recv_len, from_addr) = timeout_at(deadline, peer_socket.recv_from(&mut buf))
        .await
        .expect("should receive forwarded packet")
        .expect("recv_from should succeed");
    assert_eq!(recv_len, test_data.len());
    assert_eq!(&buf[..recv_len], test_data);
    assert_eq!(from_addr, downstream_addr);

    cancel.cancel();
    handle.await.unwrap();

    let done_msg = timeout(Duration::from_millis(100), done_rx.recv())
        .await
        .expect("should receive done notification")
        .expect("done channel should have message");
    assert_eq!(done_msg.0, peer);
    assert_eq!(done_msg.1, token);
}

#[tokio::test]
async fn spawn_upstream_reader_handles_downstream_send_error_and_reports_done() {
    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let upstream_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_server_addr = upstream_server.local_addr().unwrap();
    let upstream_client = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    upstream_client.connect(upstream_server_addr).await.unwrap();

    let peer = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 12345));

    let token = 321u64;
    let cancel = CancellationToken::new();
    let (done_tx, mut done_rx) = mpsc::unbounded_channel();
    let handle = QuicEndpoint::spawn_upstream_reader(
        upstream_client.clone(),
        downstream,
        peer,
        token,
        cancel.clone(),
        done_tx,
    );

    upstream_server
        .send_to(
            b"trigger send_to error",
            upstream_client.local_addr().unwrap(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;

    cancel.cancel();
    handle.await.unwrap();

    let done_msg = timeout(Duration::from_millis(200), done_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done_msg.0, peer);
    assert_eq!(done_msg.1, token);
}
