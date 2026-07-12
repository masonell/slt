use std::time::Duration;

use tokio::time::timeout;

use super::super::*;
use crate::test_support::{encode_ping, udp_pair};

#[tokio::test]
async fn client_udp_io_accepts_packets_from_peer() {
    let (socket_a, socket_b) = udp_pair().await;

    // Create ClientUdpIo with socket_a, expecting packets from socket_b
    let peer_addr = socket_b.local_addr().unwrap();
    let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

    // Send a packet from the peer (socket_b)
    let ping_frame = encode_ping(0x1234);
    socket_b.send(&ping_frame).await.unwrap();

    // Receive should succeed
    let mut buf = [0u8; 2048];
    let len = io.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..len], ping_frame.as_slice());
}

#[tokio::test]
async fn client_udp_io_ignores_packets_from_non_peer() {
    let (socket_a, socket_b) = udp_pair().await;

    // Create a third socket that is NOT the peer
    let socket_c = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("failed to bind socket C"),
    );

    // Create ClientUdpIo with socket_a, expecting packets from socket_b
    let peer_addr = socket_b.local_addr().unwrap();
    let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

    // Send a packet from non-peer (socket_c) to socket_a
    let junk_packet = b"junk from non-peer";
    socket_c
        .send_to(junk_packet, socket_a.local_addr().unwrap())
        .await
        .unwrap();

    // Give the packet time to arrive
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Now send the real packet from the peer
    let ping_frame = encode_ping(0x5678);
    socket_b.send(&ping_frame).await.unwrap();

    // Receive should return the peer's packet, skipping the non-peer's
    let mut buf = [0u8; 2048];
    let len = io.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..len], ping_frame.as_slice());
    // Verify we got the ping, not the junk
    assert_ne!(&buf[..len.min(junk_packet.len())], junk_packet);
}

#[tokio::test]
async fn client_udp_io_send_delivers_to_peer() {
    let (socket_a, socket_b) = udp_pair().await;

    // Create ClientUdpIo with socket_a, sending to socket_b
    let peer_addr = socket_b.local_addr().unwrap();
    let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

    // Send a packet
    let ping_frame = encode_ping(0xABCD);
    io.send(&ping_frame).await.unwrap();

    // Socket_b should receive it
    let mut buf = [0u8; 2048];
    let (len, from) = socket_b.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..len], ping_frame.as_slice());
    assert_eq!(from, socket_a.local_addr().unwrap());
}

#[tokio::test]
async fn client_udp_io_multiple_packets_in_order() {
    let (socket_a, socket_b) = udp_pair().await;

    let peer_addr = socket_b.local_addr().unwrap();
    let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

    // Send multiple packets from peer
    for nonce in 0u64..5 {
        let ping_frame = encode_ping(nonce);
        socket_b.send(&ping_frame).await.unwrap();
    }

    // Receive them in order
    let mut buf = [0u8; 2048];
    for expected_nonce in 0u64..5 {
        let len = io.recv(&mut buf).await.unwrap();
        let expected = encode_ping(expected_nonce);
        assert_eq!(&buf[..len], expected.as_slice());
    }
}

#[tokio::test]
async fn client_udp_io_recv_timeout_when_no_peer_packet() {
    let (socket_a, socket_b) = udp_pair().await;

    // Create a third socket that is NOT the peer
    let socket_c = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("failed to bind socket C"),
    );

    let peer_addr = socket_b.local_addr().unwrap();
    let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

    // Send junk from non-peer
    let junk_packet = b"junk from non-peer";
    socket_c
        .send_to(junk_packet, socket_a.local_addr().unwrap())
        .await
        .unwrap();

    // Recv should block waiting for a packet from the actual peer
    // Use a short timeout to verify it doesn't return the non-peer packet
    let mut buf = [0u8; 2048];
    let result = timeout(Duration::from_millis(50), io.recv(&mut buf)).await;
    assert!(
        result.is_err(),
        "recv should timeout since no peer packet arrived"
    );
}
