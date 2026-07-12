use slt_core::crypto::udp_qsp::QuicQspSession;
use slt_core::proto::{CloseCode, HEADER_LEN, Message, MessageLimits, PingPayload, PongPayload};
use slt_core::types::Cid;

use super::super::*;
use crate::test_support::{
    encode_close, encode_data, encode_ping, encode_pong, make_server_keys, make_test_keys, udp_pair,
};

/// Create a paired client/server UDP-QSP transport for integration testing.
async fn udp_qsp_transport_pair() -> (UdpQspTransport<ClientUdpIo>, UdpQspTransport<ClientUdpIo>) {
    let (client_socket, server_socket) = udp_pair().await;
    let client_addr = client_socket.local_addr().unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);

    let client_io = ClientUdpIo::new(client_socket, server_addr);
    let client_session = QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
    let client_metrics = Arc::new(Metrics::default());
    let client = UdpQspTransport::new(client_session, client_metrics);

    let server_io = ClientUdpIo::new(server_socket, client_addr);
    let server_session =
        QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
    let server_metrics = Arc::new(Metrics::default());
    let server = UdpQspTransport::new(server_session, server_metrics);

    (client, server)
}

#[tokio::test]
async fn full_roundtrip_over_real_udp_sockets() {
    let (mut client, mut server) = udp_qsp_transport_pair().await;

    let limits = MessageLimits::new(2048, 2048);
    let nonce = 0x1234_5678_9ABC_DEF0u64;

    // Client sends ping
    let ping_frame = encode_ping(nonce);
    client
        .write_message(Message::Ping {
            payload: &ping_frame[HEADER_LEN..],
        })
        .await
        .unwrap();

    // Server receives and decodes
    let msg = server.read_next_message(limits).await.unwrap();
    match msg.message() {
        Message::Ping { payload } => {
            assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
        }
        _ => panic!("expected ping"),
    }
}

#[tokio::test]
async fn bidirectional_message_exchange_over_real_udp() {
    let (mut client, mut server) = udp_qsp_transport_pair().await;

    let limits = MessageLimits::new(2048, 2048);
    let nonce = 0xDEAD_BEEF_CAFE_BABEu64;

    // Client sends ping
    let ping_frame = encode_ping(nonce);
    client
        .write_message(Message::Ping {
            payload: &ping_frame[HEADER_LEN..],
        })
        .await
        .unwrap();

    // Server receives ping
    let msg = server.read_next_message(limits).await.unwrap();
    match msg.message() {
        Message::Ping { payload } => {
            assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
        }
        _ => panic!("expected ping"),
    }

    // Server sends pong
    let pong_frame = encode_pong(nonce);
    server
        .write_message(Message::Pong {
            payload: &pong_frame[HEADER_LEN..],
        })
        .await
        .unwrap();

    // Client receives pong
    let msg = client.read_next_message(limits).await.unwrap();
    match msg.message() {
        Message::Pong { payload } => {
            assert_eq!(PongPayload::decode(payload).unwrap().nonce, nonce);
        }
        _ => panic!("expected pong"),
    }
}

#[tokio::test]
async fn multiple_packets_in_sequence_over_real_udp() {
    let (mut client, mut server) = udp_qsp_transport_pair().await;

    let limits = MessageLimits::new(2048, 2048);

    // Send multiple pings in sequence
    for nonce in 0u64..5 {
        let ping_frame = encode_ping(nonce);
        client
            .write_message(Message::Ping {
                payload: &ping_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        let msg = server.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Ping { payload } => {
                assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
            }
            _ => panic!("expected ping for nonce {nonce}"),
        }
    }
}

#[tokio::test]
async fn data_message_roundtrip_over_real_udp() {
    let (mut client, mut server) = udp_qsp_transport_pair().await;

    let limits = MessageLimits::new(2048, 2048);
    let packet_data = b"hello world vpn packet";

    let data_frame = encode_data(packet_data);
    client
        .write_message(Message::Data {
            packet: &data_frame[HEADER_LEN..],
        })
        .await
        .unwrap();

    let msg = server.read_next_message(limits).await.unwrap();
    match msg.message() {
        Message::Data { packet } => {
            assert_eq!(packet, &data_frame[HEADER_LEN..]);
        }
        _ => panic!("expected data"),
    }
}

#[tokio::test]
async fn close_message_roundtrip_over_real_udp() {
    let (mut client, mut server) = udp_qsp_transport_pair().await;

    let limits = MessageLimits::new(2048, 2048);
    let close_code = CloseCode::Normal;

    let close_frame = encode_close(close_code);
    client
        .write_message(Message::Close {
            payload: &close_frame[HEADER_LEN..],
        })
        .await
        .unwrap();

    let msg = server.read_next_message(limits).await.unwrap();
    match msg.message() {
        Message::Close { payload } => {
            use slt_core::proto::ClosePayload;
            assert_eq!(ClosePayload::decode(payload).unwrap().code, close_code);
        }
        _ => panic!("expected close"),
    }
}

#[tokio::test]
async fn server_to_client_message_over_real_udp() {
    let (mut client, mut server) = udp_qsp_transport_pair().await;

    let limits = MessageLimits::new(2048, 2048);
    let nonce = 0xF00D_FACEu64;

    // Server sends ping to client
    let ping_frame = encode_ping(nonce);
    server
        .write_message(Message::Ping {
            payload: &ping_frame[HEADER_LEN..],
        })
        .await
        .unwrap();

    // Client receives it
    let msg = client.read_next_message(limits).await.unwrap();
    match msg.message() {
        Message::Ping { payload } => {
            assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
        }
        _ => panic!("expected ping"),
    }
}

/// On Unix the client transport wraps the GSO `UdpQspIo` backend, so a data
/// write buffers into the send slab and is only transmitted once `flush` runs.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn write_message_buffers_until_flush_over_gso_backend() {
    use std::time::Duration;

    use tokio::time::timeout;

    let (client_socket, server_socket) = udp_pair().await;
    let client_addr = client_socket.local_addr().unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);

    let client_io = client_udp_qsp_io(&client_socket, server_addr).unwrap();
    let client_session = QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
    let mut client = UdpQspTransport::new(client_session, Arc::new(Metrics::default()));

    let server_io = client_udp_qsp_io(&server_socket, client_addr).unwrap();
    let server_session =
        QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
    let mut server = UdpQspTransport::new(server_session, Arc::new(Metrics::default()));

    let limits = MessageLimits::new(2048, 2048);
    let ping_frame = encode_ping(0xBEEF);

    // Writing buffers into the GSO send slab; nothing is transmitted yet.
    client
        .write_message(Message::Ping {
            payload: &ping_frame[HEADER_LEN..],
        })
        .await
        .unwrap();
    assert!(
        client.has_pending_flush(),
        "write_message must leave a pending flush"
    );
    assert!(
        timeout(Duration::from_millis(80), server.read_next_message(limits))
            .await
            .is_err(),
        "buffered packet must not be delivered until flush"
    );

    // Flushing transmits the slab and clears the pending flag.
    client.flush().await.unwrap();
    assert!(!client.has_pending_flush());

    let msg = server.read_next_message(limits).await.unwrap();
    match msg.message() {
        Message::Ping { payload } => {
            assert_eq!(PingPayload::decode(payload).unwrap().nonce, 0xBEEF);
        }
        _ => panic!("expected ping"),
    }
}
