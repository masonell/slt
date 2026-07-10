//! Integration tests using the mock TLS server.
//!
//! These tests cover:
//! - TCP session message handling (ping/pong, data, close)
//! - UDP upgrade flow (`REGISTER_CID/REGISTER_OK`, `REGISTER_FAIL`)
//! - Reconnection handling

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use slt_core::proto::{
        AuthFailCode, CloseCode, Message, MessageLimits, PingPayload, PongPayload,
        RegisterFailCode, RegisterFailPayload, RegisterOkPayload,
    };
    use slt_core::transport::tcp::TcpChannel;
    use slt_core::types::MAX_DCID_LEN;
    use tokio::io::DuplexStream;
    use tokio_boring::SslStream;

    use crate::runtime::SessionError;
    use crate::test_support::{MockTlsServer, test_config, tls_server_pair};

    const MAX_FRAME: usize = 16 * 1024;

    /// Create a mock TCP transport pair for testing.
    async fn mock_transport_pair() -> (
        TcpChannel<DuplexStream, crate::transport::tcp::ClientKeyUpdater>,
        SslStream<DuplexStream>,
    ) {
        let (client_stream, server_stream) = tls_server_pair().await;
        let metrics = Arc::new(crate::metrics::Metrics::default());
        let updater = crate::transport::tcp::ClientKeyUpdater::new(metrics);
        let client = TcpChannel::with_key_updater(client_stream, updater);
        (client, server_stream)
    }

    /// Helper to read until a message is available on the mock server.
    async fn recv_server_message(server: &mut MockTlsServer) -> crate::test_support::MockMessage {
        loop {
            if let Some(msg) = server.try_pop_message().unwrap() {
                return msg;
            }
            let n = server.read_more().await.unwrap();
            assert!(n > 0, "server connection closed unexpectedly");
        }
    }

    // ============================================================================
    // TCP Session Message Handling Tests
    // ============================================================================

    mod tcp_session_messages {
        use super::*;

        /// Test that server can send PING and client responds with correct PONG.
        #[tokio::test]
        async fn ping_pong_over_tcp() {
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);

            // Server sends PING with nonce
            let nonce = 0x1234_5678_DEAD_BEEF_u64;
            server.send_ping(nonce).await.unwrap();

            // Client receives PING
            client.read_more().await.unwrap();
            let msg_buf = client
                .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
                .unwrap()
                .unwrap();

            // Verify it's a PING with correct nonce
            match msg_buf.message() {
                Message::Ping { payload } => {
                    let ping = PingPayload::decode(payload).unwrap();
                    assert_eq!(ping.nonce, nonce);
                }
                _ => panic!("expected PING, got {:?}", msg_buf.message()),
            }

            // Client sends PONG with matching nonce
            let pong = PongPayload { nonce };
            let mut pong_buf = Vec::new();
            pong.encode(&mut pong_buf);
            client
                .write_message(Message::Pong { payload: &pong_buf })
                .await
                .unwrap();

            // Server receives PONG
            let received_nonce = server.recv_pong().await.unwrap();
            assert_eq!(received_nonce, nonce);
        }

        /// Test that client can send DATA message to server.
        #[tokio::test]
        async fn data_message_roundtrip() {
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);

            // Client sends DATA
            let data = b"hello, vpn tunnel!";
            client
                .write_message(Message::Data { packet: data })
                .await
                .unwrap();

            // Server receives DATA
            let msg = recv_server_message(&mut server).await;

            assert!(matches!(msg.message(), Message::Data { .. }));
            // Payload starts after 5-byte header (type + length)
            assert_eq!(&msg.buf[5..], data);
        }

        /// Test that server can send CLOSE and client receives it.
        #[tokio::test]
        async fn close_message_from_server() {
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);

            // Server sends CLOSE
            server.send_close(CloseCode::Normal).await.unwrap();

            // Client receives CLOSE
            client.read_more().await.unwrap();
            let msg_buf = client
                .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
                .unwrap()
                .unwrap();

            match msg_buf.message() {
                Message::Close { payload } => {
                    let close = slt_core::proto::ClosePayload::decode(payload).unwrap();
                    assert_eq!(close.code, CloseCode::Normal);
                }
                _ => panic!("expected CLOSE, got {:?}", msg_buf.message()),
            }
        }

        /// Test that client can send CLOSE to server.
        #[tokio::test]
        async fn close_message_from_client() {
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);

            // Client sends CLOSE
            let payload = slt_core::proto::ClosePayload {
                code: CloseCode::IdleTimeout,
            };
            let mut buf = Vec::new();
            payload.encode(&mut buf);
            client
                .write_message(Message::Close { payload: &buf })
                .await
                .unwrap();

            // Server receives CLOSE
            let msg = recv_server_message(&mut server).await;

            assert!(matches!(msg.message(), Message::Close { .. }));
        }

        /// Test multiple PING/PONG exchanges.
        #[tokio::test]
        async fn multiple_ping_pong_exchanges() {
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);

            for nonce in [
                0x0000_0000_0000_0001,
                0xDEAD_BEEF_CAFE_BABE,
                0xFFFF_FFFF_FFFF_FFFF,
            ] {
                // Server sends PING
                server.send_ping(nonce).await.unwrap();

                // Client receives and responds
                client.read_more().await.unwrap();
                let msg_buf = client
                    .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
                    .unwrap()
                    .unwrap();

                match msg_buf.message() {
                    Message::Ping { payload } => {
                        let ping = PingPayload::decode(payload).unwrap();
                        assert_eq!(ping.nonce, nonce);

                        // Respond with PONG
                        let pong = PongPayload { nonce };
                        let mut pong_buf = Vec::new();
                        pong.encode(&mut pong_buf);
                        client
                            .write_message(Message::Pong { payload: &pong_buf })
                            .await
                            .unwrap();
                    }
                    _ => panic!("expected PING"),
                }

                // Server receives PONG
                let received = server.recv_pong().await.unwrap();
                assert_eq!(received, nonce);
            }
        }

        /// Test that large DATA messages can be sent.
        #[tokio::test]
        async fn large_data_message() {
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);

            // Create a 4KB data packet
            let data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
            client
                .write_message(Message::Data { packet: &data })
                .await
                .unwrap();

            // Server receives it (may need multiple reads for larger messages)
            let msg = recv_server_message(&mut server).await;

            assert!(matches!(msg.message(), Message::Data { .. }));
            assert_eq!(&msg.buf[5..], data.as_slice());
        }

        /// Test PONG payload decode error handling.
        #[tokio::test]
        async fn pong_payload_decode_errors() {
            // Empty payload
            let result = PongPayload::decode(&[]);
            assert!(result.is_err());

            // Too short payload
            let result = PongPayload::decode(&[0x01, 0x02, 0x03, 0x04]);
            assert!(result.is_err());

            // Decode error is preserved as a typed SessionError::Payload.
            let err = SessionError::from(result.unwrap_err());
            assert!(matches!(err, SessionError::Payload(_)));
        }

        /// Test PING payload decode error handling.
        #[tokio::test]
        async fn ping_payload_decode_errors() {
            // Empty payload
            let result = PingPayload::decode(&[]);
            assert!(result.is_err());

            let err = SessionError::from(result.unwrap_err());
            assert!(matches!(err, SessionError::Payload(_)));
        }
    }

    // ============================================================================
    // UDP Upgrade Flow Tests
    // ============================================================================

    mod udp_upgrade_flow {
        use super::*;

        /// Test `REGISTER_CID/REGISTER_OK` exchange.
        #[tokio::test]
        async fn register_cid_ok_exchange() {
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);

            // Client sends REGISTER_CID
            let dcid = slt_core::types::Cid::from([0xAA; MAX_DCID_LEN]);
            let scid = slt_core::types::Cid::from([0xBB; MAX_DCID_LEN]);
            let register = slt_core::proto::RegisterCidPayload {
                client_to_server_cid: dcid,
                server_to_client_cid: scid,
                cipher: slt_core::proto::CipherSuite::Aes128Gcm,
                secret_tx: [0x01; slt_core::proto::UDP_QSP_TRAFFIC_SECRET_LEN],
                secret_rx: [0x02; slt_core::proto::UDP_QSP_TRAFFIC_SECRET_LEN],
                pn_start: 1000,
                pn_start_rx: 2000,
                key_phase: false,
            };

            let mut payload_buf = Vec::new();
            register.encode(&mut payload_buf).unwrap();
            client
                .write_message(Message::RegisterCid {
                    payload: &payload_buf,
                })
                .await
                .unwrap();

            // Server receives and sends REGISTER_OK
            let received_dcid = server.recv_register_and_send_ok().await.unwrap();
            assert_eq!(received_dcid, dcid);

            // Client receives REGISTER_OK
            client.read_more().await.unwrap();
            let msg_buf = client
                .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
                .unwrap()
                .unwrap();

            match msg_buf.message() {
                Message::RegisterOk { payload } => {
                    let ok = RegisterOkPayload::decode(payload).unwrap();
                    assert_eq!(ok.client_to_server_cid, dcid);
                }
                _ => panic!("expected REGISTER_OK, got {:?}", msg_buf.message()),
            }
        }

        /// Test `REGISTER_CID/REGISTER_FAIL` exchange.
        #[tokio::test]
        async fn register_cid_fail_exchange() {
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);

            // Client sends REGISTER_CID
            let dcid = slt_core::types::Cid::from([0xAA; MAX_DCID_LEN]);
            let scid = slt_core::types::Cid::from([0xBB; MAX_DCID_LEN]);
            let register = slt_core::proto::RegisterCidPayload {
                client_to_server_cid: dcid,
                server_to_client_cid: scid,
                cipher: slt_core::proto::CipherSuite::Aes128Gcm,
                secret_tx: [0x01; slt_core::proto::UDP_QSP_TRAFFIC_SECRET_LEN],
                secret_rx: [0x02; slt_core::proto::UDP_QSP_TRAFFIC_SECRET_LEN],
                pn_start: 1000,
                pn_start_rx: 2000,
                key_phase: false,
            };

            let mut payload_buf = Vec::new();
            register.encode(&mut payload_buf).unwrap();
            client
                .write_message(Message::RegisterCid {
                    payload: &payload_buf,
                })
                .await
                .unwrap();

            // Server receives REGISTER_CID and sends REGISTER_FAIL
            let msg = recv_server_message(&mut server).await;
            assert!(matches!(msg.message(), Message::RegisterCid { .. }));

            let fail = RegisterFailPayload {
                code: RegisterFailCode::InvalidCid,
            };
            let mut fail_buf = Vec::new();
            fail.encode(&mut fail_buf);
            server
                .write_message(Message::RegisterFail { payload: &fail_buf })
                .await
                .unwrap();

            // Client receives REGISTER_FAIL
            client.read_more().await.unwrap();
            let msg_buf = client
                .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
                .unwrap()
                .unwrap();

            match msg_buf.message() {
                Message::RegisterFail { payload } => {
                    let fail = RegisterFailPayload::decode(payload).unwrap();
                    assert_eq!(fail.code, RegisterFailCode::InvalidCid);
                }
                _ => panic!("expected REGISTER_FAIL, got {:?}", msg_buf.message()),
            }
        }

        /// Test all `REGISTER_FAIL` codes can be decoded.
        #[tokio::test]
        async fn register_fail_all_codes() {
            let codes = [
                (RegisterFailCode::Unknown, "unknown"),
                (RegisterFailCode::NotAuthenticated, "not authenticated"),
                (RegisterFailCode::InvalidCipher, "invalid cipher"),
                (RegisterFailCode::InvalidCid, "invalid cid"),
                (RegisterFailCode::InvalidKeys, "invalid keys"),
            ];

            for (code, _name) in codes {
                let buf = [u8::from(code)];
                let decoded = RegisterFailPayload::decode(&buf).unwrap();
                assert_eq!(decoded.code, code);
            }
        }

        /// Test `REGISTER_OK` payload roundtrip.
        #[tokio::test]
        async fn register_ok_payload_roundtrip() {
            let dcid = slt_core::types::Cid::from([0xCD; MAX_DCID_LEN]);
            let payload = RegisterOkPayload {
                client_to_server_cid: dcid,
            };

            let mut buf = Vec::new();
            payload.encode(&mut buf).unwrap();

            let decoded = RegisterOkPayload::decode(&buf).unwrap();
            assert_eq!(decoded.client_to_server_cid, dcid);
        }

        /// Test `REGISTER_FAIL` payload roundtrip.
        #[tokio::test]
        async fn register_fail_payload_roundtrip() {
            let payload = RegisterFailPayload {
                code: RegisterFailCode::InvalidKeys,
            };

            let mut buf = Vec::new();
            payload.encode(&mut buf);

            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::InvalidKeys);
        }

        /// Test `REGISTER_OK` decode errors.
        #[tokio::test]
        async fn register_ok_decode_errors() {
            // Empty payload
            let result = RegisterOkPayload::decode(&[]);
            assert!(result.is_err());

            // Truncated payload
            let result = RegisterOkPayload::decode(&[0x01, 0x02, 0x03, 0x04]);
            assert!(result.is_err());

            // Decode error is preserved as a typed SessionError::Payload.
            let err = SessionError::from(result.unwrap_err());
            assert!(matches!(err, SessionError::Payload(_)));
        }

        /// Test `REGISTER_FAIL` decode errors.
        #[tokio::test]
        async fn register_fail_decode_errors() {
            // Empty payload
            let result = RegisterFailPayload::decode(&[]);
            assert!(result.is_err());

            // Invalid code
            let result = RegisterFailPayload::decode(&[0xFF]);
            assert!(result.is_err());

            // Too long payload
            let result = RegisterFailPayload::decode(&[0x00, 0x01]);
            assert!(result.is_err());
        }
    }

    // ============================================================================
    // Reconnection Handling Tests
    // ============================================================================

    mod reconnection_handling {
        use super::*;
        use crate::runtime::ReconnectBackoff;

        /// Test backoff timing for reconnection.
        #[tokio::test]
        async fn reconnect_backoff_timing() {
            let base = Duration::from_millis(100);
            let max = Duration::from_secs(5);
            let mut backoff = ReconnectBackoff::new(base, max);

            fastrand::seed(42);

            // First attempt: should be in [50, 100]ms
            let d1 = backoff.next_delay();
            let d1_ms = d1.as_millis() as u64;
            assert!((50..=100).contains(&d1_ms), "d1_ms = {d1_ms}");

            // After failure, backoff increases
            let d2 = backoff.next_delay();
            let d2_ms = d2.as_millis() as u64;
            assert!((100..=200).contains(&d2_ms), "d2_ms = {d2_ms}");

            // Continue backoff
            let d3 = backoff.next_delay();
            let d3_ms = d3.as_millis() as u64;
            assert!((200..=400).contains(&d3_ms), "d3_ms = {d3_ms}");
        }

        /// Test backoff reset after successful connection.
        #[tokio::test]
        async fn backoff_reset_after_success() {
            let base = Duration::from_millis(100);
            let max = Duration::from_secs(5);
            let mut backoff = ReconnectBackoff::new(base, max);

            fastrand::seed(42);

            // Advance backoff
            let _ = backoff.next_delay();
            let _ = backoff.next_delay();
            assert!(backoff.current() > base);

            // Reset after successful connection
            backoff.reset();
            assert_eq!(backoff.current(), base);

            // Next delay should be at base level again
            let d = backoff.next_delay();
            let d_ms = d.as_millis() as u64;
            assert!((50..=100).contains(&d_ms), "d_ms = {d_ms}");
        }

        /// Test connection drop detection.
        #[tokio::test]
        async fn connection_drop_detection() {
            let (mut client, server) = mock_transport_pair().await;

            // Drop the server side
            drop(server);

            // Client should detect EOF on next read
            let result = client.read_more().await;
            assert!(result.is_ok()); // May return 0 for EOF
            let n = result.unwrap();
            assert_eq!(n, 0, "should get EOF (0 bytes read)");
        }

        /// Test that backoff is capped at max.
        #[tokio::test]
        async fn backoff_capped_at_max() {
            let base = Duration::from_millis(100);
            let max = Duration::from_millis(500);
            let mut backoff = ReconnectBackoff::new(base, max);

            fastrand::seed(42);

            // Exhaust backoff
            for _ in 0..10 {
                let _ = backoff.next_delay();
            }

            // Should be at max
            assert_eq!(backoff.current(), max);
        }
    }

    // ============================================================================
    // Combined Flow Tests
    // ============================================================================

    mod combined_flows {
        use super::*;
        use crate::auth::authenticate_with_channel;

        /// Test full flow: auth -> data -> ping -> close.
        #[tokio::test]
        async fn full_session_flow() {
            let config = test_config();
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);
            let metrics = Arc::new(crate::metrics::Metrics::default());

            // 1. Auth (run client and server concurrently)
            let server_fut = server.recv_auth_and_send_ok(&config);
            let client_fut = authenticate_with_channel(&mut client, &config, &metrics);
            let (server_result, client_result) = tokio::join!(server_fut, client_fut);
            server_result.expect("server auth should succeed");
            client_result.expect("client auth should succeed");

            // 2. Data exchange
            client
                .write_message(Message::Data {
                    packet: b"hello from client",
                })
                .await
                .unwrap();
            let msg = recv_server_message(&mut server).await;
            assert!(matches!(msg.message(), Message::Data { .. }));

            // 3. Ping/pong
            server.send_ping(12345).await.unwrap();
            client.read_more().await.unwrap();
            let msg = client
                .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
                .unwrap()
                .unwrap();
            match msg.message() {
                Message::Ping { payload } => {
                    let ping = PingPayload::decode(payload).unwrap();
                    assert_eq!(ping.nonce, 12345);

                    let pong = PongPayload { nonce: ping.nonce };
                    let mut buf = Vec::new();
                    pong.encode(&mut buf);
                    client
                        .write_message(Message::Pong { payload: &buf })
                        .await
                        .unwrap();
                }
                _ => panic!("expected PING"),
            }
            let nonce = server.recv_pong().await.unwrap();
            assert_eq!(nonce, 12345);

            // 4. Graceful close
            let close = slt_core::proto::ClosePayload {
                code: CloseCode::Normal,
            };
            let mut buf = Vec::new();
            close.encode(&mut buf);
            client
                .write_message(Message::Close { payload: &buf })
                .await
                .unwrap();
            let msg = recv_server_message(&mut server).await;
            assert!(matches!(msg.message(), Message::Close { .. }));
        }

        /// Test that unexpected messages during session are received correctly.
        #[tokio::test]
        async fn unexpected_message_during_session() {
            let config = test_config();
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);
            let metrics = Arc::new(crate::metrics::Metrics::default());

            // Complete auth (run concurrently)
            let server_fut = server.recv_auth_and_send_ok(&config);
            let client_fut = authenticate_with_channel(&mut client, &config, &metrics);
            let (server_result, client_result) = tokio::join!(server_fut, client_fut);
            drop(server_result);
            drop(client_result);

            // Server sends AUTH_FAIL after session established (unexpected)
            let fail = slt_core::proto::AuthFailPayload {
                code: AuthFailCode::BadSignature,
            };
            let mut buf = Vec::new();
            fail.encode(&mut buf);
            server
                .write_message(Message::AuthFail { payload: &buf })
                .await
                .unwrap();

            // Client receives it
            client.read_more().await.unwrap();
            let msg = client
                .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
                .unwrap()
                .unwrap();

            // This is unexpected during established session but client can receive it
            assert!(matches!(msg.message(), Message::AuthFail { .. }));
        }

        /// Test that connection can be re-established after TCP close.
        #[tokio::test]
        async fn reconnect_after_server_close() {
            let config = test_config();
            let metrics = Arc::new(crate::metrics::Metrics::default());

            // First connection
            let (mut client1, server1) = mock_transport_pair().await;
            let mut server1 = MockTlsServer::new(server1);

            // Complete auth (run concurrently)
            let server_fut = server1.recv_auth_and_send_ok(&config);
            let client_fut = authenticate_with_channel(&mut client1, &config, &metrics);
            let (server_result, client_result) = tokio::join!(server_fut, client_fut);
            drop(server_result);
            drop(client_result);

            // Server closes connection
            server1.send_close(CloseCode::Normal).await.unwrap();

            // Client detects close
            client1.read_more().await.unwrap();
            let msg = client1
                .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
                .unwrap()
                .unwrap();
            assert!(matches!(msg.message(), Message::Close { .. }));

            // Second connection (reconnect)
            let (mut client2, server2) = mock_transport_pair().await;
            let mut server2 = MockTlsServer::new(server2);

            // Auth on new connection (run concurrently)
            let server_fut = server2.recv_auth_and_send_ok(&config);
            let client_fut = authenticate_with_channel(&mut client2, &config, &metrics);
            let (server_result, client_result) = tokio::join!(server_fut, client_fut);
            server_result.expect("server auth should succeed");
            client_result.expect("client auth should succeed");
        }

        /// Test multiple sequential connections.
        #[tokio::test]
        async fn multiple_sequential_connections() {
            let config = test_config();
            let metrics = Arc::new(crate::metrics::Metrics::default());

            for i in 0..3 {
                let (mut client, server) = mock_transport_pair().await;
                let mut server = MockTlsServer::new(server);

                // Auth (run concurrently)
                let server_fut = server.recv_auth_and_send_ok(&config);
                let client_fut = authenticate_with_channel(&mut client, &config, &metrics);
                let (server_result, client_result) = tokio::join!(server_fut, client_fut);
                server_result
                    .unwrap_or_else(|_| panic!("server auth should succeed, iteration {i}"));
                client_result
                    .unwrap_or_else(|_| panic!("client auth should succeed, iteration {i}"));

                // Exchange data
                let data = format!("test data {i}");
                client
                    .write_message(Message::Data {
                        packet: data.as_bytes(),
                    })
                    .await
                    .unwrap();

                let msg = recv_server_message(&mut server).await;
                assert!(
                    matches!(msg.message(), Message::Data { .. }),
                    "iteration {i}"
                );
            }
        }
    }

    // ============================================================================
    // Transport Switch Tests
    // ============================================================================

    mod transport_switch {
        use super::*;

        /// TCP DATA remains decodable while UDP-QSP is the preferred path.
        #[tokio::test]
        async fn tcp_data_remains_valid_with_udp_available() {
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);

            // Server sends DATA over TCP
            server
                .write_message(Message::Data {
                    packet: b"tcp data",
                })
                .await
                .unwrap();

            // Client receives
            client.read_more().await.unwrap();
            let msg = client
                .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
                .unwrap()
                .unwrap();
            assert!(matches!(msg.message(), Message::Data { .. }));
        }

        /// TCP PING remains decodable while UDP-QSP is the preferred path.
        #[tokio::test]
        async fn tcp_ping_remains_valid_with_udp_available() {
            let (mut client, server) = mock_transport_pair().await;
            let mut server = MockTlsServer::new(server);

            // Server sends PING over TCP
            server.send_ping(999).await.unwrap();

            // Client receives
            client.read_more().await.unwrap();
            let msg = client
                .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
                .unwrap()
                .unwrap();

            match msg.message() {
                Message::Ping { payload } => {
                    let ping = PingPayload::decode(payload).unwrap();
                    assert_eq!(ping.nonce, 999);
                }
                _ => panic!("expected PING"),
            }
        }
    }

    // ============================================================================
    // Error Handling Tests
    // ============================================================================

    mod error_handling {
        use super::*;

        /// Test that malformed PING payload returns correct error.
        #[tokio::test]
        async fn malformed_ping_payload_error() {
            let result = PingPayload::decode(&[0x01, 0x02, 0x03]); // Too short
            assert!(result.is_err());

            // Preserved as a typed SessionError::Payload.
            let err = SessionError::from(result.unwrap_err());
            assert!(matches!(err, SessionError::Payload(_)));
        }

        /// Test that malformed CLOSE payload returns correct error.
        #[tokio::test]
        async fn malformed_close_payload_error() {
            let result = slt_core::proto::ClosePayload::decode(&[0xFF]); // Invalid code
            assert!(result.is_err());

            let err = SessionError::from(result.unwrap_err());
            assert!(matches!(err, SessionError::Payload(_)));
        }

        /// Test all close codes are valid.
        #[tokio::test]
        async fn close_code_values() {
            let codes = [CloseCode::Normal, CloseCode::IdleTimeout];

            for code in codes {
                let payload = slt_core::proto::ClosePayload { code };
                let mut buf = Vec::new();
                payload.encode(&mut buf);

                let decoded = slt_core::proto::ClosePayload::decode(&buf).unwrap();
                assert_eq!(decoded.code, code);
            }
        }

        /// Test all auth fail codes are valid.
        #[tokio::test]
        async fn auth_fail_code_values() {
            let codes = [
                AuthFailCode::Unknown,
                AuthFailCode::BadSignature,
                AuthFailCode::UnknownClient,
                AuthFailCode::IpMismatch,
            ];

            for code in codes {
                let payload = slt_core::proto::AuthFailPayload { code };
                let mut buf = Vec::new();
                payload.encode(&mut buf);

                let decoded = slt_core::proto::AuthFailPayload::decode(&buf).unwrap();
                assert_eq!(decoded.code, code);
            }
        }
    }
}
