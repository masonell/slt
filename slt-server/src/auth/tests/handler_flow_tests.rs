use super::*;

fn assert_close_code(buf: &[u8], limits: MessageLimits, expected: CloseCode) {
    let (message, _) = slt_core::proto::decode_message(buf, limits)
        .unwrap()
        .unwrap();
    match message {
        Message::Close { payload } => {
            let close = ClosePayload::decode(payload).unwrap();
            assert_eq!(close.code, expected);
        }
        _ => panic!("expected close, got {message:?}"),
    }
}

fn assert_protocol_error_close(buf: &[u8], limits: MessageLimits) {
    assert_close_code(buf, limits, CloseCode::ProtocolError);
}

async fn assert_pre_auth_protocol_error(message: Message<'_>) {
    let (handler, _registry, metrics) = TestAuthHandler::builder()
        .with_auth_timeout(Duration::from_secs(5))
        .build_async()
        .await;

    let (server_tls, mut client_tls) = tls_pair().await;
    let limits = MessageLimits::from_mtu(1500);
    let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

    let mut frame = Vec::new();
    slt_core::proto::encode_message(message, &mut frame).unwrap();
    client_tls.write_all(&frame).await.unwrap();

    let buf = timeout(
        Duration::from_secs(2),
        read_message(&mut client_tls, limits),
    )
    .await
    .unwrap()
    .unwrap();
    assert_protocol_error_close(&buf, limits);

    let err = handle
        .await
        .unwrap()
        .expect_err("protocol violation must fail the auth phase");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.auth_failures, 1);
    assert_eq!(snapshot.auth_rejections, 0);
}

#[test]
fn ensure_session_queue_size_returns_ok_when_nonzero() {
    let (handler, _registry, _metrics) = TestAuthHandler::builder()
        .with_session_queue_size(8)
        .build();

    assert!(handler.inner.ensure_session_queue_size().is_ok());
}

#[test]
fn ensure_session_queue_size_returns_error_when_zero() {
    let (handler, _registry, _metrics) = TestAuthHandler::builder()
        .with_session_queue_size(0)
        .build();

    let result = handler.inner.ensure_session_queue_size();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("session_queue_size"));
}

#[tokio::test]
async fn auth_phase_responds_to_ping_with_pong() {
    let (handler, _registry, _metrics) = TestAuthHandler::builder()
        .with_auth_timeout(Duration::from_secs(5))
        .build_async()
        .await;

    let (server_tls, mut client_tls) = tls_pair().await;
    let limits = MessageLimits::from_mtu(1500);

    let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

    let nonce = 0xA1B2_C3D4_E5F6_0708_u64;
    let ping_payload = PingPayload { nonce };
    let mut ping_buf = Vec::new();
    ping_payload.encode(&mut ping_buf);
    let mut frame = Vec::new();
    slt_core::proto::encode_message(Message::Ping { payload: &ping_buf }, &mut frame).unwrap();
    client_tls.write_all(&frame).await.unwrap();

    let buf = timeout(
        Duration::from_secs(2),
        read_message(&mut client_tls, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let (message, _) = slt_core::proto::decode_message(&buf, limits)
        .unwrap()
        .unwrap();
    match message {
        Message::Pong { payload } => {
            let pong = PongPayload::decode(payload).unwrap();
            assert_eq!(pong.nonce, nonce);
        }
        _ => panic!("expected pong, got {message:?}"),
    }

    let close = ClosePayload {
        code: slt_core::proto::CloseCode::Normal,
    };
    let mut close_buf = Vec::new();
    close.encode(&mut close_buf);
    let mut close_frame = Vec::new();
    slt_core::proto::encode_message(
        Message::Close {
            payload: &close_buf,
        },
        &mut close_frame,
    )
    .unwrap();
    client_tls.write_all(&close_frame).await.unwrap();

    let _ = handle.await.unwrap();
}

#[tokio::test]
async fn auth_deadline_cancels_blocked_response_write() {
    let (handler, _registry, metrics) = TestAuthHandler::builder()
        .with_auth_timeout(Duration::from_millis(200))
        .build_async()
        .await;
    let (server_tls, mut client_tls, write_gate) = tls_pair_with_parkable_server_writes().await;
    write_gate.park();
    let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

    let mut ping_buf = Vec::new();
    PingPayload { nonce: 7 }.encode(&mut ping_buf);
    let mut frame = Vec::new();
    slt_core::proto::encode_message(Message::Ping { payload: &ping_buf }, &mut frame).unwrap();
    client_tls.write_all(&frame).await.unwrap();
    timeout(
        Duration::from_secs(1),
        write_gate.wait_until_write_blocked(),
    )
    .await
    .expect("auth handler entered the parked response write");

    let err = timeout(Duration::from_secs(1), handle)
        .await
        .expect("auth deadline must cancel a parked response write")
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert_eq!(metrics.snapshot().auth_failures, 1);
}

#[tokio::test]
async fn auth_phase_handles_close_message() {
    let (handler, _registry, _metrics) = TestAuthHandler::builder()
        .with_auth_timeout(Duration::from_secs(5))
        .build_async()
        .await;

    let (server_tls, client_tls) = tls_pair().await;

    let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

    drop(client_tls);

    let result = timeout(Duration::from_secs(2), handle).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn auth_phase_rejects_pre_auth_data_with_protocol_error() {
    assert_pre_auth_protocol_error(Message::Data { packet: &[0x45] }).await;
}

#[tokio::test]
async fn auth_phase_rejects_pre_auth_register_cid_with_protocol_error() {
    assert_pre_auth_protocol_error(Message::RegisterCid { payload: &[] }).await;
}

#[tokio::test]
async fn auth_phase_rejects_invalid_auth_payload_with_protocol_error() {
    assert_pre_auth_protocol_error(Message::Auth { payload: &[] }).await;
}

#[tokio::test]
async fn auth_phase_rejects_invalid_close_payload_with_protocol_error() {
    assert_pre_auth_protocol_error(Message::Close { payload: &[] }).await;
}

/// Regression test for the message-parse-error path (`auth/handler.rs`):
/// a malformed frame (unknown message type) makes `try_pop_message` return
/// `Err(MessageError)`, which the handler must still answer with
/// `CLOSE(ProtocolError)` on the wire before returning the typed error.
///
/// This path is security-relevant (the server must *respond* rather than drop
/// the connection on a parse error) and carries a silent `ErrorKind`
/// reclassification at the binary boundary: the message-parse failure surfaces
/// as `io::ErrorKind::InvalidData` via `AuthError::io_kind()`. The test pins
/// both the on-wire response and the failure-metric count.
#[tokio::test]
async fn auth_phase_responds_with_protocol_error_close_on_malformed_frame() {
    let (handler, _registry, metrics) = TestAuthHandler::builder()
        .with_auth_timeout(Duration::from_secs(5))
        .build_async()
        .await;

    let (server_tls, mut client_tls) = tls_pair().await;
    let limits = MessageLimits::from_mtu(1500);

    let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

    // Craft a frame with an unknown message type byte (0xFF) and a zero
    // payload length. `try_pop_message` decodes this as
    // `MessageError::Frame(FrameError::UnknownType(0xFF))`.
    let malformed_frame = [0xFF, 0x00, 0x00, 0x00, 0x00];
    client_tls.write_all(&malformed_frame).await.unwrap();

    // The server reports the framing violation before terminating the stream.
    let buf = timeout(
        Duration::from_secs(2),
        read_message(&mut client_tls, limits),
    )
    .await
    .unwrap()
    .unwrap();
    assert_protocol_error_close(&buf, limits);

    // The handler returns Err(AuthError) (a MessageError, surfaced as
    // io::ErrorKind::InvalidData at the boundary) — recorded as an auth
    // failure.
    let result = handle.await.unwrap();
    assert!(
        result.is_err(),
        "malformed frame should surface as an io::Error at the boundary"
    );
    assert_eq!(
        result.unwrap_err().kind(),
        io::ErrorKind::InvalidData,
        "message-parse failure must classify as InvalidData at the boundary"
    );
    assert_eq!(
        metrics.snapshot().auth_failures,
        1,
        "malformed frame must increment auth_failures"
    );
    assert_eq!(metrics.snapshot().auth_rejections, 0);
}

#[tokio::test]
async fn auth_phase_successful_authentication() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let client_id = ClientId([0xA1; 16]);
    let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 9);
    let client = make_client(client_id, &signing_key, assigned_ipv4, true);

    let (handler, registry, metrics) = TestAuthHandler::builder()
        .with_client(client)
        .with_auth_timeout(Duration::from_secs(5))
        .build_async()
        .await;

    let (server_tls, mut client_tls) = tls_pair().await;
    let limits = MessageLimits::from_mtu(1500);

    let challenge = slt_core::crypto::export_auth_challenge(server_tls.ssl()).unwrap();

    let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

    let auth_payload = make_payload(client_id, assigned_ipv4, challenge, &signing_key);
    let mut auth_buf = Vec::new();
    auth_payload.encode(&mut auth_buf);
    let mut frame = Vec::new();
    slt_core::proto::encode_message(Message::Auth { payload: &auth_buf }, &mut frame).unwrap();
    client_tls.write_all(&frame).await.unwrap();

    let buf = timeout(
        Duration::from_secs(2),
        read_message(&mut client_tls, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let (message, _) = slt_core::proto::decode_message(&buf, limits)
        .unwrap()
        .unwrap();
    assert!(matches!(message, Message::AuthOk { .. }));

    assert!(registry.lookup_ip(assigned_ipv4).is_some());
    assert_eq!(metrics.snapshot().auth_successes, 1);

    let _ = handle.await.unwrap();
}

#[tokio::test]
async fn auth_phase_mtu_mismatch_sends_auth_fail() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let client_id = ClientId([0xA1; 16]);
    let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 9);
    let client = make_client(client_id, &signing_key, assigned_ipv4, true);

    let (handler, registry, metrics) = TestAuthHandler::builder()
        .with_client(client)
        .with_auth_timeout(Duration::from_secs(5))
        .build_async()
        .await;

    let (server_tls, mut client_tls) = tls_pair().await;
    let limits = MessageLimits::from_mtu(1500);
    let challenge = slt_core::crypto::export_auth_challenge(server_tls.ssl()).unwrap();
    let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

    let auth_payload = make_payload_with_mtu(
        client_id,
        assigned_ipv4,
        TEST_TUN_MTU + 1,
        challenge,
        &signing_key,
    );
    let mut auth_buf = Vec::new();
    auth_payload.encode(&mut auth_buf);
    let mut frame = Vec::new();
    slt_core::proto::encode_message(Message::Auth { payload: &auth_buf }, &mut frame).unwrap();
    client_tls.write_all(&frame).await.unwrap();

    let buf = timeout(
        Duration::from_secs(2),
        read_message(&mut client_tls, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let (message, _) = slt_core::proto::decode_message(&buf, limits)
        .unwrap()
        .unwrap();
    let Message::AuthFail { payload } = message else {
        panic!("expected AUTH_FAIL, got {message:?}");
    };
    assert_eq!(
        AuthFailPayload::decode(payload).unwrap().code,
        AuthFailCode::MtuMismatch
    );
    assert!(registry.lookup_ip(assigned_ipv4).is_none());
    assert_eq!(metrics.snapshot().auth_rejections, 1);

    let _ = handle.await.unwrap();
}

#[tokio::test]
async fn auth_phase_failed_authentication_sends_auth_fail() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let client_id = ClientId([0xA1; 16]);
    let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 9);
    let client = make_client(client_id, &signing_key, assigned_ipv4, false);

    let (handler, _registry, metrics) = TestAuthHandler::builder()
        .with_client(client)
        .with_auth_timeout(Duration::from_secs(5))
        .build_async()
        .await;

    let (server_tls, mut client_tls) = tls_pair().await;
    let limits = MessageLimits::from_mtu(1500);

    let challenge = slt_core::crypto::export_auth_challenge(server_tls.ssl()).unwrap();

    let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

    let auth_payload = make_payload(client_id, assigned_ipv4, challenge, &signing_key);
    let mut auth_buf = Vec::new();
    auth_payload.encode(&mut auth_buf);
    let mut frame = Vec::new();
    slt_core::proto::encode_message(Message::Auth { payload: &auth_buf }, &mut frame).unwrap();
    client_tls.write_all(&frame).await.unwrap();

    let buf = timeout(
        Duration::from_secs(2),
        read_message(&mut client_tls, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let (message, _) = slt_core::proto::decode_message(&buf, limits)
        .unwrap()
        .unwrap();
    match message {
        Message::AuthFail { payload } => {
            let fail = AuthFailPayload::decode(payload).unwrap();
            assert_eq!(fail.code, AuthFailCode::Disabled);
        }
        _ => panic!("expected auth fail, got {message:?}"),
    }

    assert_eq!(metrics.snapshot().auth_failures, 1);

    let _ = handle.await.unwrap();
}

#[tokio::test]
async fn auth_phase_replaces_existing_session() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let client_id = ClientId([0xA1; 16]);
    let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 9);
    let client = make_client(client_id, &signing_key, assigned_ipv4, true);

    let (handler, registry, _metrics) = TestAuthHandler::builder()
        .with_client(client)
        .with_auth_timeout(Duration::from_secs(5))
        .build_async()
        .await;

    let limits = MessageLimits::from_mtu(1500);

    let (old_server_tls, mut old_client_tls) = tls_pair().await;
    let old_challenge = slt_core::crypto::export_auth_challenge(old_server_tls.ssl()).unwrap();
    let old_auth = handler.inner.clone();
    let old_handle = tokio::spawn(async move { old_auth.handle_with_tls(old_server_tls).await });

    let old_auth_payload = make_payload(client_id, assigned_ipv4, old_challenge, &signing_key);
    let mut old_auth_buf = Vec::new();
    old_auth_payload.encode(&mut old_auth_buf);
    let mut old_frame = Vec::new();
    slt_core::proto::encode_message(
        Message::Auth {
            payload: &old_auth_buf,
        },
        &mut old_frame,
    )
    .unwrap();
    old_client_tls.write_all(&old_frame).await.unwrap();
    let _ = timeout(
        Duration::from_secs(2),
        read_message(&mut old_client_tls, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let _ = old_handle.await.unwrap();
    assert!(registry.lookup_ip(assigned_ipv4).is_some());

    let (server_tls, mut client_tls) = tls_pair().await;

    let challenge = slt_core::crypto::export_auth_challenge(server_tls.ssl()).unwrap();

    let auth = handler.inner.clone();
    let handle = tokio::spawn(async move { auth.handle_with_tls(server_tls).await });

    let auth_payload = make_payload(client_id, assigned_ipv4, challenge, &signing_key);
    let mut auth_buf = Vec::new();
    auth_payload.encode(&mut auth_buf);
    let mut frame = Vec::new();
    slt_core::proto::encode_message(Message::Auth { payload: &auth_buf }, &mut frame).unwrap();
    client_tls.write_all(&frame).await.unwrap();

    let _ = timeout(
        Duration::from_secs(2),
        read_message(&mut client_tls, limits),
    )
    .await
    .unwrap()
    .unwrap();

    let close = timeout(
        Duration::from_secs(2),
        read_message(&mut old_client_tls, limits),
    )
    .await
    .unwrap()
    .unwrap();
    assert_close_code(&close, limits, CloseCode::Normal);

    let mut eof = [0_u8; 1];
    let n = timeout(Duration::from_secs(2), old_client_tls.read(&mut eof))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);

    assert!(registry.lookup_ip(assigned_ipv4).is_some());

    let _ = handle.await.unwrap();
}
