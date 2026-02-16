use super::*;

#[tokio::test]
async fn auth_phase_timeout_increments_failure_metrics() {
    let (handler, _registry, metrics) = TestAuthHandler::builder()
        .with_auth_timeout(Duration::from_millis(50))
        .build_async()
        .await;

    let (server_tls, _client_tls) = tls_pair().await;

    let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

    let _ = handle.await.unwrap();

    assert_eq!(metrics.snapshot().auth_failures, 1);
}

#[tokio::test]
async fn auth_phase_connection_close_increments_failure_metrics() {
    let (handler, _registry, metrics) = TestAuthHandler::builder()
        .with_auth_timeout(Duration::from_secs(5))
        .build_async()
        .await;

    let (server_tls, client_tls) = tls_pair().await;

    let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

    drop(client_tls);

    let _ = handle.await.unwrap();

    assert_eq!(metrics.snapshot().auth_failures, 1);
}

#[tokio::test]
async fn tls_handshake_timeout_increments_failure_metrics() {
    let (handler, _registry, metrics) = TestAuthHandler::builder()
        .with_auth_timeout(Duration::from_millis(100))
        .build_async()
        .await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handler.inner.handle(stream).await
    });

    let _client = tokio::net::TcpStream::connect(addr).await.unwrap();

    let result = timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    let err = result.expect_err("expected TLS handshake timeout");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert_eq!(metrics.snapshot().auth_failures, 1);
}

#[tokio::test]
async fn tls_handshake_error_increments_failure_metrics() {
    let (handler, _registry, metrics) = TestAuthHandler::builder()
        .with_auth_timeout(Duration::from_secs(5))
        .build_async()
        .await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handler.inner.handle(stream).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    client.write_all(b"not a tls client hello").await.unwrap();
    client.shutdown().await.unwrap();

    let result = timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    let err = result.expect_err("expected TLS handshake failure");
    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert_eq!(metrics.snapshot().auth_failures, 1);
}
