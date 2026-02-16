use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::time::Instant;

use boring::ssl::SslAcceptor;
use slt_core::proto::{
    AUTH_CHALLENGE_LEN, AuthFailCode, AuthFailPayload, AuthOkPayload, AuthPayload, Message,
    PingPayload, PongPayload,
};
use slt_core::transport::tcp::TcpChannel;
use tokio::net::TcpStream;
use tokio::time;
use tokio_boring::accept as tls_accept;
use tracing::{debug, info, trace, warn};
use tun_rs::AsyncDevice;

use super::authenticator::{Authenticator, verify_auth_payload};
use super::errors::map_payload_error;
use super::session_manager::SessionManager;
use super::types::{AuthPhaseResult, AuthStep};
use crate::AssignedIp;
use crate::sessions::{SessionKeyUpdater, SessionTcpChannel};
use crate::tun::TunDeviceIo;

/// Helper function to extract TCP channel from Option.
///
/// # Errors
///
/// Returns an error with `ErrorKind::Other` if the channel is missing.
fn as_tcp_channel(
    channel: &mut Option<SessionTcpChannel<TcpStream>>,
) -> io::Result<&mut SessionTcpChannel<TcpStream>> {
    channel
        .as_mut()
        .ok_or_else(|| io::Error::other("tcp channel missing"))
}

#[cfg(test)]
fn as_tcp_channel_test<S>(
    channel: &mut Option<TcpChannel<S, SessionKeyUpdater>>,
) -> io::Result<&mut TcpChannel<S, SessionKeyUpdater>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    channel
        .as_mut()
        .ok_or_else(|| io::Error::other("tcp channel missing"))
}

/// TLS + AUTH handler that creates client sessions.
#[derive(Clone)]
pub struct AuthHandlerBase<T: TunDeviceIo> {
    acceptor: SslAcceptor,
    authenticator: Authenticator,
    sessions: SessionManager<T>,
    auth_timeout: std::time::Duration,
}

/// Default auth handler using a real TUN device.
pub type AuthHandler = AuthHandlerBase<AsyncDevice>;

impl<T: TunDeviceIo> AuthHandlerBase<T> {
    /// Build a new auth handler.
    #[must_use]
    pub const fn new(
        acceptor: SslAcceptor,
        authenticator: Authenticator,
        sessions: SessionManager<T>,
        auth_timeout: std::time::Duration,
    ) -> Self {
        Self {
            acceptor,
            authenticator,
            sessions,
            auth_timeout,
        }
    }

    /// Perform TLS + AUTH and spawn a client session on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS handshake, exporter, or socket IO fails.
    /// Returns `ErrorKind::TimedOut` if the auth phase times out.
    /// Returns `ErrorKind::ConnectionReset` if the connection is closed.
    pub async fn handle(&self, stream: TcpStream) -> io::Result<()> {
        let peer_addr = stream.peer_addr().ok();

        let tls = self.tls_handshake(stream, peer_addr.as_ref()).await?;
        let mut tcp = Some(TcpChannel::with_key_updater(
            tls,
            SessionKeyUpdater::new(self.sessions.metrics().clone()),
        ));

        let challenge = Self::generate_challenge(
            tcp.as_ref()
                .ok_or_else(|| io::Error::other("tcp channel missing"))?,
        )?;

        let result = self
            .run_auth_loop(&mut tcp, &challenge, peer_addr.as_ref())
            .await?;
        self.record_result(result);
        result.into_io_result()
    }

    /// Performs TLS handshake with timeout.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::TimedOut` if handshake times out.
    /// Returns `ErrorKind::Other` if handshake fails.
    async fn tls_handshake(
        &self,
        stream: TcpStream,
        peer_addr: Option<&SocketAddr>,
    ) -> io::Result<tokio_boring::SslStream<TcpStream>> {
        debug!(timeout_ms = self.auth_timeout.as_millis(), peer_addr = ?peer_addr, "starting TLS handshake");

        match time::timeout(self.auth_timeout, tls_accept(&self.acceptor, stream)).await {
            Ok(Ok(stream)) => {
                debug!(peer_addr = ?peer_addr, "TLS handshake completed");
                Ok(stream)
            }
            Ok(Err(err)) => {
                self.sessions.metrics().inc_auth_failures();
                warn!(peer_addr = ?peer_addr, error = ?err, "TLS handshake failed");
                Err(io::Error::other(format!("{err:?}")))
            }
            Err(_) => {
                self.sessions.metrics().inc_auth_failures();
                warn!(timeout_ms = self.auth_timeout.as_millis(), peer_addr = ?peer_addr, "TLS handshake timed out");
                Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "tls handshake timed out",
                ))
            }
        }
    }

    /// Generates auth challenge from TLS keying material.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::Other` if keying material export fails.
    fn generate_challenge(
        tcp: &SessionTcpChannel<TcpStream>,
    ) -> io::Result<[u8; AUTH_CHALLENGE_LEN]> {
        let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
        tcp.ssl()
            .export_keying_material(&mut challenge, "slt-auth-challenge", None)
            .map_err(|err| io::Error::other(format!("{err:?}")))?;
        Ok(challenge)
    }

    /// Runs the main auth loop, processing messages until completion.
    ///
    /// # Errors
    ///
    /// Returns IO errors from socket operations.
    async fn run_auth_loop(
        &self,
        tcp: &mut Option<SessionTcpChannel<TcpStream>>,
        challenge: &[u8; AUTH_CHALLENGE_LEN],
        peer_addr: Option<&SocketAddr>,
    ) -> io::Result<AuthPhaseResult> {
        let deadline = Instant::now() + self.auth_timeout;

        loop {
            let timeout_fut = time::sleep_until(deadline.into());
            tokio::pin!(timeout_fut);

            tokio::select! {
                () = timeout_fut.as_mut() => {
                    warn!(peer_addr = ?peer_addr, "auth phase timed out waiting for message");
                    return Ok(AuthPhaseResult::Timeout);
                },
                res = async {
                    as_tcp_channel(tcp)?.read_more().await
                } => {
                    let n = res?;
                    if n == 0 {
                        trace!(peer_addr = ?peer_addr, "connection closed during auth phase");
                        return Ok(AuthPhaseResult::ConnectionClosed);
                    }
                    trace!(bytes_read = n, peer_addr = ?peer_addr, "received data during auth phase");
                }
            }

            // Process all available messages
            loop {
                let msg_buf = match as_tcp_channel(tcp)?.try_pop_message(self.sessions.limits()) {
                    Ok(Some(buf)) => buf,
                    Ok(None) => break,
                    Err(e) => {
                        warn!(error = ?e, peer_addr = ?peer_addr, "message parse error");
                        if let Ok(t) = as_tcp_channel(tcp) {
                            let _ = self.send_auth_fail(t, AuthFailCode::Unknown).await;
                        }
                        return Ok(AuthPhaseResult::Failed(AuthFailCode::Unknown));
                    }
                };

                match self
                    .handle_auth_message(msg_buf.message(), tcp, challenge)
                    .await?
                {
                    AuthStep::Continue => {}
                    AuthStep::Done => return Ok(AuthPhaseResult::Success),
                }
            }
        }
    }

    /// Records the auth result in metrics.
    fn record_result(&self, result: AuthPhaseResult) {
        if result.is_failure() {
            self.sessions.metrics().inc_auth_failures();
        }
    }

    async fn handle_auth_message(
        &self,
        message: Message<'_>,
        tcp: &mut Option<SessionTcpChannel<TcpStream>>,
        challenge: &[u8; AUTH_CHALLENGE_LEN],
    ) -> io::Result<AuthStep> {
        match message {
            Message::Auth { payload } => self.handle_auth(payload, tcp, challenge).await,
            Message::Ping { payload } => self.handle_ping(payload, tcp).await,
            Message::Close { .. } => {
                trace!("received close message during auth phase");
                Ok(AuthStep::Done)
            }
            other => self.handle_unexpected_message(other, tcp).await,
        }
    }

    /// Handles AUTH message processing.
    async fn handle_auth(
        &self,
        payload: &[u8],
        tcp: &mut Option<SessionTcpChannel<TcpStream>>,
        challenge: &[u8; AUTH_CHALLENGE_LEN],
    ) -> io::Result<AuthStep> {
        let auth = AuthPayload::decode(payload).map_err(map_payload_error)?;
        trace!(client_id = %auth.client_id, assigned_ip = %auth.assigned_ipv4, "processing auth message");

        match self.verify_auth(&auth, challenge) {
            Ok(assigned_ip) => {
                self.sessions.metrics().inc_auth_successes();
                info!(client_id = %auth.client_id, assigned_ip = %assigned_ip, "authentication successful");

                let mut ok_buf = Vec::new();
                AuthOkPayload.encode(&mut ok_buf);
                self.send_message(as_tcp_channel(tcp)?, Message::AuthOk { payload: &ok_buf })
                    .await?;

                self.sessions
                    .create_session(auth.client_id, assigned_ip, tcp)?;
                Ok(AuthStep::Done)
            }
            Err(code) => {
                self.sessions.metrics().inc_auth_failures();
                warn!(client_id = %auth.client_id, assigned_ip = %auth.assigned_ipv4, code = ?code, "authentication failed");
                self.send_auth_fail(as_tcp_channel(tcp)?, code).await?;
                Ok(AuthStep::Done)
            }
        }
    }

    /// Handles PING message by responding with PONG.
    async fn handle_ping(
        &self,
        payload: &[u8],
        tcp: &mut Option<SessionTcpChannel<TcpStream>>,
    ) -> io::Result<AuthStep> {
        let ping_in = PingPayload::decode(payload).map_err(map_payload_error)?;
        trace!(nonce = ping_in.nonce, "received ping during auth phase");

        let mut pong_buf = Vec::with_capacity(8);
        PongPayload {
            nonce: ping_in.nonce,
        }
        .encode(&mut pong_buf);
        self.send_message(as_tcp_channel(tcp)?, Message::Pong { payload: &pong_buf })
            .await?;
        Ok(AuthStep::Continue)
    }

    /// Handles unexpected messages during auth phase.
    async fn handle_unexpected_message(
        &self,
        message: Message<'_>,
        tcp: &mut Option<SessionTcpChannel<TcpStream>>,
    ) -> io::Result<AuthStep> {
        self.sessions.metrics().inc_auth_failures();
        warn!(message = ?message, "received unexpected message during auth phase");
        self.send_auth_fail(as_tcp_channel(tcp)?, AuthFailCode::Unknown)
            .await?;
        Ok(AuthStep::Done)
    }

    fn verify_auth(
        &self,
        payload: &AuthPayload,
        challenge: &[u8; AUTH_CHALLENGE_LEN],
    ) -> Result<AssignedIp, AuthFailCode> {
        verify_auth_payload(&self.authenticator, payload, challenge)
    }

    async fn send_message(
        &self,
        tcp: &mut SessionTcpChannel<TcpStream>,
        message: Message<'_>,
    ) -> io::Result<()> {
        tcp.write_message(message).await
    }

    async fn send_auth_fail(
        &self,
        tcp: &mut SessionTcpChannel<TcpStream>,
        code: AuthFailCode,
    ) -> io::Result<()> {
        let payload = AuthFailPayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        self.send_message(tcp, Message::AuthFail { payload: &buf })
            .await
    }

    /// Test-only accessor to validate session queue size.
    #[cfg(test)]
    pub fn ensure_session_queue_size(&self) -> io::Result<()> {
        self.sessions.ensure_queue_size()
    }

    /// Test-only method to handle auth with a pre-established TLS stream.
    ///
    /// This bypasses the TLS accept step and uses the provided stream directly.
    #[cfg(test)]
    pub async fn handle_with_tls<S>(&self, tls: tokio_boring::SslStream<S>) -> io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let mut tcp: Option<TcpChannel<S, SessionKeyUpdater>> = Some(TcpChannel::with_key_updater(
            tls,
            SessionKeyUpdater::new(self.sessions.metrics().clone()),
        ));

        let challenge = {
            let tcp_ref = tcp
                .as_ref()
                .ok_or_else(|| io::Error::other("tcp channel missing"))?;
            let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
            tcp_ref
                .ssl()
                .export_keying_material(&mut challenge, "slt-auth-challenge", None)
                .map_err(|err| io::Error::other(format!("{err:?}")))?;
            challenge
        };

        let result = self.run_auth_loop_test(&mut tcp, &challenge).await?;
        self.record_result(result);
        result.into_io_result()
    }

    /// Test-only auth loop that works with generic streams.
    #[cfg(test)]
    async fn run_auth_loop_test<S>(
        &self,
        tcp: &mut Option<TcpChannel<S, SessionKeyUpdater>>,
        challenge: &[u8; AUTH_CHALLENGE_LEN],
    ) -> io::Result<AuthPhaseResult>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let deadline = Instant::now() + self.auth_timeout;

        loop {
            let timeout_fut = time::sleep_until(deadline.into());
            tokio::pin!(timeout_fut);

            tokio::select! {
                () = timeout_fut.as_mut() => {
                    return Ok(AuthPhaseResult::Timeout);
                },
                res = async {
                    as_tcp_channel_test(tcp)?.read_more().await
                } => {
                    let n = res?;
                    if n == 0 {
                        return Ok(AuthPhaseResult::ConnectionClosed);
                    }
                }
            }

            loop {
                let msg_buf =
                    match as_tcp_channel_test(tcp)?.try_pop_message(self.sessions.limits()) {
                        Ok(Some(buf)) => buf,
                        Ok(None) => break,
                        Err(_) => return Ok(AuthPhaseResult::Failed(AuthFailCode::Unknown)),
                    };

                match self
                    .handle_auth_message_test(msg_buf.message(), tcp, challenge)
                    .await?
                {
                    AuthStep::Continue => {}
                    AuthStep::Done => return Ok(AuthPhaseResult::Success),
                }
            }
        }
    }

    /// Test-only message handler that works with generic streams.
    #[cfg(test)]
    async fn handle_auth_message_test<S>(
        &self,
        message: Message<'_>,
        tcp: &mut Option<TcpChannel<S, SessionKeyUpdater>>,
        challenge: &[u8; AUTH_CHALLENGE_LEN],
    ) -> io::Result<AuthStep>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        match message {
            Message::Auth { payload } => {
                let auth = AuthPayload::decode(payload).map_err(map_payload_error)?;

                match self.verify_auth(&auth, challenge) {
                    Ok(assigned_ip) => {
                        self.sessions.metrics().inc_auth_successes();

                        // Send AuthOk
                        let mut ok_buf = Vec::new();
                        AuthOkPayload.encode(&mut ok_buf);
                        as_tcp_channel_test(tcp)?
                            .write_message(Message::AuthOk { payload: &ok_buf })
                            .await?;

                        self.sessions
                            .create_session_test(auth.client_id, assigned_ip, tcp)?;
                        Ok(AuthStep::Done)
                    }
                    Err(code) => {
                        self.sessions.metrics().inc_auth_failures();
                        let payload = AuthFailPayload { code };
                        let mut buf = Vec::with_capacity(1);
                        payload.encode(&mut buf);
                        as_tcp_channel_test(tcp)?
                            .write_message(Message::AuthFail { payload: &buf })
                            .await?;
                        Ok(AuthStep::Done)
                    }
                }
            }
            Message::Ping { payload } => {
                let ping_in = PingPayload::decode(payload).map_err(map_payload_error)?;
                let mut pong_buf = Vec::with_capacity(8);
                PongPayload {
                    nonce: ping_in.nonce,
                }
                .encode(&mut pong_buf);
                as_tcp_channel_test(tcp)?
                    .write_message(Message::Pong { payload: &pong_buf })
                    .await?;
                Ok(AuthStep::Continue)
            }
            Message::Close { .. } => Ok(AuthStep::Done),
            _ => {
                self.sessions.metrics().inc_auth_failures();
                let payload = AuthFailPayload {
                    code: AuthFailCode::Unknown,
                };
                let mut buf = Vec::with_capacity(1);
                payload.encode(&mut buf);
                as_tcp_channel_test(tcp)?
                    .write_message(Message::AuthFail { payload: &buf })
                    .await?;
                Ok(AuthStep::Done)
            }
        }
    }
}
