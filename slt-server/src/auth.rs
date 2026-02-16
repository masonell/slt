//! Client authentication and session management.
//!
//! This module handles the authentication phase of client connections, from TLS
//! handshake through successful authentication, and spawns client sessions.
//!
//! # Architecture
//!
//! The module is organized around two main components:
//!
//! - [`Authenticator`]: Simple allowlist-based client validation against server config
//! - [`AuthHandlerBase`]: Handles TLS handshake and the AUTH protocol message exchange
//! - [`SessionManager`]: Manages session creation and lifecycle resources
//!
//! # Protocol Messages
//!
//! During the auth phase, the following messages are handled:
//! - `AUTH`: Contains client ID, assigned IP, challenge, and Ed25519 signature
//! - `PING`: Responded with `PONG` (for keepalive during auth)
//! - `CLOSE`: Ends the auth phase
//! - Any other message: Responded with `AUTH_FAIL`
//!
//! # Error Handling
//!
//! Authentication failures are categorized into:
//! - `AuthFailCode::UnknownClient`: Client ID not in allowlist
//! - `AuthFailCode::Disabled`: Client exists but is disabled
//! - `AuthFailCode::IpMismatch`: IP address doesn't match config
//! - `AuthFailCode::ChallengeInvalid`: Challenge mismatch
//! - `AuthFailCode::BadSignature`: Ed25519 signature verification failed
//! - `AuthFailCode::Unknown`: Protocol error or unexpected message

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use boring::ssl::SslAcceptor;
use ed25519_dalek::{Signature, VerifyingKey};
use slt_core::config::ServerConfig;
use slt_core::proto::{
    AUTH_CHALLENGE_LEN, AuthFailCode, AuthFailPayload, AuthOkPayload, AuthPayload, Message,
    MessageLimits, PayloadError, PingPayload, PongPayload,
};
use slt_core::transport::tcp::TcpChannel;
use slt_core::types::{ClientId, ServerClient};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time;
use tokio_boring::accept as tls_accept;
use tracing::{debug, error, info, trace, warn};
use tun_rs::AsyncDevice;

use super::AssignedIp;
use super::metrics::Metrics;
use super::registry::SessionRegistry;
use crate::sessions::{
    ClientSessionBase, SessionEvent, SessionKeyUpdater, SessionTcpChannel, SessionTimeouts,
};
use crate::tun::TunDeviceIo;

/// Result of an authentication operation with explicit failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthPhaseResult {
    /// Authentication completed successfully.
    Success,
    /// Authentication failed with a specific code.
    Failed(AuthFailCode),
    /// Operation timed out.
    Timeout,
    /// Connection was closed by peer.
    ConnectionClosed,
}

impl AuthPhaseResult {
    /// Converts the auth result to an IO result.
    ///
    /// Returns `Ok(())` for success, appropriate `io::Error` for failures.
    fn into_io_result(self) -> io::Result<()> {
        match self {
            Self::Success => Ok(()),
            Self::Failed(code) => Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!("auth failed: {code:?}"),
            )),
            Self::Timeout => Err(io::Error::new(ErrorKind::TimedOut, "auth timed out")),
            Self::ConnectionClosed => Err(io::Error::new(
                ErrorKind::ConnectionReset,
                "connection closed",
            )),
        }
    }

    /// Returns true if this result indicates a failure.
    const fn is_failure(self) -> bool {
        matches!(
            self,
            Self::Failed(_) | Self::Timeout | Self::ConnectionClosed
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthStep {
    Continue,
    Done,
}

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

/// Manages session creation and lifecycle.
///
/// Encapsulates all resources needed to spawn and manage client sessions.
#[derive(Clone)]
pub struct SessionManager<T: TunDeviceIo> {
    registry: Arc<SessionRegistry>,
    metrics: Arc<Metrics>,
    tun: Arc<T>,
    udp_socket: Arc<tokio::net::UdpSocket>,
    limits: MessageLimits,
    session_timeouts: SessionTimeouts,
    session_queue_size: usize,
}

impl<T: TunDeviceIo> SessionManager<T> {
    /// Creates a new session manager.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        registry: Arc<SessionRegistry>,
        metrics: Arc<Metrics>,
        tun: Arc<T>,
        udp_socket: Arc<tokio::net::UdpSocket>,
        limits: MessageLimits,
        session_timeouts: SessionTimeouts,
        session_queue_size: usize,
    ) -> Self {
        Self {
            registry,
            metrics,
            tun,
            udp_socket,
            limits,
            session_timeouts,
            session_queue_size,
        }
    }

    /// Returns a reference to the metrics.
    #[must_use]
    pub const fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Returns the message limits.
    #[must_use]
    pub const fn limits(&self) -> MessageLimits {
        self.limits
    }

    /// Validates that session queue size is non-zero.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` error if queue size is zero.
    pub fn ensure_queue_size(&self) -> io::Result<()> {
        if self.session_queue_size == 0 {
            error!("session_queue_size must be non-zero");
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session_queue_size must be non-zero",
            ));
        }
        Ok(())
    }

    /// Spawns a new client session after successful authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if queue size is zero or channel allocation fails.
    fn spawn_session(
        &self,
        client_id: ClientId,
        assigned_ip: AssignedIp,
        tcp_channel: SessionTcpChannel<TcpStream>,
        tx: mpsc::Sender<SessionEvent>,
        rx: mpsc::Receiver<SessionEvent>,
    ) {
        let (handle, old) = self
            .registry
            .register_session(client_id, assigned_ip, tx.clone());

        if let Some(old) = old {
            debug!(client_id = %client_id, session_id = %handle.session_id, replaced_session_id = %old.session_id, "replacing existing session");
            tokio::spawn(async move {
                let _ = old.tx.send(SessionEvent::Shutdown).await;
            });
        }

        let session = ClientSessionBase::new(
            handle.session_id,
            client_id,
            assigned_ip,
            tcp_channel,
            self.tun.clone(),
            self.udp_socket.clone(),
            self.registry.clone(),
            self.metrics.clone(),
            tx,
            rx,
            self.limits,
            self.session_timeouts,
        );

        tokio::spawn(async move {
            let _ = session.run().await;
        });
    }

    /// Creates session channels and spawns the session.
    ///
    /// # Errors
    ///
    /// Returns an error if queue size is zero or tcp channel is missing.
    pub fn create_session(
        &self,
        client_id: ClientId,
        assigned_ip: AssignedIp,
        tcp: &mut Option<SessionTcpChannel<TcpStream>>,
    ) -> io::Result<()> {
        self.ensure_queue_size()?;
        let (tx, rx) = mpsc::channel(self.session_queue_size);

        let tcp_channel = tcp
            .take()
            .ok_or_else(|| io::Error::other("tcp channel missing"))?;

        self.spawn_session(client_id, assigned_ip, tcp_channel, tx, rx);
        Ok(())
    }

    /// Test-only session spawning for generic streams.
    #[cfg(test)]
    fn spawn_session_test<S>(
        &self,
        client_id: ClientId,
        assigned_ip: AssignedIp,
        tcp_channel: TcpChannel<S, SessionKeyUpdater>,
        tx: mpsc::Sender<SessionEvent>,
        rx: mpsc::Receiver<SessionEvent>,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let (handle, old) = self
            .registry
            .register_session(client_id, assigned_ip, tx.clone());

        if let Some(old) = old {
            tokio::spawn(async move {
                let _ = old.tx.send(SessionEvent::Shutdown).await;
            });
        }

        let session = ClientSessionBase::new(
            handle.session_id,
            client_id,
            assigned_ip,
            tcp_channel,
            self.tun.clone(),
            self.udp_socket.clone(),
            self.registry.clone(),
            self.metrics.clone(),
            tx,
            rx,
            self.limits,
            self.session_timeouts,
        );

        tokio::spawn(async move {
            let _ = session.run().await;
        });
    }

    /// Test-only session creation for generic streams.
    #[cfg(test)]
    pub fn create_session_test<S>(
        &self,
        client_id: ClientId,
        assigned_ip: AssignedIp,
        tcp: &mut Option<TcpChannel<S, SessionKeyUpdater>>,
    ) -> io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        self.ensure_queue_size()?;
        let (tx, rx) = mpsc::channel(self.session_queue_size);

        let tcp_channel = tcp
            .take()
            .ok_or_else(|| io::Error::other("tcp channel missing"))?;

        self.spawn_session_test(client_id, assigned_ip, tcp_channel, tx, rx);
        Ok(())
    }
}

/// Simple allowlist-based authenticator.
#[derive(Debug, Clone)]
pub struct Authenticator {
    clients_config: HashMap<ClientId, ServerClient>,
}

impl Authenticator {
    /// Build an authenticator from the server config allowlist.
    #[must_use]
    pub fn from_config(config: &ServerConfig) -> Self {
        let clients = config
            .clients
            .iter()
            .cloned()
            .map(|client| (client.client_id, client))
            .collect();
        Self {
            clients_config: clients,
        }
    }

    /// Returns the configured client entry, if present.
    #[must_use]
    pub fn get(&self, client_id: &ClientId) -> Option<&ServerClient> {
        self.clients_config.get(client_id)
    }

    /// Returns true if the client exists and is enabled.
    #[must_use]
    pub fn is_enabled(&self, client_id: &ClientId) -> bool {
        self.clients_config
            .get(client_id)
            .is_some_and(|c| c.enabled)
    }

    /// Creates an authenticator with the given clients (test-only).
    #[cfg(test)]
    #[must_use]
    pub fn new(clients: impl IntoIterator<Item = ServerClient>) -> Self {
        Self {
            clients_config: clients
                .into_iter()
                .map(|client| (client.client_id, client))
                .collect(),
        }
    }
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
                warn!(peer_addr = ?peer_addr, error = ?err, "TLS handshake failed");
                Err(io::Error::other(format!("{err:?}")))
            }
            Err(_) => {
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

#[cfg(test)]
use slt_core::proto::MessageError;

#[cfg(test)]
fn map_message_error(err: MessageError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("message error: {err:?}"),
    )
}

fn map_payload_error(err: PayloadError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("payload error: {err:?}"),
    )
}

fn verify_auth_payload(
    authenticator: &Authenticator,
    payload: &AuthPayload,
    challenge: &[u8; AUTH_CHALLENGE_LEN],
) -> Result<AssignedIp, AuthFailCode> {
    let client = authenticator
        .get(&payload.client_id)
        .ok_or(AuthFailCode::UnknownClient)?;
    trace!(client_id = %payload.client_id, "looking up client in authenticator");

    if !client.enabled {
        trace!(client_id = %payload.client_id, "client is disabled");
        return Err(AuthFailCode::Disabled);
    }
    if client.assigned_ipv4 != payload.assigned_ipv4 {
        trace!(client_id = %payload.client_id, expected = %client.assigned_ipv4, provided = %payload.assigned_ipv4, "IP address mismatch");
        return Err(AuthFailCode::IpMismatch);
    }
    if &payload.challenge != challenge {
        trace!(client_id = %payload.client_id, "challenge mismatch");
        return Err(AuthFailCode::ChallengeInvalid);
    }

    let mut context = Vec::with_capacity(11 + 16 + 4 + challenge.len());
    context.extend_from_slice(b"slt-auth-v1");
    context.extend_from_slice(payload.client_id.as_bytes());
    context.extend_from_slice(&payload.assigned_ipv4.octets());
    context.extend_from_slice(challenge);

    let key = VerifyingKey::from_bytes(client.pubkey_ed25519.as_bytes()).map_err(|_| {
        trace!(client_id = %payload.client_id, "failed to parse verifying key");
        AuthFailCode::BadSignature
    })?;
    let signature = Signature::from_bytes(&payload.signature);
    key.verify_strict(&context, &signature).map_err(|_| {
        trace!(client_id = %payload.client_id, "signature verification failed");
        AuthFailCode::BadSignature
    })?;

    trace!(client_id = %payload.client_id, "signature verified successfully");
    Ok(AssignedIp(client.assigned_ipv4))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use ed25519_dalek::{Signer, SigningKey};
    use slt_core::proto::AUTH_CHALLENGE_LEN;
    use slt_core::types::{
        PubKeyEd25519, ServerNetworkConfig, ServerTimingConfig, ServerTlsConfig, SharedSecret,
        TlsMaterial, TunConfig,
    };

    use super::*;
    #[allow(unused_imports)]
    use super::{MessageError, map_message_error};

    fn make_client(
        client_id: ClientId,
        signing_key: &SigningKey,
        assigned_ipv4: Ipv4Addr,
        enabled: bool,
    ) -> ServerClient {
        ServerClient {
            client_id,
            pubkey_ed25519: PubKeyEd25519(signing_key.verifying_key().to_bytes()),
            assigned_ipv4,
            enabled,
        }
    }

    fn make_payload(
        client_id: ClientId,
        assigned_ipv4: Ipv4Addr,
        challenge: [u8; AUTH_CHALLENGE_LEN],
        signing_key: &SigningKey,
    ) -> AuthPayload {
        let mut context = Vec::with_capacity(11 + 16 + 4 + challenge.len());
        context.extend_from_slice(b"slt-auth-v1");
        context.extend_from_slice(client_id.as_bytes());
        context.extend_from_slice(&assigned_ipv4.octets());
        context.extend_from_slice(&challenge);
        let signature = signing_key.sign(&context).to_bytes();
        AuthPayload {
            client_id,
            assigned_ipv4,
            challenge,
            signature,
        }
    }

    #[test]
    fn authenticator_from_config_tracks_enabled_clients() {
        let client_enabled_id = ClientId([0x01; 16]);
        let client_disabled_id = ClientId([0x02; 16]);
        let client_enabled = ServerClient {
            client_id: client_enabled_id,
            pubkey_ed25519: PubKeyEd25519([0x11; 32]),
            assigned_ipv4: Ipv4Addr::new(10, 0, 0, 1),
            enabled: true,
        };
        let client_disabled = ServerClient {
            client_id: client_disabled_id,
            pubkey_ed25519: PubKeyEd25519([0x22; 32]),
            assigned_ipv4: Ipv4Addr::new(10, 0, 0, 2),
            enabled: false,
        };

        let config = ServerConfig {
            server_secret: SharedSecret([0xAA; 32]),
            network: ServerNetworkConfig {
                listen_tcp: SocketAddr::from(([127, 0, 0, 1], 0)),
                listen_udp: SocketAddr::from(([127, 0, 0, 1], 0)),
                nginx_tcp_upstream: SocketAddr::from(([127, 0, 0, 1], 0)),
                nginx_udp_upstream: SocketAddr::from(([127, 0, 0, 1], 0)),
            },
            tls: ServerTlsConfig {
                tls_cert: TlsMaterial::File {
                    file: "vendor/boring/test/cert.pem".into(),
                },
                tls_key: TlsMaterial::File {
                    file: "vendor/boring/test/key.pem".into(),
                },
            },
            tun: TunConfig {
                tun_name: "test0".to_string(),
                tun_mtu: 1500,
            },
            timing: ServerTimingConfig {
                ping_min: std::time::Duration::from_secs(1),
                ping_max: std::time::Duration::from_secs(2),
                auth_timeout: std::time::Duration::from_secs(3),
                idle_timeout: std::time::Duration::from_secs(4),
            },
            udp_nat_max_entries: 32,
            session_queue_size: 8,
            clients: vec![client_enabled, client_disabled],
        };

        let auth = Authenticator::from_config(&config);
        assert!(auth.is_enabled(&client_enabled_id));
        assert!(!auth.is_enabled(&client_disabled_id));
        assert!(auth.get(&client_enabled_id).is_some());
    }

    #[test]
    fn verify_auth_accepts_valid_payload() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let client_id = ClientId([0xA1; 16]);
        let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 9);
        let challenge = [0x5A; AUTH_CHALLENGE_LEN];
        let client = make_client(client_id, &signing_key, assigned_ipv4, true);
        let authenticator = Authenticator {
            clients_config: vec![(client.client_id, client)].into_iter().collect(),
        };

        let payload = make_payload(client_id, assigned_ipv4, challenge, &signing_key);
        let assigned = verify_auth_payload(&authenticator, &payload, &challenge).unwrap();
        assert_eq!(assigned, AssignedIp(assigned_ipv4));
    }

    #[test]
    fn verify_auth_reports_mismatches() {
        let signing_key = SigningKey::from_bytes(&[0x55; 32]);
        let client_id = ClientId([0xB2; 16]);
        let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 10);
        let challenge = [0x6B; AUTH_CHALLENGE_LEN];
        let client = make_client(client_id, &signing_key, assigned_ipv4, true);
        let authenticator = Authenticator {
            clients_config: vec![(client.client_id, client)].into_iter().collect(),
        };

        let wrong_ip = Ipv4Addr::new(10, 0, 0, 11);
        let payload = make_payload(client_id, wrong_ip, challenge, &signing_key);
        assert_eq!(
            verify_auth_payload(&authenticator, &payload, &challenge),
            Err(AuthFailCode::IpMismatch)
        );

        let mut wrong_challenge = challenge;
        wrong_challenge[0] ^= 0xFF;
        let payload = make_payload(client_id, assigned_ipv4, wrong_challenge, &signing_key);
        assert_eq!(
            verify_auth_payload(&authenticator, &payload, &challenge),
            Err(AuthFailCode::ChallengeInvalid)
        );
    }

    #[test]
    fn verify_auth_reports_disabled_or_unknown() {
        let signing_key = SigningKey::from_bytes(&[0x77; 32]);
        let client_id = ClientId([0xC3; 16]);
        let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 12);
        let challenge = [0x7C; AUTH_CHALLENGE_LEN];
        let client = make_client(client_id, &signing_key, assigned_ipv4, false);
        let authenticator = Authenticator {
            clients_config: vec![(client.client_id, client)].into_iter().collect(),
        };

        let payload = make_payload(client_id, assigned_ipv4, challenge, &signing_key);
        assert_eq!(
            verify_auth_payload(&authenticator, &payload, &challenge),
            Err(AuthFailCode::Disabled)
        );

        let unknown_id = ClientId([0xD4; 16]);
        let payload = make_payload(unknown_id, assigned_ipv4, challenge, &signing_key);
        assert_eq!(
            verify_auth_payload(&authenticator, &payload, &challenge),
            Err(AuthFailCode::UnknownClient)
        );
    }

    #[test]
    fn verify_auth_rejects_bad_signature() {
        let signing_key = SigningKey::from_bytes(&[0x88; 32]);
        let other_key = SigningKey::from_bytes(&[0x99; 32]);
        let client_id = ClientId([0xE5; 16]);
        let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 13);
        let challenge = [0x8D; AUTH_CHALLENGE_LEN];
        let client = make_client(client_id, &signing_key, assigned_ipv4, true);
        let authenticator = Authenticator {
            clients_config: vec![(client.client_id, client)].into_iter().collect(),
        };

        let payload = make_payload(client_id, assigned_ipv4, challenge, &other_key);
        assert_eq!(
            verify_auth_payload(&authenticator, &payload, &challenge),
            Err(AuthFailCode::BadSignature)
        );
    }

    #[test]
    fn map_message_error_converts_to_io_error() {
        use slt_core::proto::{FrameError, MessageError};

        let err = map_message_error(MessageError::DataTooLarge { len: 100, max: 50 });
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("message error"));

        let err = map_message_error(MessageError::Frame(FrameError::UnknownType(0xFF)));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("message error"));
    }

    #[test]
    fn map_payload_error_converts_to_io_error() {
        use slt_core::proto::PayloadError;

        let err = map_payload_error(PayloadError::LengthMismatch {
            expected: 32,
            actual: 16,
        });
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("payload error"));

        let err = map_payload_error(PayloadError::InvalidCipher(99));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("payload error"));
    }

    #[test]
    fn ensure_session_queue_size_returns_ok_when_nonzero() {
        use crate::test_support::TestAuthHandler;

        let (handler, _registry, _metrics) = TestAuthHandler::builder()
            .with_session_queue_size(8)
            .build();

        assert!(handler.inner.ensure_session_queue_size().is_ok());
    }

    #[test]
    fn ensure_session_queue_size_returns_error_when_zero() {
        use crate::test_support::TestAuthHandler;

        let (handler, _registry, _metrics) = TestAuthHandler::builder()
            .with_session_queue_size(0)
            .build();

        let result = handler.inner.ensure_session_queue_size();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("session_queue_size"));
    }

    // =========================================================================
    // Integration tests using TLS pairs
    // =========================================================================

    use slt_core::proto::ClosePayload;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Duration, timeout};

    use crate::test_support::{TestAuthHandler, TlsDuplexStream, tls_pair};

    async fn read_message(
        stream: &mut TlsDuplexStream,
        limits: MessageLimits,
    ) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tls closed"));
            }
            buf.extend_from_slice(&chunk[..n]);
            match slt_core::proto::decode_message(&buf, limits) {
                Ok(Some((_msg, _))) => return Ok(buf),
                Ok(None) => {}
                Err(err) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("message error: {err:?}"),
                    ));
                }
            }
        }
    }

    #[tokio::test]
    async fn auth_phase_responds_to_ping_with_pong() {
        let (handler, _registry, _metrics) = TestAuthHandler::builder()
            .with_auth_timeout(Duration::from_secs(5))
            .build_async()
            .await;

        let (server_tls, mut client_tls) = tls_pair().await;
        let limits = MessageLimits::from_mtu(1500);

        // Spawn the auth handler
        let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

        // Send a ping
        let nonce = 0xA1B2_C3D4_E5F6_0708u64;
        let ping_payload = PingPayload { nonce };
        let mut ping_buf = Vec::new();
        ping_payload.encode(&mut ping_buf);
        let mut frame = Vec::new();
        slt_core::proto::encode_message(Message::Ping { payload: &ping_buf }, &mut frame).unwrap();
        client_tls.write_all(&frame).await.unwrap();

        // Read the pong response
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

        // Close the connection to end the auth loop
        let close = ClosePayload {
            code: slt_core::proto::CloseCode::Normal,
        };
        let mut close_buf = Vec::new();
        close.encode(&mut close_buf);
        let mut frame = Vec::new();
        slt_core::proto::encode_message(
            Message::Close {
                payload: &close_buf,
            },
            &mut frame,
        )
        .unwrap();
        client_tls.write_all(&frame).await.unwrap();

        let _ = handle.await.unwrap();
    }

    #[tokio::test]
    async fn auth_phase_handles_close_message() {
        let (handler, _registry, _metrics) = TestAuthHandler::builder()
            .with_auth_timeout(Duration::from_secs(5))
            .build_async()
            .await;

        let (server_tls, _client_tls) = tls_pair().await;

        // Spawn the auth handler
        let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

        // Drop the client side - this will cause the server to read 0 bytes
        drop(_client_tls);

        // Handler should complete
        let result = timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn auth_phase_rejects_unexpected_message_with_auth_fail() {
        let (handler, _registry, _metrics) = TestAuthHandler::builder()
            .with_auth_timeout(Duration::from_secs(5))
            .build_async()
            .await;

        let (server_tls, mut client_tls) = tls_pair().await;
        let limits = MessageLimits::from_mtu(1500);

        // Spawn the auth handler
        let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

        // Send an unexpected message (AuthOk from client is invalid)
        let mut frame = Vec::new();
        slt_core::proto::encode_message(Message::AuthOk { payload: &[] }, &mut frame).unwrap();
        client_tls.write_all(&frame).await.unwrap();

        // Read the auth fail response
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
                assert_eq!(fail.code, AuthFailCode::Unknown);
            }
            _ => panic!("expected auth fail, got {message:?}"),
        }

        let _ = handle.await.unwrap();
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

        // Get the challenge from the TLS keying material
        let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
        server_tls
            .ssl()
            .export_keying_material(&mut challenge, "slt-auth-challenge", None)
            .unwrap();

        // Spawn the auth handler
        let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

        // Build and send auth message
        let auth_payload = make_payload(client_id, assigned_ipv4, challenge, &signing_key);
        let mut auth_buf = Vec::new();
        auth_payload.encode(&mut auth_buf);
        let mut frame = Vec::new();
        slt_core::proto::encode_message(Message::Auth { payload: &auth_buf }, &mut frame).unwrap();
        client_tls.write_all(&frame).await.unwrap();

        // Read the auth ok response
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

        // Verify session was registered
        assert!(registry.lookup_ip(assigned_ipv4).is_some());

        // Verify metrics
        assert_eq!(metrics.snapshot().auth_successes, 1);

        let _ = handle.await.unwrap();
    }

    #[tokio::test]
    async fn auth_phase_failed_authentication_sends_auth_fail() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let client_id = ClientId([0xA1; 16]);
        let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 9);
        let client = make_client(client_id, &signing_key, assigned_ipv4, false); // disabled

        let (handler, _registry, metrics) = TestAuthHandler::builder()
            .with_client(client)
            .with_auth_timeout(Duration::from_secs(5))
            .build_async()
            .await;

        let (server_tls, mut client_tls) = tls_pair().await;
        let limits = MessageLimits::from_mtu(1500);

        // Get the challenge
        let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
        server_tls
            .ssl()
            .export_keying_material(&mut challenge, "slt-auth-challenge", None)
            .unwrap();

        // Spawn the auth handler
        let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

        // Build and send auth message
        let auth_payload = make_payload(client_id, assigned_ipv4, challenge, &signing_key);
        let mut auth_buf = Vec::new();
        auth_payload.encode(&mut auth_buf);
        let mut frame = Vec::new();
        slt_core::proto::encode_message(Message::Auth { payload: &auth_buf }, &mut frame).unwrap();
        client_tls.write_all(&frame).await.unwrap();

        // Read the auth fail response
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

        // Verify metrics
        assert_eq!(metrics.snapshot().auth_failures, 1);

        let _ = handle.await.unwrap();
    }

    #[tokio::test]
    async fn auth_phase_timeout_increments_failure_metrics() {
        let (handler, _registry, metrics) = TestAuthHandler::builder()
            .with_auth_timeout(Duration::from_millis(50))
            .build_async()
            .await;

        let (server_tls, _client_tls) = tls_pair().await;

        // Spawn the auth handler
        let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

        // Wait for timeout
        let _ = handle.await.unwrap();

        // Verify failure was recorded
        assert_eq!(metrics.snapshot().auth_failures, 1);
    }

    #[tokio::test]
    async fn auth_phase_connection_close_increments_failure_metrics() {
        let (handler, _registry, metrics) = TestAuthHandler::builder()
            .with_auth_timeout(Duration::from_secs(5))
            .build_async()
            .await;

        let (server_tls, client_tls) = tls_pair().await;

        // Spawn the auth handler
        let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

        // Close the client side immediately
        drop(client_tls);

        // Wait for handler to complete
        let _ = handle.await.unwrap();

        // Verify failure was recorded
        assert_eq!(metrics.snapshot().auth_failures, 1);
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

        // Pre-register an old session
        let (old_tx, mut old_rx) = tokio::sync::mpsc::channel(1);
        registry.register_session(client_id, AssignedIp(assigned_ipv4), old_tx);

        let (server_tls, mut client_tls) = tls_pair().await;
        let limits = MessageLimits::from_mtu(1500);

        // Get the challenge
        let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
        server_tls
            .ssl()
            .export_keying_material(&mut challenge, "slt-auth-challenge", None)
            .unwrap();

        // Spawn the auth handler
        let handle = tokio::spawn(async move { handler.inner.handle_with_tls(server_tls).await });

        // Send auth message
        let auth_payload = make_payload(client_id, assigned_ipv4, challenge, &signing_key);
        let mut auth_buf = Vec::new();
        auth_payload.encode(&mut auth_buf);
        let mut frame = Vec::new();
        slt_core::proto::encode_message(Message::Auth { payload: &auth_buf }, &mut frame).unwrap();
        client_tls.write_all(&frame).await.unwrap();

        // Read auth ok
        let _ = timeout(
            Duration::from_secs(2),
            read_message(&mut client_tls, limits),
        )
        .await
        .unwrap();

        // Verify old session received shutdown
        let event = timeout(Duration::from_millis(100), old_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(event, SessionEvent::Shutdown));

        // Verify new session is registered (lookup succeeds)
        assert!(registry.lookup_ip(assigned_ipv4).is_some());

        let _ = handle.await.unwrap();
    }
}
