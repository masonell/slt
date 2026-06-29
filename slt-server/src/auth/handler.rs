use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use boring::ssl::SslAcceptor;
use slt_core::proto::{
    AUTH_CHALLENGE_LEN, AuthFailCode, AuthFailPayload, AuthOkPayload, AuthPayload, Message,
    PingPayload, PongPayload,
};
use slt_core::transport::tcp::TcpChannel;
use slt_core::types::ClientId;
use tokio::net::TcpStream;
use tokio::time;
use tokio_boring::accept as tls_accept;
use tracing::{debug, info, trace, warn};
use tun_rs::AsyncDevice;

use super::authenticator::{Authenticator, verify_auth_payload};
use super::error::{AuthError, TlsError};
use super::session_manager::SessionManager;
use super::types::{AuthPhaseResult, AuthStep};
use crate::AssignedIp;
use crate::sessions::{SessionKeyUpdater, SessionTcpChannel};
use crate::tun::TunDeviceIo;

/// Helper function to extract TCP channel from Option.
///
/// # Errors
///
/// Returns [`AuthError::Connection`] if the channel is missing.
fn as_tcp_channel<S>(
    channel: &mut Option<SessionTcpChannel<S>>,
) -> Result<&mut SessionTcpChannel<S>, AuthError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    channel.as_mut().ok_or_else(|| AuthError::Connection {
        source: io::Error::other("tcp channel missing"),
    })
}

/// TLS + AUTH handler that creates client sessions.
///
/// Manages the full authentication flow from incoming TCP connection through
/// TLS handshake to successful authentication and session spawning. Includes
/// timeout handling and metrics recording.
#[derive(Clone)]
pub struct AuthHandlerBase<T: TunDeviceIo> {
    acceptor: SslAcceptor,
    authenticator: Authenticator,
    sessions: SessionManager<T>,
    auth_timeout: std::time::Duration,
}

/// Default auth handler using a real TUN device.
///
/// Type alias for [`AuthHandlerBase`] parameterized with `AsyncDevice`,
/// used in production server configurations.
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
    /// This is the binary entry-point boundary: the typed `AuthError` from the
    /// internal auth flow is converted to `io::Error` here (via its `From` impl)
    /// so the historical `handle()` -> `io::Result<()>` contract is preserved
    /// for the TCP front-door task and the metrics tests that assert on
    /// `ErrorKind`. The structured error is preserved as the `io::Error`'s inner
    /// source, so the cause chain survives for `{:#}` and the log.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` whose kind is derived from the `AuthError`
    /// variant: `TimedOut` for auth/TLS timeouts, `ConnectionReset` for a peer
    /// disconnect, `InvalidData` for protocol decode failures, `Other` for TLS
    /// handshake / keying-material export faults, and the underlying kind for
    /// connection I/O.
    pub async fn handle(&self, stream: TcpStream) -> io::Result<()> {
        let peer_addr = stream.peer_addr().ok();
        let result = self.handle_stream(stream, peer_addr.as_ref()).await;
        self.record_result(&result);
        result.map(|_outcome| ()).map_err(AuthError::into)
    }

    async fn handle_stream(
        &self,
        stream: TcpStream,
        peer_addr: Option<&SocketAddr>,
    ) -> Result<AuthPhaseResult, AuthError> {
        let tls = self.tls_handshake(stream, peer_addr).await?;

        let mut tcp = Some(TcpChannel::with_key_updater(
            tls,
            SessionKeyUpdater::new(self.sessions.metrics().clone()),
        ));

        let mut create_session =
            |client_id: ClientId,
             assigned_ip: AssignedIp,
             tcp: &mut Option<SessionTcpChannel<TcpStream>>| {
                self.sessions.create_session(client_id, assigned_ip, tcp)
            };

        self.run_auth_flow(&mut tcp, peer_addr, &mut create_session)
            .await
    }

    /// Performs TLS handshake with timeout.
    async fn tls_handshake(
        &self,
        stream: TcpStream,
        peer_addr: Option<&SocketAddr>,
    ) -> Result<tokio_boring::SslStream<TcpStream>, AuthError> {
        debug!(timeout_ms = self.auth_timeout.as_millis(), peer_addr = ?peer_addr, "starting TLS handshake");

        match time::timeout(self.auth_timeout, tls_accept(&self.acceptor, stream)).await {
            Ok(Ok(stream)) => {
                debug!(peer_addr = ?peer_addr, "TLS handshake completed");
                Ok(stream)
            }
            Ok(Err(err)) => {
                warn!(peer_addr = ?peer_addr, error = %err, "TLS handshake failed");
                Err(AuthError::TlsHandshake {
                    source: TlsError::from_handshake_error(&err),
                })
            }
            Err(_) => {
                warn!(timeout_ms = self.auth_timeout.as_millis(), peer_addr = ?peer_addr, "TLS handshake timed out");
                Err(AuthError::TlsHandshakeTimeout)
            }
        }
    }

    /// Generates auth challenge from TLS keying material.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ChallengeExport`] if keying material export fails.
    /// The boring `ErrorStack` is preserved rather than stringified.
    fn generate_challenge<S>(
        tcp: &SessionTcpChannel<S>,
    ) -> Result<[u8; AUTH_CHALLENGE_LEN], AuthError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
        tcp.ssl()
            .export_keying_material(&mut challenge, "slt-auth-challenge", None)
            .map_err(|source| AuthError::ChallengeExport { source })?;
        Ok(challenge)
    }

    async fn run_auth_flow<S, F>(
        &self,
        tcp: &mut Option<SessionTcpChannel<S>>,
        peer_addr: Option<&SocketAddr>,
        create_session: &mut F,
    ) -> Result<AuthPhaseResult, AuthError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
        F: FnMut(ClientId, AssignedIp, &mut Option<SessionTcpChannel<S>>) -> io::Result<()>,
    {
        let challenge = Self::generate_challenge(as_tcp_channel(tcp)?)?;
        self.run_auth_loop(tcp, &challenge, peer_addr, create_session)
            .await
    }

    /// Runs the main auth loop, processing messages until completion.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` for transport failures (timeout, peer disconnect,
    /// I/O) and protocol decode errors. On-protocol auth outcomes
    /// (success / `AUTH_FAIL` sent) are returned as `Ok(AuthPhaseResult)`.
    async fn run_auth_loop<S, F>(
        &self,
        tcp: &mut Option<SessionTcpChannel<S>>,
        challenge: &[u8; AUTH_CHALLENGE_LEN],
        peer_addr: Option<&SocketAddr>,
        create_session: &mut F,
    ) -> Result<AuthPhaseResult, AuthError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
        F: FnMut(ClientId, AssignedIp, &mut Option<SessionTcpChannel<S>>) -> io::Result<()>,
    {
        let deadline = Instant::now() + self.auth_timeout;

        loop {
            let timeout_fut = time::sleep_until(deadline.into());
            tokio::pin!(timeout_fut);

            tokio::select! {
                () = timeout_fut.as_mut() => {
                    warn!(peer_addr = ?peer_addr, "auth phase timed out waiting for message");
                    return Err(AuthError::Timeout);
                },
                res = async {
                    as_tcp_channel(tcp)?.read_more().await
                } => {
                    // read_more returns io::Result<usize>; the channel-missing
                    // case is already typed via as_tcp_channel. Map the raw
                    // socket I/O into AuthError::Connection, preserving source.
                    let n = res.map_err(|source| AuthError::Connection { source })?;
                    if n == 0 {
                        trace!(peer_addr = ?peer_addr, "connection closed during auth phase");
                        return Err(AuthError::ConnectionClosed);
                    }
                    trace!(bytes_read = n, peer_addr = ?peer_addr, "received data during auth phase");
                }
            }

            loop {
                let msg_buf = match as_tcp_channel(tcp)?.try_pop_message(self.sessions.limits()) {
                    Ok(Some(buf)) => buf,
                    Ok(None) => break,
                    // FrameError flows via #[from]; MessageError via manual From.
                    Err(err) => {
                        // MessageError is not Display; render via Debug.
                        warn!(error = ?err, peer_addr = ?peer_addr, "message parse error");
                        if let Ok(channel) = as_tcp_channel(tcp) {
                            let _ = self.send_auth_fail(channel, AuthFailCode::Unknown).await;
                        }
                        return Err(err.into());
                    }
                };

                match self
                    .handle_auth_message(msg_buf.message(), tcp, challenge, create_session)
                    .await?
                {
                    AuthStep::Continue => {}
                    AuthStep::Done(result) => return Ok(result),
                }
            }
        }
    }

    async fn handle_auth_message<S, F>(
        &self,
        message: Message<'_>,
        tcp: &mut Option<SessionTcpChannel<S>>,
        challenge: &[u8; AUTH_CHALLENGE_LEN],
        create_session: &mut F,
    ) -> Result<AuthStep, AuthError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
        F: FnMut(ClientId, AssignedIp, &mut Option<SessionTcpChannel<S>>) -> io::Result<()>,
    {
        match message {
            Message::Auth { payload } => {
                self.handle_auth(payload, tcp, challenge, create_session)
                    .await
            }
            Message::Ping { payload } => self.handle_ping(payload, tcp).await,
            Message::Close { .. } => {
                trace!("received close message during auth phase");
                Ok(AuthStep::Done(AuthPhaseResult::Completed))
            }
            other => self.handle_unexpected_message(other, tcp).await,
        }
    }

    /// Handles AUTH message processing.
    async fn handle_auth<S, F>(
        &self,
        payload: &[u8],
        tcp: &mut Option<SessionTcpChannel<S>>,
        challenge: &[u8; AUTH_CHALLENGE_LEN],
        create_session: &mut F,
    ) -> Result<AuthStep, AuthError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
        F: FnMut(ClientId, AssignedIp, &mut Option<SessionTcpChannel<S>>) -> io::Result<()>,
    {
        // PayloadError flows via #[from], preserving the proto detail (was
        // map_payload_error).
        let auth = AuthPayload::decode(payload)?;
        trace!(client_id = %auth.client_id, assigned_ip = %auth.assigned_ipv4, "processing auth message");

        match self.verify_auth(&auth, challenge) {
            Ok(assigned_ip) => {
                info!(client_id = %auth.client_id, assigned_ip = %assigned_ip, "authentication successful");

                let mut ok_buf = Vec::new();
                AuthOkPayload.encode(&mut ok_buf);
                self.send_message(as_tcp_channel(tcp)?, Message::AuthOk { payload: &ok_buf })
                    .await?;

                create_session(auth.client_id, assigned_ip, tcp)
                    .map_err(|source| AuthError::Connection { source })?;
                Ok(AuthStep::Done(AuthPhaseResult::Authenticated))
            }
            Err(code) => {
                warn!(client_id = %auth.client_id, assigned_ip = %auth.assigned_ipv4, code = ?code, "authentication failed");
                self.send_auth_fail(as_tcp_channel(tcp)?, code).await?;
                Ok(AuthStep::Done(AuthPhaseResult::Rejected(code)))
            }
        }
    }

    /// Handles PING message by responding with PONG.
    async fn handle_ping<S>(
        &self,
        payload: &[u8],
        tcp: &mut Option<SessionTcpChannel<S>>,
    ) -> Result<AuthStep, AuthError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        // PayloadError flows via #[from], preserving the proto detail (was
        // map_payload_error).
        let ping_in = PingPayload::decode(payload)?;
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
    async fn handle_unexpected_message<S>(
        &self,
        message: Message<'_>,
        tcp: &mut Option<SessionTcpChannel<S>>,
    ) -> Result<AuthStep, AuthError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        warn!(message = ?message, "received unexpected message during auth phase");
        self.send_auth_fail(as_tcp_channel(tcp)?, AuthFailCode::Unknown)
            .await?;
        Ok(AuthStep::Done(AuthPhaseResult::Rejected(
            AuthFailCode::Unknown,
        )))
    }

    /// Record auth-phase metrics from the typed outcome.
    ///
    /// Both the success outcomes (`Ok(AuthPhaseResult)`) and the failure path
    /// (`Err(AuthError)`) can represent an auth attempt whose result should be
    /// counted: an on-protocol `Rejected(code)` increments failures the same way
    /// a transport/decode failure does (preserving the historical metric
    /// semantics where every `is_failure()` outcome counted).
    fn record_result(&self, result: &Result<AuthPhaseResult, AuthError>) {
        match result {
            Ok(outcome) => {
                if outcome.is_authenticated() {
                    self.sessions.metrics().inc_auth_successes();
                }
                if outcome.is_failure() {
                    self.sessions.metrics().inc_auth_failures();
                    // Genuine AUTH_FAIL rejection (the server chose to send a
                    // rejection code). Counted separately from transport/decode
                    // failures (the Err arm below) so the metric distinguishes
                    // "credential/config rejection" from "auth exchange never
                    // completed".
                    self.sessions.metrics().inc_auth_rejections();
                }
            }
            // Transport/decode failures (TLS handshake/timeout, auth-phase
            // timeout, peer disconnect, socket I/O, proto decode) increment
            // auth_failures but NOT auth_rejections.
            Err(_) => {
                self.sessions.metrics().inc_auth_failures();
            }
        }
    }

    fn verify_auth(
        &self,
        payload: &AuthPayload,
        challenge: &[u8; AUTH_CHALLENGE_LEN],
    ) -> Result<AssignedIp, AuthFailCode> {
        verify_auth_payload(&self.authenticator, payload, challenge)
    }

    async fn send_message<S>(
        &self,
        tcp: &mut SessionTcpChannel<S>,
        message: Message<'_>,
    ) -> Result<(), AuthError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        tcp.write_message(message).await.map_err(|err| match err {
            slt_core::transport::tcp::TcpWriteError::Frame(frame) => AuthError::Frame(frame),
            slt_core::transport::tcp::TcpWriteError::Io(source) => AuthError::Connection { source },
        })
    }

    async fn send_auth_fail<S>(
        &self,
        tcp: &mut SessionTcpChannel<S>,
        code: AuthFailCode,
    ) -> Result<(), AuthError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
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
    /// Mirrors [`Self::handle`]'s boundary conversion for test ergonomics: the
    /// typed `AuthError` is converted to `io::Error` so the test helpers that
    /// assert on `ErrorKind` continue to work.
    #[cfg(test)]
    pub async fn handle_with_tls<S>(&self, tls: tokio_boring::SslStream<S>) -> io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let mut tcp = Some(TcpChannel::with_key_updater(
            tls,
            SessionKeyUpdater::new(self.sessions.metrics().clone()),
        ));

        let mut create_session =
            |client_id: ClientId,
             assigned_ip: AssignedIp,
             tcp: &mut Option<SessionTcpChannel<S>>| {
                self.sessions
                    .create_session_test(client_id, assigned_ip, tcp)
            };

        let result = self
            .run_auth_flow(&mut tcp, None, &mut create_session)
            .await;
        self.record_result(&result);
        result.map(|_outcome| ()).map_err(AuthError::into)
    }
}
