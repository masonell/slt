//! Client authentication helpers.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use boring::ssl::SslAcceptor;
use ed25519_dalek::{Signature, VerifyingKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time;
use tokio_boring::accept as tls_accept;
use tun_rs::AsyncDevice;

use crate::config::{ServerClient, ServerConfig};
use crate::proto::{
    AuthFailCode, AuthFailPayload, AuthOkPayload, AuthPayload, FrameError, Message, MessageError,
    MessageLimits, PayloadError, PingPayload, PongPayload, decode_message, encode_message,
};
use crate::types::ClientId;

use super::AssignedIp;
use super::registry::SessionRegistry;
use super::sessions::{ClientSessionBase, SessionEvent, SessionTimeouts};
use super::tun::TunDeviceIo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthStep {
    Continue,
    Done,
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
}

/// TLS + AUTH handler that creates client sessions.
#[derive(Clone)]
pub struct AuthHandlerBase<T: TunDeviceIo> {
    acceptor: SslAcceptor,
    authenticator: Authenticator,
    registry: Arc<SessionRegistry>,
    tun: Arc<T>,
    udp_socket: Arc<tokio::net::UdpSocket>,
    limits: MessageLimits,
    session_timeouts: SessionTimeouts,
    auth_timeout: std::time::Duration,
    session_queue_size: usize,
}

/// Default auth handler using a real TUN device.
pub type AuthHandler = AuthHandlerBase<AsyncDevice>;

impl<T: TunDeviceIo> AuthHandlerBase<T> {
    /// Build a new auth handler.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        acceptor: SslAcceptor,
        authenticator: Authenticator,
        registry: Arc<SessionRegistry>,
        tun: Arc<T>,
        udp_socket: Arc<tokio::net::UdpSocket>,
        limits: MessageLimits,
        session_timeouts: SessionTimeouts,
        auth_timeout: std::time::Duration,
        session_queue_size: usize,
    ) -> Self {
        Self {
            acceptor,
            authenticator,
            registry,
            tun,
            udp_socket,
            limits,
            session_timeouts,
            auth_timeout,
            session_queue_size,
        }
    }

    /// Perform TLS + AUTH and spawn a client session on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS handshake, exporter, or socket IO fails.
    pub async fn handle(&self, stream: TcpStream) -> io::Result<()> {
        let mut tls = Some(
            tls_accept(&self.acceptor, stream)
                .await
                .map_err(|err| io::Error::other(format!("{err:?}")))?,
        );

        let mut challenge = [0u8; crate::proto::AUTH_CHALLENGE_LEN];
        let tls_ref = tls
            .as_ref()
            .ok_or_else(|| io::Error::other("tls stream missing"))?;
        tls_ref
            .ssl()
            .export_keying_material(&mut challenge, "slt-auth-challenge", None)
            .map_err(|err| io::Error::other(format!("{err:?}")))?;

        let deadline = Instant::now() + self.auth_timeout;
        let mut buf = Vec::with_capacity(16 * 1024);

        loop {
            let timeout = time::sleep_until(deadline.into());
            let tls_ref = tls
                .as_mut()
                .ok_or_else(|| io::Error::other("tls stream missing"))?;
            tokio::select! {
                () = timeout => return Ok(()),
                res = tls_ref.read_buf(&mut buf) => {
                    let n = res?;
                    if n == 0 {
                        return Ok(());
                    }
                }
            }

            loop {
                let decoded = decode_message(&buf, self.limits).map_err(map_message_error)?;
                let Some((_, consumed)) = decoded else {
                    break;
                };

                let rest = buf.split_off(consumed);
                let frame_buf = std::mem::replace(&mut buf, rest);
                let decoded = decode_message(&frame_buf, self.limits).map_err(map_message_error)?;
                let Some((message, _)) = decoded else {
                    break;
                };

                match self
                    .handle_auth_message(message, &mut tls, &mut buf, &challenge)
                    .await?
                {
                    AuthStep::Continue => {}
                    AuthStep::Done => return Ok(()),
                }

                drop(frame_buf);
            }
        }
    }

    async fn handle_auth_message(
        &self,
        message: Message<'_>,
        tls: &mut Option<tokio_boring::SslStream<TcpStream>>,
        buf: &mut Vec<u8>,
        challenge: &[u8; crate::proto::AUTH_CHALLENGE_LEN],
    ) -> io::Result<AuthStep> {
        match message {
            Message::Auth { payload } => {
                let auth = AuthPayload::decode(payload).map_err(map_payload_error)?;
                match self.verify_auth(&auth, challenge) {
                    Ok(assigned_ip) => {
                        let mut ok_buf = Vec::new();
                        let ok = AuthOkPayload;
                        ok.encode(&mut ok_buf);
                        {
                            let tls_ref = tls
                                .as_mut()
                                .ok_or_else(|| io::Error::other("tls stream missing"))?;
                            self.send_message(tls_ref, Message::AuthOk { payload: &ok_buf })
                                .await?;
                        }

                        self.ensure_session_queue_size()?;
                        let (tx, rx) = mpsc::channel(self.session_queue_size);
                        let (handle, old) =
                            self.registry
                                .register_session(auth.client_id, assigned_ip, tx.clone());
                        if let Some(old) = old {
                            tokio::spawn(async move {
                                let _ = old.tx.send(SessionEvent::Shutdown).await;
                            });
                        }

                        let tls_stream = tls
                            .take()
                            .ok_or_else(|| io::Error::other("tls stream missing"))?;
                        let session = ClientSessionBase::new(
                            handle.session_id,
                            auth.client_id,
                            assigned_ip,
                            tls_stream,
                            self.tun.clone(),
                            self.udp_socket.clone(),
                            self.registry.clone(),
                            tx,
                            rx,
                            self.limits,
                            self.session_timeouts,
                            std::mem::take(buf),
                        );

                        tokio::spawn(async move {
                            let _ = session.run().await;
                        });

                        Ok(AuthStep::Done)
                    }
                    Err(code) => {
                        let tls_ref = tls
                            .as_mut()
                            .ok_or_else(|| io::Error::other("tls stream missing"))?;
                        self.send_auth_fail(tls_ref, code).await?;
                        Ok(AuthStep::Done)
                    }
                }
            }
            Message::Ping { payload } => {
                let ping_in = PingPayload::decode(payload).map_err(map_payload_error)?;
                let pong_out = PongPayload {
                    nonce: ping_in.nonce,
                };
                let mut pong_buf = Vec::new();
                pong_out.encode(&mut pong_buf);
                let tls_ref = tls
                    .as_mut()
                    .ok_or_else(|| io::Error::other("tls stream missing"))?;
                self.send_message(tls_ref, Message::Pong { payload: &pong_buf })
                    .await?;
                Ok(AuthStep::Continue)
            }
            Message::Close { .. } => Ok(AuthStep::Done),
            _ => {
                let tls_ref = tls
                    .as_mut()
                    .ok_or_else(|| io::Error::other("tls stream missing"))?;
                self.send_auth_fail(tls_ref, AuthFailCode::Unknown).await?;
                Ok(AuthStep::Done)
            }
        }
    }

    fn ensure_session_queue_size(&self) -> io::Result<()> {
        if self.session_queue_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session_queue_size must be non-zero",
            ));
        }
        Ok(())
    }

    fn verify_auth(
        &self,
        payload: &AuthPayload,
        challenge: &[u8; crate::proto::AUTH_CHALLENGE_LEN],
    ) -> Result<AssignedIp, AuthFailCode> {
        let client = self
            .authenticator
            .get(&payload.client_id)
            .ok_or(AuthFailCode::UnknownClient)?;
        if !client.enabled {
            return Err(AuthFailCode::Disabled);
        }
        if client.assigned_ipv4 != payload.assigned_ipv4 {
            return Err(AuthFailCode::IpMismatch);
        }
        if &payload.challenge != challenge {
            return Err(AuthFailCode::ChallengeInvalid);
        }

        let mut context = Vec::with_capacity(11 + 16 + 4 + challenge.len());
        context.extend_from_slice(b"slt-auth-v1");
        context.extend_from_slice(payload.client_id.as_bytes());
        context.extend_from_slice(&payload.assigned_ipv4.octets());
        context.extend_from_slice(challenge);

        let key = VerifyingKey::from_bytes(client.pubkey_ed25519.as_bytes())
            .map_err(|_| AuthFailCode::BadSignature)?;
        let signature = Signature::from_bytes(&payload.signature);
        key.verify_strict(&context, &signature)
            .map_err(|_| AuthFailCode::BadSignature)?;

        Ok(AssignedIp(client.assigned_ipv4))
    }

    async fn send_message(
        &self,
        tls: &mut tokio_boring::SslStream<TcpStream>,
        message: Message<'_>,
    ) -> io::Result<()> {
        let mut buf = Vec::new();
        encode_message(message, &mut buf).map_err(map_frame_error)?;
        tls.write_all(&buf).await
    }

    async fn send_auth_fail(
        &self,
        tls: &mut tokio_boring::SslStream<TcpStream>,
        code: AuthFailCode,
    ) -> io::Result<()> {
        let payload = AuthFailPayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        self.send_message(tls, Message::AuthFail { payload: &buf })
            .await
    }
}

fn map_message_error(err: MessageError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("message error: {err:?}"),
    )
}

fn map_frame_error(err: FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("frame error: {err:?}"))
}

fn map_payload_error(err: PayloadError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("payload error: {err:?}"),
    )
}
