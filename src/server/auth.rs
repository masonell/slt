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
use super::metrics::Metrics;
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
    metrics: Arc<Metrics>,
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
        metrics: Arc<Metrics>,
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
            metrics,
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
        let tls = match time::timeout(self.auth_timeout, tls_accept(&self.acceptor, stream)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                self.metrics.inc_auth_failures();
                return Err(io::Error::other(format!("{err:?}")));
            }
            Err(_) => {
                self.metrics.inc_auth_failures();
                return Ok(());
            }
        };
        let mut tls = Some(tls);

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
                () = timeout => {
                    self.metrics.inc_auth_failures();
                    return Ok(());
                },
                res = tls_ref.read_buf(&mut buf) => {
                    let n = res?;
                    if n == 0 {
                        self.metrics.inc_auth_failures();
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
                        self.metrics.inc_auth_successes();
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
                            self.metrics.clone(),
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
                        self.metrics.inc_auth_failures();
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
                self.metrics.inc_auth_failures();
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
        verify_auth_payload(&self.authenticator, payload, challenge)
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

fn verify_auth_payload(
    authenticator: &Authenticator,
    payload: &AuthPayload,
    challenge: &[u8; crate::proto::AUTH_CHALLENGE_LEN],
) -> Result<AssignedIp, AuthFailCode> {
    let client = authenticator
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::net::{Ipv4Addr, SocketAddr};

    use crate::proto::AUTH_CHALLENGE_LEN;
    use crate::types::{PubKeyEd25519, SharedSecret};

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
            listen_tcp: SocketAddr::from(([127, 0, 0, 1], 0)),
            listen_udp: SocketAddr::from(([127, 0, 0, 1], 0)),
            tls_cert: crate::types::TlsMaterial::File {
                file: "vendor/boring/test/cert.pem".into(),
            },
            tls_key: crate::types::TlsMaterial::File {
                file: "vendor/boring/test/key.pem".into(),
            },
            nginx_tcp_upstream: SocketAddr::from(([127, 0, 0, 1], 0)),
            nginx_udp_upstream: SocketAddr::from(([127, 0, 0, 1], 0)),
            tun_name: "test0".to_string(),
            tun_mtu: 1500,
            ping_min: std::time::Duration::from_secs(1),
            ping_max: std::time::Duration::from_secs(2),
            auth_timeout: std::time::Duration::from_secs(3),
            idle_timeout: std::time::Duration::from_secs(4),
            udp_verify_timeout: std::time::Duration::from_secs(5),
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
}
