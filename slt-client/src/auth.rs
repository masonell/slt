use ed25519_dalek::{Signer, SigningKey};
use slt_core::config::ClientConfig;
use slt_core::proto::{
    AUTH_CHALLENGE_LEN, AuthFailPayload, AuthOkPayload, AuthPayload, Message, MessageLimits,
    PingPayload, PongPayload,
};
use std::io;
use std::time::{Duration, Instant};
use tokio::time;
use tracing::{debug, info, trace, warn};

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_MAX_FRAME: usize = 16 * 1024;

/// Perform TLS exporter auth and wait for `AUTH_OK`.
pub async fn authenticate(
    tcp: &mut crate::transport::tcp::TcpTransport,
    config: &ClientConfig,
) -> io::Result<()> {
    let challenge = export_challenge(tcp)?;
    let payload = build_auth_payload(config, challenge);
    send_auth(tcp, &payload).await?;

    let limits = MessageLimits::new(AUTH_MAX_FRAME, AUTH_MAX_FRAME);
    let deadline = Instant::now() + AUTH_TIMEOUT;

    loop {
        let timeout = time::sleep_until(deadline.into());
        tokio::select! {
            () = timeout => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "auth timed out"));
            }
            res = tcp.read_more() => {
                let n = res?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "auth connection closed"));
                }
                trace!(bytes_read = n, "received auth data");
            }
        }

        loop {
            let Some(msg_buf) = tcp
                .try_pop_message(limits)
                .map_err(crate::wire::map_message_error)?
            else {
                break;
            };

            match handle_auth_message(tcp, msg_buf.message()).await? {
                AuthResult::Continue => {}
                AuthResult::Accepted => return Ok(()),
                AuthResult::Rejected => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "auth failed",
                    ));
                }
            }
        }
    }
}

fn export_challenge(
    tcp: &crate::transport::tcp::TcpTransport,
) -> io::Result<[u8; AUTH_CHALLENGE_LEN]> {
    let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
    tcp.ssl()
        .export_keying_material(&mut challenge, "slt-auth-challenge", None)
        .map_err(|err| io::Error::other(format!("{err:?}")))?;
    Ok(challenge)
}

fn build_auth_payload(config: &ClientConfig, challenge: [u8; AUTH_CHALLENGE_LEN]) -> AuthPayload {
    let mut context = Vec::with_capacity(11 + 16 + 4 + challenge.len());
    context.extend_from_slice(b"slt-auth-v1");
    context.extend_from_slice(config.client_id.as_bytes());
    context.extend_from_slice(&config.assigned_ipv4.octets());
    context.extend_from_slice(&challenge);

    let signing_key = SigningKey::from_bytes(config.privkey_ed25519.as_bytes());
    let signature = signing_key.sign(&context).to_bytes();

    AuthPayload {
        client_id: config.client_id,
        assigned_ipv4: config.assigned_ipv4,
        challenge,
        signature,
    }
}

async fn send_auth(
    tcp: &mut crate::transport::tcp::TcpTransport,
    payload: &AuthPayload,
) -> io::Result<()> {
    let mut payload_buf = Vec::with_capacity(slt_core::proto::AUTH_PAYLOAD_LEN);
    payload.encode(&mut payload_buf);
    tcp.write_message(Message::Auth {
        payload: &payload_buf,
    })
    .await
}

async fn handle_auth_message(
    tcp: &mut crate::transport::tcp::TcpTransport,
    message: Message<'_>,
) -> io::Result<AuthResult> {
    match message {
        Message::AuthOk { payload } => {
            AuthOkPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
            info!("authentication accepted");
            Ok(AuthResult::Accepted)
        }
        Message::AuthFail { payload } => {
            let fail = AuthFailPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
            warn!(code = ?fail.code, "authentication rejected");
            Ok(AuthResult::Rejected)
        }
        Message::Ping { payload } => {
            let ping = PingPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
            debug!(nonce = ping.nonce, "received ping during auth");
            let pong_payload = PongPayload { nonce: ping.nonce };
            let mut pong_buf = Vec::with_capacity(8);
            pong_payload.encode(&mut pong_buf);
            tcp.write_message(Message::Pong { payload: &pong_buf })
                .await?;
            Ok(AuthResult::Continue)
        }
        Message::Close { .. } => {
            warn!("received close during auth");
            Ok(AuthResult::Rejected)
        }
        other => {
            warn!(message = ?other, "unexpected message during auth");
            Ok(AuthResult::Rejected)
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AuthResult {
    Continue,
    Accepted,
    Rejected,
}
