use ed25519_dalek::{Signer, SigningKey};
use slt_core::config::ClientConfig;
use slt_core::proto::{
    AUTH_CHALLENGE_LEN, AuthFailPayload, AuthOkPayload, AuthPayload, Message, MessageError,
    MessageLimits, PayloadError, PingPayload, PongPayload, decode_message, encode_message,
};
use std::io;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;
use tokio_boring::SslStream;
use tracing::{debug, info, trace, warn};

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_MAX_FRAME: usize = 16 * 1024;

/// Result of the auth phase.
pub struct AuthOutcome {
    /// Extra bytes read beyond `AUTH_OK` that should be preserved.
    pub leftover: Vec<u8>,
}

/// Perform TLS exporter auth and wait for `AUTH_OK`.
pub async fn authenticate(
    stream: &mut SslStream<TcpStream>,
    config: &ClientConfig,
) -> io::Result<AuthOutcome> {
    let challenge = export_challenge(stream)?;
    let payload = build_auth_payload(config, challenge);
    send_auth(stream, &payload).await?;

    let mut buf = Vec::with_capacity(16 * 1024);
    let limits = MessageLimits::new(AUTH_MAX_FRAME, AUTH_MAX_FRAME);
    let deadline = Instant::now() + AUTH_TIMEOUT;

    loop {
        let timeout = time::sleep_until(deadline.into());
        tokio::select! {
            () = timeout => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "auth timed out"));
            }
            res = stream.read_buf(&mut buf) => {
                let n = res?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "auth connection closed"));
                }
                trace!(bytes_read = n, "received auth data");
            }
        }

        loop {
            let decoded = decode_message(&buf, limits).map_err(map_message_error)?;
            let Some((message, consumed)) = decoded else {
                break;
            };

            let result = handle_auth_message(stream, message).await;
            let rest = buf.split_off(consumed);

            match result? {
                AuthResult::Continue => {}
                AuthResult::Accepted => return Ok(AuthOutcome { leftover: rest }),
                AuthResult::Rejected => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "auth failed",
                    ));
                }
            }

            buf = rest;
        }
    }
}

fn export_challenge(stream: &SslStream<TcpStream>) -> io::Result<[u8; AUTH_CHALLENGE_LEN]> {
    let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
    stream
        .ssl()
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

async fn send_auth(stream: &mut SslStream<TcpStream>, payload: &AuthPayload) -> io::Result<()> {
    let mut payload_buf = Vec::with_capacity(slt_core::proto::AUTH_PAYLOAD_LEN);
    payload.encode(&mut payload_buf);
    send_message(
        stream,
        Message::Auth {
            payload: &payload_buf,
        },
    )
    .await
}

async fn handle_auth_message(
    stream: &mut SslStream<TcpStream>,
    message: Message<'_>,
) -> io::Result<AuthResult> {
    match message {
        Message::AuthOk { payload } => {
            AuthOkPayload::decode(payload).map_err(map_payload_error)?;
            info!("authentication accepted");
            Ok(AuthResult::Accepted)
        }
        Message::AuthFail { payload } => {
            let fail = AuthFailPayload::decode(payload).map_err(map_payload_error)?;
            warn!(code = ?fail.code, "authentication rejected");
            Ok(AuthResult::Rejected)
        }
        Message::Ping { payload } => {
            let ping = PingPayload::decode(payload).map_err(map_payload_error)?;
            debug!(nonce = ping.nonce, "received ping during auth");
            let pong_payload = PongPayload { nonce: ping.nonce };
            let mut pong_buf = Vec::with_capacity(8);
            pong_payload.encode(&mut pong_buf);
            send_message(stream, Message::Pong { payload: &pong_buf }).await?;
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

async fn send_message(stream: &mut SslStream<TcpStream>, message: Message<'_>) -> io::Result<()> {
    let mut buf = Vec::new();
    encode_message(message, &mut buf).map_err(map_frame_error)?;
    stream.write_all(&buf).await
}

fn map_frame_error(err: slt_core::proto::FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("frame error: {err:?}"))
}

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

#[derive(Debug, Clone, Copy)]
enum AuthResult {
    Continue,
    Accepted,
    Rejected,
}
