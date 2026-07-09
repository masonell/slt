use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use ed25519_dalek::{Signer, SigningKey};
use slt_core::config::ServerConfig;
use slt_core::proto::{
    AUTH_CHALLENGE_LEN, AuthFailCode, AuthFailPayload, AuthPayload, ClosePayload, Message,
    MessageLimits, PingPayload, PongPayload,
};
use slt_core::types::{
    ClientId, PubKeyEd25519, ServerClient, ServerNetworkConfig, ServerTimingConfig,
    ServerTlsConfig, ServerTransportConfig, SharedSecret, TlsMaterial, TunConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

use super::authenticator::verify_auth_payload;
use super::*;
use crate::AssignedIp;
use crate::test_support::{
    TestAuthHandler, TlsDuplexStream, tls_pair, tls_pair_with_parkable_server_writes,
};

mod authenticator_tests;
mod handler_flow_tests;
mod metrics_tests;

pub(super) fn make_client(
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

pub(super) fn make_payload(
    client_id: ClientId,
    assigned_ipv4: Ipv4Addr,
    challenge: [u8; AUTH_CHALLENGE_LEN],
    signing_key: &SigningKey,
) -> AuthPayload {
    let context = slt_core::proto::auth_signature_context(&client_id, assigned_ipv4, &challenge);
    let signature = signing_key.sign(&context).to_bytes();
    AuthPayload {
        client_id,
        assigned_ipv4,
        challenge,
        signature,
    }
}

pub(super) async fn read_message(
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
