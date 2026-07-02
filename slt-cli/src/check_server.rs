//! `check-server`: validate a deployed SLT server against its domain.
//!
//! Five independent checks run against `<domain>`; `--client-config` adds the VPN-auth
//! check. Everything is synchronous (no async runtime, no HTTP library): checks 1-3 are
//! hand-rolled HTTP/1.1 over a `BoringSSL` stream, check 4 reuses the `quiche` Initial probe,
//! and check 5 drives the SLT wire protocol over a VPN-token TLS connection.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use boring::ssl::{HandshakeError, Ssl, SslStream, SslVerifyMode};
use quiche::ConnectionId;
use slt_core::crypto::client_hello::client_hello_session_id_callback;
use slt_core::crypto::{
    configure_ca_store, configure_client_chrome_ssl, configure_host_ca_store,
    configure_hostname_verification, export_auth_challenge, quic_client_chrome_config,
    tcp_client_chrome_ctx_builder,
};
use slt_core::proto::{
    AuthFailPayload, AuthOkPayload, CloseCode, Message, MessageLimits, decode_message,
    encode_message,
};
use slt_core::types::{SharedSecret, TlsMaterial};

use crate::config_io::load_client_config;
use crate::http_probe::{self, HttpResponse};

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const AUTH_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const QUIC_PROBE_DEADLINE: Duration = Duration::from_secs(3);
const AUTH_MAX_FRAME: usize = 16 * 1024;

/// How a single check turned out.
struct Outcome {
    name: &'static str,
    ok: bool,
    detail: Option<String>,
}

/// Run all checks against `domain`, printing `[PASS]`/`[FAIL]` lines unless `quiet`.
///
/// Returns `Ok(())` iff every run check passed; otherwise returns an error so the CLI
/// exits non-zero. `client_config` enables the VPN-auth check.
///
/// # Errors
///
/// - Bails with a summary if any check failed.
/// - Individual check failures are captured as `Outcome` detail, not propagated as errors.
pub fn check_server(domain: &str, client_config: Option<&Path>, quiet: bool) -> Result<()> {
    let mut outcomes: Vec<Outcome> = Vec::new();

    outcomes.push(outcome(
        "HTTP redirect (80 -> 443)",
        check_http_redirect(domain),
    ));

    // Checks 2 and 3 share one HTTPS request.
    let https = fetch_https(domain);
    outcomes.push(outcome(
        "HTTPS reaches nginx (system-CA verified)",
        https.as_ref().map(|_| ()).map_err(|e| format!("{e:#}")),
    ));
    outcomes.push(outcome(
        "ALT-SVC header present",
        match &https {
            Ok(resp) => check_alt_svc(resp),
            Err(e) => Err(format!("no HTTPS response: {e:#}")),
        },
    ));

    outcomes.push(outcome("QUIC responds on UDP/443", check_quic(domain)));

    if let Some(path) = client_config {
        outcomes.push(outcome("VPN auth", check_vpn_auth(path)));
    }

    if !quiet {
        for o in &outcomes {
            match (o.ok, &o.detail) {
                (true, _) => println!("[PASS] {}", o.name),
                (false, Some(d)) => println!("[FAIL] {}: {d}", o.name),
                (false, None) => println!("[FAIL] {}", o.name),
            }
        }
    }

    let failures = outcomes.iter().filter(|o| !o.ok).count();
    if failures == 0 {
        Ok(())
    } else {
        bail!(
            "check-server: {failures} of {} checks failed",
            outcomes.len()
        )
    }
}

fn outcome(name: &'static str, res: Result<(), String>) -> Outcome {
    match res {
        Ok(()) => Outcome {
            name,
            ok: true,
            detail: None,
        },
        Err(detail) => Outcome {
            name,
            ok: false,
            detail: Some(detail),
        },
    }
}

/// Resolve `domain:port` to a single address.
fn resolve(domain: &str, port: u16) -> Result<SocketAddr> {
    (domain, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {domain}:{port}"))?
        .next()
        .with_context(|| format!("no addresses returned for {domain}:{port}"))
}

fn set_timeouts(stream: &TcpStream, d: Duration) -> Result<()> {
    stream
        .set_read_timeout(Some(d))
        .context("failed to set socket read timeout")?;
    stream
        .set_write_timeout(Some(d))
        .context("failed to set socket write timeout")?;
    Ok(())
}

/// Check 1: port 80 must redirect to `https://`.
fn check_http_redirect(domain: &str) -> Result<(), String> {
    let addr = resolve(domain, HTTP_PORT).map_err(|e| format!("{e:#}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("connect {addr} failed: {e}"))?;
    set_timeouts(&stream, HTTP_TIMEOUT).map_err(|e| format!("{e:#}"))?;

    let resp = http_probe::get(&mut stream, domain).map_err(|e| format!("{e:#}"))?;
    if !(300..400).contains(&resp.status) {
        return Err(format!("expected 3xx redirect, got status {}", resp.status));
    }
    let Some(location) = resp.header("location") else {
        return Err(format!(
            "status {} redirect has no Location header",
            resp.status
        ));
    };
    if location.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("redirect Location {location:?} is not https://"))
    }
}

/// Checks 2/3: tokenless HTTPS (system CA) — server classifies as plain traffic and
/// proxies to nginx. A successful handshake against the system CA + an HTTP response
/// means nginx answered; if the VPN server claimed the connection it would present a
/// self-signed cert and the handshake would fail.
fn fetch_https(domain: &str) -> Result<HttpResponse> {
    let addr = resolve(domain, HTTPS_PORT)?;
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .with_context(|| format!("connect {addr} failed"))?;
    set_timeouts(&stream, HTTP_TIMEOUT)?;
    let mut tls = connect_tls(stream, domain, TlsMode::PublicCa)?;
    let resp = http_probe::get(&mut tls, domain)?;
    Ok(resp)
}

fn check_alt_svc(resp: &HttpResponse) -> Result<(), String> {
    if resp.header("alt-svc").is_some() {
        Ok(())
    } else {
        Err("no Alt-Svc header in response".to_string())
    }
}

/// Check 4: send a QUIC Initial and confirm any UDP response from `domain:443`.
fn check_quic(domain: &str) -> Result<(), String> {
    let peer = resolve(domain, HTTPS_PORT).map_err(|e| format!("{e:#}"))?;
    // Bind a local socket of the same family as the peer: an IPv4 socket can't send to an
    // IPv6 peer (and vice versa), so follow whatever `resolve` returned.
    let bind_ip: IpAddr = if peer.is_ipv6() {
        Ipv6Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::UNSPECIFIED.into()
    };
    let socket = UdpSocket::bind((bind_ip, 0)).map_err(|e| format!("bind UDP socket: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .map_err(|e| format!("set UDP read timeout: {e}"))?;
    let local = socket
        .local_addr()
        .map_err(|e| format!("local UDP addr: {e}"))?;

    let mut config = quic_client_chrome_config().map_err(|e| format!("QUIC config: {e}"))?;
    let scid = ConnectionId::from_ref(&[]);
    let mut conn = quiche::connect(Some(domain), &scid, local, peer, &mut config)
        .map_err(|e| format!("quiche connect: {e}"))?;

    // Emit the Initial.
    let mut out = [0u8; 1350];
    loop {
        match conn.send(&mut out) {
            Ok((n, info)) => {
                socket
                    .send_to(&out[..n], info.to)
                    .map_err(|e| format!("UDP send: {e}"))?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(format!("quiche send: {e}")),
        }
    }

    // A datagram from the exact peer address within the deadline means something speaks
    // QUIC on UDP/443. Matching the full address (not just the IP) avoids counting stray
    // datagrams from the same host on a different port.
    let deadline = Instant::now() + QUIC_PROBE_DEADLINE;
    let mut buf = [0u8; 1500];
    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((_n, from)) if from == peer => return Ok(()),
            Ok(_) => {}
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => return Err(format!("UDP recv: {e}")),
        }
    }
    Err("no QUIC response on UDP/443 within deadline".to_string())
}

/// Check 5: connect with the VPN token + pinned cert, run `AUTH`, expect `AUTH_OK`.
///
/// The endpoint and SNI come from the client config — `network.ip`, `network.port`, and
/// `network.hostname` — matching how `slt-client` dials, so a config that uses a non-443
/// port or an explicit IP override is probed on the same target it would actually use.
fn check_vpn_auth(client_config_path: &Path) -> Result<(), String> {
    let config =
        load_client_config(client_config_path).map_err(|e| format!("load client config: {e:#}"))?;

    let sni = config.network.hostname.clone();
    let addr = match config.network.ip {
        Some(ip) => SocketAddr::new(ip, config.network.port),
        None => resolve(&sni, config.network.port).map_err(|e| format!("{e:#}"))?,
    };
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("connect {addr} failed: {e}"))?;
    set_timeouts(&stream, AUTH_PROBE_TIMEOUT).map_err(|e| format!("{e:#}"))?;

    let mode = TlsMode::Pinned {
        ca: config.tls.tls_ca.clone(),
        secret: config.identity.shared_secret,
    };
    let mut tls = connect_tls(stream, &sni, mode).map_err(|e| format!("{e:#}"))?;

    let challenge = export_auth_challenge(tls.ssl()).map_err(|e| format!("TLS export: {e}"))?;
    let payload = slt_core::proto::build_auth_payload(&config, challenge);
    let mut payload_buf = Vec::new();
    payload.encode(&mut payload_buf);
    let mut frame = Vec::new();
    encode_message(
        Message::Auth {
            payload: &payload_buf,
        },
        &mut frame,
    )
    .map_err(|e| format!("encode AUTH: {e}"))?;
    tls.write_all(&frame)
        .map_err(|e| format!("send AUTH: {e}"))?;
    tls.flush().map_err(|e| format!("flush AUTH: {e}"))?;

    let limits = MessageLimits::new(AUTH_MAX_FRAME, AUTH_MAX_FRAME);
    let deadline = Instant::now() + AUTH_PROBE_TIMEOUT;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match decode_message(&buf, limits) {
            Ok(Some((message, _consumed))) => match message {
                Message::AuthOk { payload } => {
                    AuthOkPayload::decode(payload).map_err(|e| format!("decode AUTH_OK: {e}"))?;
                    // Best-effort graceful close before dropping.
                    let mut close_buf = Vec::new();
                    let _ = encode_message(
                        Message::Close {
                            payload: &[u8::from(CloseCode::Normal)],
                        },
                        &mut close_buf,
                    );
                    let _ = tls.write_all(&close_buf);
                    let _ = tls.flush();
                    return Ok(());
                }
                Message::AuthFail { payload } => {
                    let fail = AuthFailPayload::decode(payload)
                        .map_err(|e| format!("decode AUTH_FAIL: {e}"))?;
                    return Err(format!("rejected: {:?}", fail.code));
                }
                Message::Close { .. } => return Err("server closed during auth".to_string()),
                other => return Err(format!("unexpected message: {other:?}")),
            },
            Ok(None) => {}
            Err(e) => return Err(format!("decode response: {e}")),
        }
        if Instant::now() >= deadline {
            return Err("auth response timed out".to_string());
        }
        let n = tls
            .read(&mut chunk)
            .map_err(|e| format!("read auth response: {e}"))?;
        if n == 0 {
            return Err("connection closed during auth".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// TLS verification strategy for a probe connection.
enum TlsMode {
    /// Trust the system CA bundle (nginx path).
    PublicCa,
    /// Pin the client's server cert and inject the VPN `ClientHello` token (auth path).
    Pinned {
        ca: TlsMaterial,
        secret: SharedSecret,
    },
}

/// Establish a `BoringSSL` client session over `stream` with the given verification mode.
fn connect_tls(stream: TcpStream, sni: &str, mode: TlsMode) -> Result<SslStream<TcpStream>> {
    let http1_only = matches!(mode, TlsMode::PublicCa);
    let mut ctx = tcp_client_chrome_ctx_builder()?;
    match mode {
        TlsMode::PublicCa => {
            configure_host_ca_store(&mut ctx)?;
        }
        TlsMode::Pinned { ca, secret } => {
            configure_ca_store(&mut ctx, &ca)?;
            ctx.set_client_hello_session_id_callback(client_hello_session_id_callback(secret));
        }
    }
    ctx.set_verify(SslVerifyMode::PEER);

    let ctx = ctx.build();
    let mut ssl = Ssl::new(&ctx)?;
    configure_client_chrome_ssl(&mut ssl)?;
    if http1_only {
        // The Chrome ALPN list offers h2, and nginx negotiates HTTP/2 — but this probe
        // speaks text HTTP/1.1, which is invalid HTTP/2. Pin http/1.1 so nginx replies
        // in a format the probe can parse. (VPN-auth keeps the full Chrome ALPN.)
        ssl.set_alpn_protos(b"\x08http/1.1")?;
    }
    ssl.set_hostname(sni)?;
    configure_hostname_verification(&mut ssl, sni)?;

    match ssl.connect(stream) {
        Ok(stream) => Ok(stream),
        Err(HandshakeError::Failure(mid)) => bail!("TLS handshake failed: {}", mid.error()),
        Err(HandshakeError::SetupFailure(e)) => bail!("TLS setup failed: {e}"),
        Err(HandshakeError::WouldBlock(_)) => bail!("TLS handshake stalled unexpectedly"),
    }
}

#[cfg(test)]
mod tests {
    use slt_core::proto::{
        AUTH_CHALLENGE_LEN, AUTH_PAYLOAD_LEN, AuthFailCode, AuthFailPayload, AuthOkPayload,
        AuthPayload, MessageLimits, decode_message, encode_message,
    };
    use slt_core::types::ClientId;

    use super::*;

    #[test]
    fn outcome_records_failure_detail() {
        let o = outcome("test", Err("boom".to_string()));
        assert!(!o.ok);
        assert_eq!(o.detail.as_deref(), Some("boom"));

        let o = outcome("test", Ok(()));
        assert!(o.ok);
        assert!(o.detail.is_none());
    }

    #[test]
    fn auth_ok_roundtrips_through_frame_codec() {
        let mut buf = Vec::new();
        encode_message(Message::AuthOk { payload: &[] }, &mut buf).unwrap();
        let (msg, consumed) = decode_message(&buf, MessageLimits::new(1024, 1024))
            .unwrap()
            .unwrap();
        assert_eq!(consumed, buf.len());
        match msg {
            Message::AuthOk { payload } => {
                AuthOkPayload::decode(payload).unwrap();
            }
            other => panic!("expected AuthOk, got {other:?}"),
        }
    }

    #[test]
    fn auth_fail_roundtrips_and_carries_code() {
        let mut payload_buf = Vec::new();
        AuthFailPayload {
            code: AuthFailCode::BadSignature,
        }
        .encode(&mut payload_buf);

        let mut frame = Vec::new();
        encode_message(
            Message::AuthFail {
                payload: &payload_buf,
            },
            &mut frame,
        )
        .unwrap();
        let (msg, _) = decode_message(&frame, MessageLimits::new(1024, 1024))
            .unwrap()
            .unwrap();
        match msg {
            Message::AuthFail { payload } => {
                let fail = AuthFailPayload::decode(payload).unwrap();
                assert_eq!(fail.code, AuthFailCode::BadSignature);
            }
            other => panic!("expected AuthFail, got {other:?}"),
        }
    }

    #[test]
    fn auth_payload_frame_decodes_to_expected_type() {
        // build_auth_payload is exercised in slt-core; here we confirm the frame we send
        // in check 5 decodes back to a correctly-sized Auth message.
        let payload = AuthPayload {
            client_id: ClientId([0x11; 16]),
            assigned_ipv4: std::net::Ipv4Addr::new(10, 10, 0, 2),
            challenge: [0x44; AUTH_CHALLENGE_LEN],
            signature: [0x77; 64],
        };
        assert_eq!(AUTH_PAYLOAD_LEN, 16 + 4 + AUTH_CHALLENGE_LEN + 64);
        let mut payload_buf = Vec::new();
        payload.encode(&mut payload_buf);
        let mut frame = Vec::new();
        encode_message(
            Message::Auth {
                payload: &payload_buf,
            },
            &mut frame,
        )
        .unwrap();
        let (msg, _) = decode_message(&frame, MessageLimits::new(16 * 1024, 16 * 1024))
            .unwrap()
            .unwrap();
        match msg {
            Message::Auth { payload } => {
                let decoded = AuthPayload::decode(payload).unwrap();
                assert_eq!(decoded.client_id, ClientId([0x11; 16]));
                assert_eq!(decoded.signature, [0x77; 64]);
            }
            other => panic!("expected Auth, got {other:?}"),
        }
    }

    #[test]
    fn close_frame_encodes_normal_code() {
        let mut buf = Vec::new();
        encode_message(
            Message::Close {
                payload: &[u8::from(CloseCode::Normal)],
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf[0], u8::from(slt_core::proto::MessageType::Close));
        assert_eq!(buf[1..5], [0, 0, 0, 1]); // length = 1
        assert_eq!(buf[5], u8::from(CloseCode::Normal));
    }
}
