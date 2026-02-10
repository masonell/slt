mod limits;
mod register;
mod session;

use crate::{auth, transport, tun};
use slt_core::config::ClientConfig;
use slt_core::proto::MessageLimits;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use tun_rs::DeviceBuilder;

const PING_MIN: Duration = Duration::from_secs(10);
const PING_MAX: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

const RECONNECT_MIN: Duration = Duration::from_millis(200);
const RECONNECT_MAX: Duration = Duration::from_secs(5);

/// Run the client runtime until shutdown.
pub async fn run_client(
    config: ClientConfig,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let limits = limits::message_limits_from_mtu(config.tun_mtu);
    let mut backoff = ReconnectBackoff::new(RECONNECT_MIN, RECONNECT_MAX);
    let mut attempt: u64 = 0;
    let mut tun_state: Option<TunState> = None;

    let result: io::Result<()> = loop {
        if cancel.is_cancelled() {
            break Ok(());
        }

        attempt = attempt.saturating_add(1);
        info!(attempt, hostname = %config.hostname, port = config.port, "connecting");

        let mut tcp = match connect_authenticated(&config, &cancel).await {
            Ok(tcp) => tcp,
            Err(err) => {
                if cancel.is_cancelled() {
                    break Ok(());
                }
                if err.kind() == io::ErrorKind::PermissionDenied {
                    warn!(error = %err, "authentication rejected");
                    break Err(err);
                }

                if !should_reconnect(&err) {
                    warn!(
                        attempt,
                        kind = ?err.kind(),
                        error = %err,
                        "connect/auth failed (non-recoverable)"
                    );
                    break Err(err);
                }

                warn!(
                    attempt,
                    kind = ?err.kind(),
                    error = %err,
                    "connect/auth failed; retrying"
                );
                sleep_backoff(&cancel, &mut backoff).await;
                continue;
            }
        };
        backoff.reset();

        if tun_state.is_none() {
            tun_state = Some(TunState::spawn(&config, cancel.clone())?);
        }
        let tun_state_ref = tun_state.as_mut().expect("tun state initialized");

        let quic_ids = discover_quic_ids(&config, &cancel, tcp.peer).await;
        let udp_session =
            register_udp_qsp(&mut tcp.transport, limits, tun_state_ref, quic_ids.as_ref()).await;

        let exit = run_session(
            tcp.transport,
            limits,
            tun_state_ref,
            &cancel,
            quic_ids,
            udp_session,
        )
        .await;

        match exit {
            Ok(session::SessionExit::Shutdown) => break Ok(()),
            Ok(session::SessionExit::TunClosed) => {
                warn!("tun tasks stopped; shutting down");
                break Ok(());
            }
            Ok(reason) => {
                warn!(reason = ?reason, "session ended; reconnecting");
                sleep_backoff(&cancel, &mut backoff).await;
            }
            Err(err) => {
                if cancel.is_cancelled() {
                    break Ok(());
                }
                if should_reconnect(&err) {
                    warn!(kind = ?err.kind(), error = %err, "session error; reconnecting");
                    sleep_backoff(&cancel, &mut backoff).await;
                } else {
                    break Err(err);
                }
            }
        }
    };

    cancel.cancel();
    if let Some(tun_state) = tun_state {
        tun_state.shutdown().await;
    }

    if let Err(err) = result {
        warn!(error = %err, "client runtime exited with error");
        return Err(err.into());
    }

    info!("client shutdown complete");
    Ok(())
}

fn should_reconnect(err: &io::Error) -> bool {
    !matches!(
        err.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied
    )
}

async fn sleep_backoff(cancel: &CancellationToken, backoff: &mut ReconnectBackoff) {
    let delay = backoff.next_delay();
    tokio::select! {
        () = cancel.cancelled() => {}
        () = time::sleep(delay) => {}
    }
}

struct ReconnectBackoff {
    base: Duration,
    max: Duration,
    current: Duration,
}

impl ReconnectBackoff {
    const fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            current: base,
        }
    }

    const fn reset(&mut self) {
        self.current = self.base;
    }

    fn next_delay(&mut self) -> Duration {
        let cap = self.current;
        let next = self.current.checked_mul(2).unwrap_or(self.max);
        self.current = std::cmp::min(next, self.max);

        let cap_ms = u64::try_from(cap.as_millis()).unwrap_or(u64::MAX);
        let half = cap_ms / 2;
        let jitter = if half > 0 { fastrand::u64(0..=half) } else { 0 };
        Duration::from_millis(half.saturating_add(jitter))
    }
}

async fn connect_authenticated(
    config: &ClientConfig,
    cancel: &CancellationToken,
) -> io::Result<transport::tcp::TcpSession> {
    let mut tcp = tokio::select! {
        () = cancel.cancelled() => {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "connect cancelled"));
        }
        res = transport::tcp::connect(config) => res,
    }?;

    info!(peer = ?tcp.peer, sni = ?tcp.sni, "tcp handshake complete");

    tokio::select! {
        () = cancel.cancelled() => {
            Err(io::Error::new(io::ErrorKind::Interrupted, "auth cancelled"))
        }
        res = auth::authenticate(&mut tcp.transport, config) => res,
    }?;

    if tcp.transport.has_buffered_input() {
        debug!("preserved auth leftovers");
    }

    Ok(tcp)
}

async fn discover_quic_ids(
    config: &ClientConfig,
    cancel: &CancellationToken,
    peer: Option<SocketAddr>,
) -> Option<transport::quic_discovery::QuicIds> {
    if config.upgrade.is_none() {
        debug!("upgrade disabled; skipping quic dcid discovery");
        return None;
    }

    match transport::quic_discovery::discover_quic_ids(config, cancel, peer).await {
        Ok(ids) => {
            info!(
                dcid_len = ids.dcid.len(),
                scid_len = ids.scid.len(),
                "quic dcid discovery succeeded"
            );
            Some(ids)
        }
        Err(err) => {
            warn!(error = %err, "quic dcid discovery failed");
            None
        }
    }
}

async fn register_udp_qsp(
    tcp: &mut transport::tcp::TcpTransport,
    limits: MessageLimits,
    tun_state: &TunState,
    quic_ids: Option<&transport::quic_discovery::QuicIds>,
) -> Option<transport::udp_qsp::UdpQspTransport> {
    let ids = quic_ids?;

    match register::register_udp_qsp(tcp, limits, tun_state.to_tun_tx_ref(), ids).await {
        Ok(session) => {
            info!(
                dcid_len = ids.dcid.len(),
                scid_len = ids.scid.len(),
                peer = %ids.peer,
                "register_cid accepted"
            );
            Some(session)
        }
        Err(err) => {
            warn!(error = %err, "register_cid failed");
            None
        }
    }
}

async fn run_session(
    tcp: transport::tcp::TcpTransport,
    limits: MessageLimits,
    tun_state: &mut TunState,
    cancel: &CancellationToken,
    quic_ids: Option<transport::quic_discovery::QuicIds>,
    udp_session: Option<transport::udp_qsp::UdpQspTransport>,
) -> io::Result<session::SessionExit> {
    let rx = tun_state.take_session_rx();
    let to_tun_tx = tun_state.to_tun_tx();

    let mut session = session::ClientSession::new(
        tcp,
        rx,
        to_tun_tx,
        cancel.clone(),
        limits,
        PING_MIN,
        PING_MAX,
        IDLE_TIMEOUT,
        quic_ids,
        udp_session,
    );

    let exit = session.run().await;
    tun_state.restore_session_rx(session.take_to_session_rx());
    exit
}

struct TunState {
    handles: tun::TunHandles,
    to_session_rx: mpsc::Receiver<Vec<u8>>,
    to_tun_tx: mpsc::Sender<Vec<u8>>,
}

impl TunState {
    fn spawn(config: &ClientConfig, cancel: CancellationToken) -> io::Result<Self> {
        let tun = Arc::new(
            DeviceBuilder::new()
                .name(&config.tun_name)
                .mtu(config.tun_mtu)
                .build_async()?,
        );
        let mut handles = tun::spawn(tun, config.assigned_ipv4, cancel, config.tun_mtu);
        let (to_session_rx, to_tun_tx) = handles.take_channels();
        Ok(Self {
            handles,
            to_session_rx,
            to_tun_tx,
        })
    }

    fn take_session_rx(&mut self) -> mpsc::Receiver<Vec<u8>> {
        let (_dummy_tx, dummy_rx) = mpsc::channel(1);
        std::mem::replace(&mut self.to_session_rx, dummy_rx)
    }

    fn restore_session_rx(&mut self, rx: mpsc::Receiver<Vec<u8>>) {
        self.to_session_rx = rx;
    }

    fn to_tun_tx(&self) -> mpsc::Sender<Vec<u8>> {
        self.to_tun_tx.clone()
    }

    const fn to_tun_tx_ref(&self) -> &mpsc::Sender<Vec<u8>> {
        &self.to_tun_tx
    }

    async fn shutdown(self) {
        self.handles.shutdown().await;
    }
}
