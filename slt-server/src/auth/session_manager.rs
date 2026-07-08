use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use parking_lot::Mutex;
use slt_core::proto::MessageLimits;
use slt_core::transport::UdpQspIo;
#[cfg(test)]
use slt_core::transport::tcp::TcpChannel;
use slt_core::types::{ClientId, ServerUdpQspConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error};

use crate::AssignedIp;
use crate::metrics::Metrics;
use crate::registry::SessionRegistry;
#[cfg(test)]
use crate::sessions::SessionKeyUpdater;
use crate::sessions::{
    ClientSessionBase, ServerUdpQspIoFactory, SessionTcpChannel, SessionTimeouts,
    UdpSessionIoFactory,
};
use crate::tun::TunDeviceIo;

/// Manages session creation and lifecycle.
///
/// Encapsulates all resources needed to spawn and manage client sessions,
/// including the session registry, TUN device, UDP socket, metrics, and
/// configuration limits. Provides methods for creating new sessions after
/// successful authentication.
#[derive(Clone)]
pub struct SessionManager<T: TunDeviceIo> {
    registry: Arc<SessionRegistry>,
    metrics: Arc<Metrics>,
    tun: Arc<T>,
    udp_io_factory: Arc<dyn UdpSessionIoFactory<UdpQspIo>>,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    state: Arc<Mutex<SessionManagerState>>,
    limits: MessageLimits,
    session_timeouts: SessionTimeouts,
    session_queue_size: usize,
    udp_qsp_config: ServerUdpQspConfig,
}

#[derive(Debug)]
struct SessionManagerState {
    accepting_sessions: bool,
    sessions: HashMap<ClientId, ManagedSession>,
}

#[derive(Debug)]
struct ManagedSession {
    session_id: u64,
    shutdown: CancellationToken,
}

impl SessionManagerState {
    fn replace_session(
        &mut self,
        client_id: ClientId,
        session_id: u64,
        shutdown: CancellationToken,
    ) -> Option<ManagedSession> {
        self.sessions.insert(
            client_id,
            ManagedSession {
                session_id,
                shutdown,
            },
        )
    }

    fn remove_session_if_current(&mut self, client_id: ClientId, session_id: u64) {
        if self
            .sessions
            .get(&client_id)
            .is_some_and(|session| session.session_id == session_id)
        {
            self.sessions.remove(&client_id);
        }
    }
}

impl<T: TunDeviceIo> SessionManager<T> {
    /// Creates a new session manager.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: Arc<SessionRegistry>,
        metrics: Arc<Metrics>,
        tun: Arc<T>,
        udp_socket: Arc<tokio::net::UdpSocket>,
        limits: MessageLimits,
        session_timeouts: SessionTimeouts,
        session_queue_size: usize,
        udp_qsp_config: ServerUdpQspConfig,
    ) -> Self {
        Self {
            registry,
            metrics,
            tun,
            udp_io_factory: Arc::new(ServerUdpQspIoFactory::new(udp_socket)),
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
            state: Arc::new(Mutex::new(SessionManagerState {
                accepting_sessions: true,
                sessions: HashMap::new(),
            })),
            limits,
            session_timeouts,
            session_queue_size,
            udp_qsp_config,
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

    /// Begins graceful shutdown for all managed sessions.
    ///
    /// Cancels the root session token and prevents any later authenticated
    /// connection from registering a new session.
    pub fn start_shutdown(&self) {
        let mut state = self.state.lock();
        state.accepting_sessions = false;
        drop(state);
        self.shutdown.cancel();
        self.tasks.close();
    }

    /// Waits until every tracked session task has exited.
    pub async fn wait_for_shutdown(&self) {
        self.tasks.wait().await;
    }

    /// Spawns a new client session after successful authentication.
    ///
    /// Creates the session channel, registers the session in the registry,
    /// and spawns a task to run the session. If an existing session with
    /// the same client ID exists, it is gracefully shut down before
    /// the new session is created.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The unique identifier for the client
    /// * `assigned_ip` - The IPv4 address assigned to this client
    /// * `tcp_channel` - The established TLS/TCP channel for the session
    fn spawn_session_with_channel<S>(
        &self,
        client_id: ClientId,
        assigned_ip: AssignedIp,
        tcp_channel: SessionTcpChannel<S>,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        debug_assert!(self.session_queue_size > 0);
        let mut state = self.state.lock();
        if !state.accepting_sessions {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "server is shutting down",
            ));
        }

        let (tx, rx) = mpsc::channel(self.session_queue_size);
        let shutdown = self.shutdown.child_token();

        // Keep this lock across registry registration and lifecycle replacement
        // so concurrent reconnects cannot make their active-session views diverge.
        let handle = self
            .registry
            .register_session(client_id, assigned_ip, tx.clone());

        if let Some(replaced) =
            state.replace_session(client_id, handle.session_id, shutdown.clone())
        {
            debug!(client_id = %client_id, session_id = %handle.session_id, replaced_session_id = %replaced.session_id, "replacing existing session");
            replaced.shutdown.cancel();
        }

        let session_id = handle.session_id;
        let session = ClientSessionBase::new(
            session_id,
            client_id,
            assigned_ip,
            tcp_channel,
            self.tun.clone(),
            self.udp_io_factory.clone(),
            self.registry.clone(),
            self.metrics.clone(),
            tx,
            rx,
            shutdown,
            self.limits,
            self.session_timeouts,
            self.udp_qsp_config.clone(),
        );
        let cleanup_state = self.state.clone();

        drop(self.tasks.spawn(async move {
            let _ = session.run().await;
            cleanup_state
                .lock()
                .remove_session_if_current(client_id, session_id);
        }));
        drop(state);
        Ok(())
    }

    fn spawn_session(
        &self,
        client_id: ClientId,
        assigned_ip: AssignedIp,
        tcp_channel: SessionTcpChannel<TcpStream>,
    ) -> io::Result<()> {
        self.spawn_session_with_channel(client_id, assigned_ip, tcp_channel)
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

        let tcp_channel = tcp
            .take()
            .ok_or_else(|| io::Error::other("tcp channel missing"))?;

        self.spawn_session(client_id, assigned_ip, tcp_channel)
    }

    /// Test-only session spawning for generic streams.
    ///
    /// Similar to [`spawn_session`] but accepts any async read/write stream,
    /// enabling use with mock connections in tests.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The unique identifier for the client
    /// * `assigned_ip` - The IPv4 address assigned to this client
    /// * `tcp_channel` - The TCP channel (any compatible stream type)
    ///
    /// # Type Parameters
    ///
    /// * `S` - The underlying stream type (must implement async read/write)
    #[cfg(test)]
    fn spawn_session_test<S>(
        &self,
        client_id: ClientId,
        assigned_ip: AssignedIp,
        tcp_channel: TcpChannel<S, SessionKeyUpdater>,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        self.spawn_session_with_channel(client_id, assigned_ip, tcp_channel)
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

        let tcp_channel = tcp
            .take()
            .ok_or_else(|| io::Error::other("tcp channel missing"))?;

        self.spawn_session_test(client_id, assigned_ip, tcp_channel)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use slt_core::transport::tcp::TcpChannel;
    use tokio::io::AsyncReadExt;
    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::test_support::{NullTun, default_session_timeouts, tls_pair};

    async fn make_manager() -> (SessionManager<NullTun>, Arc<SessionRegistry>, Arc<Metrics>) {
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());
        let udp_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let manager = SessionManager::new(
            registry.clone(),
            metrics.clone(),
            Arc::new(NullTun),
            udp_socket,
            MessageLimits::from_mtu(1500),
            default_session_timeouts(),
            8,
            ServerUdpQspConfig::default(),
        );
        (manager, registry, metrics)
    }

    #[tokio::test]
    async fn shutdown_cancels_and_awaits_active_sessions() {
        let (manager, registry, metrics) = make_manager().await;
        let client_id = ClientId([0x11; 16]);
        let assigned_ip = AssignedIp(Ipv4Addr::new(10, 0, 0, 2));
        let (server_tcp, _client_tcp) = tls_pair().await;
        let mut tcp = Some(TcpChannel::with_key_updater(
            server_tcp,
            SessionKeyUpdater::new(metrics),
        ));

        manager
            .create_session_test(client_id, assigned_ip, &mut tcp)
            .unwrap();
        assert!(registry.lookup_ip(assigned_ip.addr()).is_some());

        manager.start_shutdown();
        manager.wait_for_shutdown().await;

        assert!(registry.lookup_ip(assigned_ip.addr()).is_none());
    }

    #[tokio::test]
    async fn replacement_cancels_previous_session() {
        let (manager, registry, metrics) = make_manager().await;
        let client_id = ClientId([0x22; 16]);
        let assigned_ip = AssignedIp(Ipv4Addr::new(10, 0, 0, 3));

        let (old_server_tcp, mut old_client_tcp) = tls_pair().await;
        let mut old_tcp = Some(TcpChannel::with_key_updater(
            old_server_tcp,
            SessionKeyUpdater::new(metrics.clone()),
        ));
        manager
            .create_session_test(client_id, assigned_ip, &mut old_tcp)
            .unwrap();

        let (new_server_tcp, _new_client_tcp) = tls_pair().await;
        let mut new_tcp = Some(TcpChannel::with_key_updater(
            new_server_tcp,
            SessionKeyUpdater::new(metrics),
        ));
        manager
            .create_session_test(client_id, assigned_ip, &mut new_tcp)
            .unwrap();

        let mut eof = [0u8; 1];
        let n = timeout(Duration::from_secs(1), old_client_tcp.read(&mut eof))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
        assert!(registry.lookup_ip(assigned_ip.addr()).is_some());

        manager.start_shutdown();
        manager.wait_for_shutdown().await;
    }
}
