use std::io;
use std::sync::Arc;

use slt_core::proto::MessageLimits;
use slt_core::transport::UdpQspIo;
#[cfg(test)]
use slt_core::transport::tcp::TcpChannel;
use slt_core::types::ClientId;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error};

use crate::AssignedIp;
use crate::metrics::Metrics;
use crate::registry::SessionRegistry;
#[cfg(test)]
use crate::sessions::SessionKeyUpdater;
use crate::sessions::{
    ClientSessionBase, ServerUdpQspIoFactory, SessionEvent, SessionTcpChannel, SessionTimeouts,
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
    limits: MessageLimits,
    session_timeouts: SessionTimeouts,
    session_queue_size: usize,
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
    ) -> Self {
        Self {
            registry,
            metrics,
            tun,
            udp_io_factory: Arc::new(ServerUdpQspIoFactory::new(udp_socket)),
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
    fn spawn_session(
        &self,
        client_id: ClientId,
        assigned_ip: AssignedIp,
        tcp_channel: SessionTcpChannel<TcpStream>,
    ) {
        debug_assert!(self.session_queue_size > 0);
        let (tx, rx) = mpsc::channel(self.session_queue_size);

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
            self.udp_io_factory.clone(),
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

        let tcp_channel = tcp
            .take()
            .ok_or_else(|| io::Error::other("tcp channel missing"))?;

        self.spawn_session(client_id, assigned_ip, tcp_channel);
        Ok(())
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
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        debug_assert!(self.session_queue_size > 0);
        let (tx, rx) = mpsc::channel(self.session_queue_size);

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
            self.udp_io_factory.clone(),
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

        let tcp_channel = tcp
            .take()
            .ok_or_else(|| io::Error::other("tcp channel missing"))?;

        self.spawn_session_test(client_id, assigned_ip, tcp_channel);
        Ok(())
    }
}
