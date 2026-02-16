use std::io;
use std::sync::Arc;

use slt_core::proto::MessageLimits;
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
use crate::sessions::{ClientSessionBase, SessionEvent, SessionTcpChannel, SessionTimeouts};
use crate::tun::TunDeviceIo;

/// Manages session creation and lifecycle.
///
/// Encapsulates all resources needed to spawn and manage client sessions.
#[derive(Clone)]
pub struct SessionManager<T: TunDeviceIo> {
    registry: Arc<SessionRegistry>,
    metrics: Arc<Metrics>,
    tun: Arc<T>,
    udp_socket: Arc<tokio::net::UdpSocket>,
    limits: MessageLimits,
    session_timeouts: SessionTimeouts,
    session_queue_size: usize,
}

impl<T: TunDeviceIo> SessionManager<T> {
    /// Creates a new session manager.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
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
            udp_socket,
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
    /// # Errors
    ///
    /// Returns an error if queue size is zero or channel allocation fails.
    fn spawn_session(
        &self,
        client_id: ClientId,
        assigned_ip: AssignedIp,
        tcp_channel: SessionTcpChannel<TcpStream>,
        tx: mpsc::Sender<SessionEvent>,
        rx: mpsc::Receiver<SessionEvent>,
    ) {
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
            self.udp_socket.clone(),
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
        let (tx, rx) = mpsc::channel(self.session_queue_size);

        let tcp_channel = tcp
            .take()
            .ok_or_else(|| io::Error::other("tcp channel missing"))?;

        self.spawn_session(client_id, assigned_ip, tcp_channel, tx, rx);
        Ok(())
    }

    /// Test-only session spawning for generic streams.
    #[cfg(test)]
    fn spawn_session_test<S>(
        &self,
        client_id: ClientId,
        assigned_ip: AssignedIp,
        tcp_channel: TcpChannel<S, SessionKeyUpdater>,
        tx: mpsc::Sender<SessionEvent>,
        rx: mpsc::Receiver<SessionEvent>,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
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
            self.udp_socket.clone(),
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
        let (tx, rx) = mpsc::channel(self.session_queue_size);

        let tcp_channel = tcp
            .take()
            .ok_or_else(|| io::Error::other("tcp channel missing"))?;

        self.spawn_session_test(client_id, assigned_ip, tcp_channel, tx, rx);
        Ok(())
    }
}
