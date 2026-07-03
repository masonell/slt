//! Auth handler test utilities.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use slt_core::proto::MessageLimits;
use slt_core::types::{ClientId, ServerClient, ServerUdpQspConfig};

use crate::auth::{AuthHandlerBase, Authenticator, SessionManager};
use crate::metrics::Metrics;
use crate::registry::SessionRegistry;
use crate::sessions::SessionTimeouts;
use crate::test_support::tls::tls_acceptor;
use crate::test_support::tun::NullTun;

/// Default session timeouts for testing.
#[must_use]
pub fn default_session_timeouts() -> SessionTimeouts {
    SessionTimeouts {
        ping_min: Duration::from_hours(1),
        ping_max: Duration::from_hours(1),
        idle_timeout: Duration::from_hours(1),
    }
}

/// Builder for creating test auth handlers.
pub struct TestAuthHandlerBuilder {
    clients: Vec<ServerClient>,
    session_queue_size: usize,
    auth_timeout: Duration,
    timeouts: SessionTimeouts,
}

impl Default for TestAuthHandlerBuilder {
    fn default() -> Self {
        Self {
            clients: Vec::new(),
            session_queue_size: 8,
            auth_timeout: Duration::from_secs(30),
            timeouts: default_session_timeouts(),
        }
    }
}

impl TestAuthHandlerBuilder {
    /// Creates a new builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a client to the authenticator.
    #[must_use]
    pub fn with_client(mut self, client: ServerClient) -> Self {
        self.clients.push(client);
        self
    }

    /// Sets the session queue size.
    #[must_use]
    pub fn with_session_queue_size(mut self, size: usize) -> Self {
        self.session_queue_size = size;
        self
    }

    /// Sets the auth timeout.
    #[must_use]
    pub fn with_auth_timeout(mut self, timeout: Duration) -> Self {
        self.auth_timeout = timeout;
        self
    }

    /// Sets the session timeouts.
    #[must_use]
    pub fn with_timeouts(mut self, timeouts: SessionTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Builds the test auth handler (async version for use with #[`tokio::test`]).
    ///
    /// Returns (handler, registry, metrics) for inspection.
    ///
    /// # Panics
    ///
    /// Panics if UDP socket binding fails.
    pub async fn build_async(self) -> (TestAuthHandler, Arc<SessionRegistry>, Arc<Metrics>) {
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());

        // Create a UDP socket (required for handler but not used in auth phase)
        let udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("failed to bind UDP socket");

        let authenticator = Authenticator::new(self.clients);

        let sessions = SessionManager::new(
            registry.clone(),
            metrics.clone(),
            Arc::new(NullTun),
            Arc::new(udp_socket),
            MessageLimits::from_mtu(1500),
            self.timeouts,
            self.session_queue_size,
            ServerUdpQspConfig::default(),
        );

        let handler =
            AuthHandlerBase::new(tls_acceptor(), authenticator, sessions, self.auth_timeout);

        (
            TestAuthHandler {
                inner: handler,
                _udp_runtime: None,
            },
            registry,
            metrics,
        )
    }

    /// Builds the test auth handler (sync version for use with #[test]).
    ///
    /// Returns (handler, registry, metrics) for inspection.
    ///
    /// # Panics
    ///
    /// Panics if UDP socket binding fails.
    #[must_use]
    pub fn build(self) -> (TestAuthHandler, Arc<SessionRegistry>, Arc<Metrics>) {
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());

        // Create a UDP socket (required for handler but not used in auth phase)
        let rt = tokio::runtime::Runtime::new().unwrap();
        let udp_socket = rt.block_on(async {
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("failed to bind UDP socket")
        });

        let authenticator = Authenticator::new(self.clients);

        let sessions = SessionManager::new(
            registry.clone(),
            metrics.clone(),
            Arc::new(NullTun),
            Arc::new(udp_socket),
            MessageLimits::from_mtu(1500),
            self.timeouts,
            self.session_queue_size,
            ServerUdpQspConfig::default(),
        );

        let handler =
            AuthHandlerBase::new(tls_acceptor(), authenticator, sessions, self.auth_timeout);

        (
            TestAuthHandler {
                inner: handler,
                _udp_runtime: Some(rt),
            },
            registry,
            metrics,
        )
    }
}

/// Wrapper around `AuthHandlerBase` for testing.
pub struct TestAuthHandler {
    /// The underlying auth handler.
    pub inner: AuthHandlerBase<NullTun>,
    /// Runtime kept alive for UDP socket (only for sync build).
    _udp_runtime: Option<tokio::runtime::Runtime>,
}

impl TestAuthHandler {
    /// Creates a builder for constructing a test auth handler.
    #[must_use]
    pub fn builder() -> TestAuthHandlerBuilder {
        TestAuthHandlerBuilder::new()
    }
}

/// Creates a test client configuration.
#[must_use]
pub fn make_test_client(
    client_id: ClientId,
    signing_key: &ed25519_dalek::SigningKey,
    assigned_ipv4: Ipv4Addr,
    enabled: bool,
) -> ServerClient {
    use slt_core::types::PubKeyEd25519;

    ServerClient {
        client_id,
        pubkey_ed25519: PubKeyEd25519(signing_key.verifying_key().to_bytes()),
        assigned_ipv4,
        enabled,
    }
}
