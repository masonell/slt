//! TCP front-door handling.

use std::io;
use std::net::TcpListener;
use std::sync::Arc;

use crate::classifier::{Verdict, classify_tcp_client_hello};
use crate::config::ServerConfig;

/// TCP acceptor and ClientHello classifier.
#[derive(Debug)]
pub struct TcpFrontDoor {
    listener: TcpListener,
    config: Arc<ServerConfig>,
    server_secret: [u8; 32],
}

impl TcpFrontDoor {
    /// Bind to the configured TCP listener.
    pub fn bind(config: Arc<ServerConfig>, server_secret: [u8; 32]) -> io::Result<Self> {
        let listener = TcpListener::bind(config.listen_tcp)?;
        Ok(Self {
            listener,
            config,
            server_secret,
        })
    }

    /// Return the bound listener.
    #[must_use]
    pub fn listener(&self) -> &TcpListener {
        &self.listener
    }

    /// Return the server configuration.
    #[must_use]
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Classify a TCP buffer that starts with TLS records.
    #[must_use]
    pub fn classify(&self, buf: &[u8]) -> Verdict {
        classify_tcp_client_hello(buf, &self.server_secret)
    }
}
