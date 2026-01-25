//! TCP front-door handling.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use crate::classifier::{Verdict, classify_tcp_client_hello};
use crate::config::ServerConfig;

const PEEK_LEN: usize = 16 * 1024;
const PEEK_ATTEMPTS: usize = 4;

/// Result of accepting and classifying a TCP connection.
#[derive(Debug)]
pub enum TcpDecision {
    /// Connection is claimed by the VPN server.
    Claim { stream: TcpStream, addr: SocketAddr },
    /// Connection should be passed through to the upstream.
    Pass { stream: TcpStream, addr: SocketAddr },
    /// Not enough data to classify yet.
    Incomplete { stream: TcpStream, addr: SocketAddr },
    /// Connection should be dropped.
    Drop { addr: SocketAddr },
}

/// TCP acceptor and ClientHello classifier.
#[derive(Debug)]
pub struct TcpFrontDoor {
    listener: TcpListener,
    config: Arc<ServerConfig>,
    server_secret: [u8; 32],
}

impl TcpFrontDoor {
    /// Bind to the configured TCP listener.
    pub async fn bind(config: Arc<ServerConfig>, server_secret: [u8; 32]) -> io::Result<Self> {
        let listener = TcpListener::bind(config.listen_tcp).await?;
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

    /// Accept a connection and classify it using a peek buffer.
    pub async fn accept(&self) -> io::Result<TcpDecision> {
        let (stream, addr) = self.listener.accept().await?;
        let verdict = self.classify_stream(&stream).await?;
        Ok(match verdict {
            Verdict::Claim => TcpDecision::Claim { stream, addr },
            Verdict::Pass => TcpDecision::Pass { stream, addr },
            Verdict::Drop => TcpDecision::Drop { addr },
            Verdict::Incomplete => TcpDecision::Incomplete { stream, addr },
        })
    }

    async fn classify_stream(&self, stream: &TcpStream) -> io::Result<Verdict> {
        let mut buf = vec![0u8; PEEK_LEN];
        let mut last_len = 0usize;

        for _ in 0..PEEK_ATTEMPTS {
            let n = stream.peek(&mut buf).await?;
            if n == 0 {
                return Ok(Verdict::Drop);
            }

            let verdict = self.classify(&buf[..n]);
            if verdict != Verdict::Incomplete {
                return Ok(verdict);
            }

            if n == last_len {
                break;
            }
            last_len = n;
            tokio::task::yield_now().await;
        }

        Ok(Verdict::Incomplete)
    }
}
