//! TCP front-door handling.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::classifier::{Verdict, classify_tcp_client_hello};
use crate::config::ServerConfig;

const PEEK_LEN: usize = 16 * 1024;
const PEEK_ATTEMPTS: usize = 4;

/// TCP acceptor and `ClientHello` classifier.
#[derive(Debug)]
pub struct TcpFrontDoor {
    listener: TcpListener,
    classification_secret: [u8; 32],
    nginx_tcp_upstream: SocketAddr,
}

impl TcpFrontDoor {
    /// Bind to the configured TCP listener.
    ///
    /// # Errors
    ///
    /// Returns an error if TCP listener binding fails.
    pub async fn bind(config: &ServerConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(config.listen_tcp).await?;
        Ok(Self {
            listener,
            classification_secret: config.server_secret,
            nginx_tcp_upstream: config.nginx_tcp_upstream,
        })
    }

    /// Return the bound listener.
    #[must_use]
    pub const fn listener(&self) -> &TcpListener {
        &self.listener
    }

    /// Classify a TCP buffer that starts with TLS records.
    #[must_use]
    pub fn classify(&self, buf: &[u8]) -> Verdict {
        classify_tcp_client_hello(buf, &self.classification_secret)
    }

    /// Run the TCP accept loop and route connections by classification.
    ///
    /// Claimed connections are handed to `claim_handler`; other traffic is
    /// proxied to the nginx upstream. The loop exits once `cancel` is canceled.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting a connection fails.
    pub async fn run(
        &self,
        cancel: CancellationToken,
        claim_handler: impl Fn(TcpStream, SocketAddr) + Send + Sync + 'static,
    ) -> io::Result<()> {
        let claim_handler = Arc::new(claim_handler);
        loop {
            let (stream, addr) = tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                res = self.listener.accept() => res?,
            };
            let server_secret = self.classification_secret;
            let upstream = self.nginx_tcp_upstream;
            let claim_handler = claim_handler.clone();

            tokio::spawn(async move {
                match Self::classify_stream(&stream, server_secret).await {
                    Ok(Verdict::Claim) => (claim_handler)(stream, addr),
                    Ok(Verdict::Pass | Verdict::Incomplete) => {
                        let _ = Self::proxy_to_upstream(stream, upstream).await;
                    }
                    Ok(Verdict::Drop) | Err(_) => {
                        // Drop the connection.
                    }
                }
            });
        }
    }

    async fn proxy_to_upstream(mut inbound: TcpStream, upstream: SocketAddr) -> io::Result<()> {
        let mut outbound = TcpStream::connect(upstream).await?;
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    }

    async fn classify_stream(stream: &TcpStream, server_secret: [u8; 32]) -> io::Result<Verdict> {
        let mut buf = vec![0u8; PEEK_LEN];
        let mut last_len = 0usize;

        for _ in 0..PEEK_ATTEMPTS {
            let n = stream.peek(&mut buf).await?;
            if n == 0 {
                return Ok(Verdict::Drop);
            }

            let verdict = classify_tcp_client_hello(&buf[..n], &server_secret);
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
