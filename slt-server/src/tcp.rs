//! TCP front-door handling.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use super::metrics::Metrics;
use slt_core::classifier::{Verdict, classify_tcp_client_hello};
use slt_core::config::ServerConfig;
use slt_core::types::SharedSecret;

const PEEK_LEN: usize = 16 * 1024;
const PEEK_ATTEMPTS: usize = 4;

/// TCP acceptor and `ClientHello` classifier.
#[derive(Debug)]
pub struct TcpFrontDoor {
    listener: TcpListener,
    classification_secret: SharedSecret,
    nginx_tcp_upstream: SocketAddr,
    metrics: Arc<Metrics>,
}

impl TcpFrontDoor {
    /// Bind to the configured TCP listener.
    ///
    /// # Errors
    ///
    /// Returns an error if TCP listener binding fails.
    pub async fn bind(config: &ServerConfig, metrics: Arc<Metrics>) -> io::Result<Self> {
        debug!(listen_addr = %config.listen_tcp, upstream_addr = %config.nginx_tcp_upstream, "binding TCP front door");
        let listener = TcpListener::bind(config.listen_tcp).await?;
        info!(listen_addr = %config.listen_tcp, "TCP front door bound successfully");
        Ok(Self {
            listener,
            classification_secret: config.server_secret,
            nginx_tcp_upstream: config.nginx_tcp_upstream,
            metrics,
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
        let verdict = classify_tcp_client_hello(buf, &self.classification_secret);
        trace!(buf_len = buf.len(), verdict = ?verdict, "classified TCP buffer");
        verdict
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
        debug!("starting TCP accept loop");
        let claim_handler = Arc::new(claim_handler);
        loop {
            let (stream, addr) = tokio::select! {
                () = cancel.cancelled() => {
                    debug!("TCP accept loop cancelled");
                    return Ok(());
                }
                res = self.listener.accept() => res?,
            };
            debug!(client_addr = %addr, "accepted TCP connection");
            self.metrics.inc_tcp_accepted();
            let server_secret = self.classification_secret;
            let upstream = self.nginx_tcp_upstream;
            let claim_handler = claim_handler.clone();
            let metrics = self.metrics.clone();

            tokio::spawn(async move {
                match Self::classify_stream(&stream, server_secret).await {
                    Ok(verdict @ Verdict::Claim) => {
                        debug!(client_addr = %addr, verdict = ?verdict, "connection claimed");
                        metrics.inc_claimed();
                        (claim_handler)(stream, addr);
                    }
                    Ok(verdict @ (Verdict::Pass | Verdict::Incomplete)) => {
                        debug!(client_addr = %addr, verdict = ?verdict, upstream_addr = %upstream, "passing connection to upstream");
                        metrics.inc_passed();
                        if let Err(e) = Self::proxy_to_upstream(stream, upstream).await {
                            warn!(client_addr = %addr, upstream_addr = %upstream, error = %e, "upstream proxy error");
                        }
                    }
                    Ok(verdict @ Verdict::Drop) => {
                        debug!(client_addr = %addr, verdict = ?verdict, "dropping connection");
                        metrics.inc_dropped();
                        // Drop the connection.
                    }
                    Err(e) => {
                        warn!(client_addr = %addr, error = %e, "classification error, dropping connection");
                        metrics.inc_dropped();
                        // Drop the connection.
                    }
                }
            });
        }
    }

    async fn proxy_to_upstream(mut inbound: TcpStream, upstream: SocketAddr) -> io::Result<()> {
        trace!(upstream_addr = %upstream, "connecting to upstream");
        let mut outbound = TcpStream::connect(upstream).await?;
        trace!(upstream_addr = %upstream, "connected to upstream, starting bidirectional copy");
        let result = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
        match &result {
            Ok((bytes_inbound, bytes_outbound)) => {
                trace!(upstream_addr = %upstream, bytes_inbound = bytes_inbound, bytes_outbound = bytes_outbound, "proxy completed");
            }
            Err(e) => {
                error!(upstream_addr = %upstream, error = %e, "proxy bidirectional copy failed");
            }
        }
        result?;
        Ok(())
    }

    async fn classify_stream(
        stream: &TcpStream,
        server_secret: SharedSecret,
    ) -> io::Result<Verdict> {
        let mut buf = vec![0u8; PEEK_LEN];
        let mut last_len = 0usize;

        trace!(
            max_attempts = PEEK_ATTEMPTS,
            buf_size = PEEK_LEN,
            "starting stream classification"
        );

        for attempt in 0..PEEK_ATTEMPTS {
            let n = stream.peek(&mut buf).await?;
            trace!(attempt = attempt, bytes_peeked = n, "peeked at stream");

            if n == 0 {
                debug!("received zero bytes on peek, dropping connection");
                return Ok(Verdict::Drop);
            }

            let verdict = classify_tcp_client_hello(&buf[..n], &server_secret);
            trace!(attempt = attempt, bytes_peeked = n, verdict = ?verdict, "classification attempt");

            if verdict != Verdict::Incomplete {
                debug!(attempts = attempt + 1, final_bytes_peeked = n, verdict = ?verdict, "classification complete");
                return Ok(verdict);
            }

            if n == last_len {
                debug!(
                    attempts = attempt + 1,
                    final_bytes_peeked = n,
                    "no new data available, classification incomplete"
                );
                break;
            }
            last_len = n;
            trace!(
                attempt = attempt,
                bytes_peeked = n,
                "yielding for more data"
            );
            tokio::task::yield_now().await;
        }

        debug!("exhausted peek attempts, verdict incomplete");
        Ok(Verdict::Incomplete)
    }
}
