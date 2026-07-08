//! TCP front-door handling.

mod admission;
mod classification;
mod proxy;
mod stream_io;

#[cfg(test)]
mod tests;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use slt_core::classifier::{Verdict, classify_tcp_client_hello};
use slt_core::config::ServerConfig;
use slt_core::types::SharedSecret;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use self::admission::{TcpAdmission, TcpAdmissionPermit};
use self::classification::{ClassificationOutcome, classify_admitted_stream, classify_stream_fast};
use self::proxy::proxy_to_upstream;
use super::metrics::Metrics;

type ClaimHandler = dyn Fn(TcpStream, SocketAddr) + Send + Sync + 'static;

struct ClassificationTask {
    stream: Arc<TcpStream>,
    addr: SocketAddr,
    server_secret: SharedSecret,
    upstream: SocketAddr,
    classification_timeout: Duration,
    permit: TcpAdmissionPermit,
    claim_handler: Arc<ClaimHandler>,
    metrics: Arc<Metrics>,
}

/// TCP acceptor and `ClientHello` classifier.
///
/// Listens for TCP connections, inspects TLS `ClientHello` messages to
/// identify VPN clients, and routes connections either to the claim handler
/// (for VPN clients) or proxies them to nginx (for regular traffic).
#[derive(Debug)]
pub struct TcpFrontDoor {
    listener: TcpListener,
    classification_secret: SharedSecret,
    nginx_tcp_upstream: SocketAddr,
    classification_timeout: Duration,
    tcp_admission: Arc<TcpAdmission>,
    metrics: Arc<Metrics>,
}

impl TcpFrontDoor {
    /// Bind to the configured TCP listener.
    ///
    /// # Errors
    ///
    /// Returns an error if TCP listener binding fails.
    pub async fn bind(config: &ServerConfig, metrics: Arc<Metrics>) -> io::Result<Self> {
        debug!(listen_addr = %config.network.listen_tcp, upstream_addr = %config.network.nginx_tcp_upstream, "binding TCP front door");
        let listener = TcpListener::bind(config.network.listen_tcp).await?;
        info!(listen_addr = %config.network.listen_tcp, "TCP front door bound successfully");
        Ok(Self {
            listener,
            classification_secret: config.server_secret,
            nginx_tcp_upstream: config.network.nginx_tcp_upstream,
            classification_timeout: config.timing.tcp_classification_timeout,
            tcp_admission: Arc::new(TcpAdmission::new(config.tcp_connection_cap)),
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
        let claim_handler: Arc<ClaimHandler> = Arc::new(claim_handler);
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
            let classification_timeout = self.classification_timeout;
            let admission = self.tcp_admission.clone();
            let metrics = self.metrics.clone();

            let admission_attempt = admission.admit_or_evict_empty();
            if admission_attempt.evicted_empty {
                debug!(client_addr = %addr, "evicted empty TCP classifier slot");
                metrics.inc_tcp_empty_classification_evictions();
                metrics.inc_dropped();
            }

            let Some(permit) = admission_attempt.permit else {
                Self::handle_over_cap_stream(
                    stream,
                    addr,
                    server_secret,
                    claim_handler.clone(),
                    metrics,
                );
                continue;
            };

            let stream = Arc::new(stream);
            // A fresh permit is not evictable until this registration; the
            // false branch preserves the admission invariant if that changes.
            if !permit.mark_no_data_if_empty(&stream) {
                debug!(client_addr = %addr, "admitted TCP connection evicted before classification");
                continue;
            }

            Self::spawn_classification_task(ClassificationTask {
                stream,
                addr,
                server_secret,
                upstream,
                classification_timeout,
                permit,
                claim_handler: claim_handler.clone(),
                metrics,
            });
        }
    }

    fn handle_over_cap_stream(
        stream: TcpStream,
        addr: SocketAddr,
        server_secret: SharedSecret,
        claim_handler: Arc<ClaimHandler>,
        metrics: Arc<Metrics>,
    ) {
        // At the cap, mirror nginx's worker-connection pressure behavior:
        // drop the new socket unless a complete VPN claim is already buffered.
        match classify_stream_fast(&stream, server_secret) {
            Ok(Verdict::Claim) => {
                debug!(client_addr = %addr, "connection claimed by fast over-cap classification");
                tokio::spawn(async move {
                    metrics.inc_claimed();
                    claim_handler(stream, addr);
                });
            }
            Ok(verdict) => {
                debug!(client_addr = %addr, verdict = ?verdict, "dropping over-cap TCP connection");
                metrics.inc_tcp_frontdoor_cap_drops();
                metrics.inc_dropped();
            }
            Err(e) => {
                warn!(client_addr = %addr, error = %e, "fast over-cap classification error, dropping connection");
                metrics.inc_tcp_frontdoor_cap_drops();
                metrics.inc_dropped();
            }
        }
    }

    fn spawn_classification_task(task: ClassificationTask) {
        let ClassificationTask {
            stream,
            addr,
            server_secret,
            upstream,
            classification_timeout,
            permit,
            claim_handler,
            metrics,
        } = task;

        tokio::spawn(async move {
            match classify_admitted_stream(&stream, server_secret, classification_timeout, &permit)
                .await
            {
                Ok(ClassificationOutcome::Verdict(verdict @ Verdict::Claim)) => {
                    Self::handle_claimed_stream(
                        stream,
                        addr,
                        permit,
                        claim_handler.as_ref(),
                        metrics.as_ref(),
                        verdict,
                    );
                }
                Ok(ClassificationOutcome::Verdict(verdict @ Verdict::Pass)) => {
                    Self::handle_pass_stream(stream, addr, upstream, metrics.as_ref(), verdict)
                        .await;
                }
                Ok(ClassificationOutcome::Verdict(verdict @ Verdict::Drop)) => {
                    debug!(client_addr = %addr, verdict = ?verdict, "dropping connection");
                    metrics.inc_dropped();
                }
                Ok(ClassificationOutcome::Verdict(verdict @ Verdict::Incomplete)) => {
                    debug!(client_addr = %addr, verdict = ?verdict, "classification timed out, dropping connection");
                    metrics.inc_tcp_classification_timeouts();
                    metrics.inc_dropped();
                }
                Ok(ClassificationOutcome::Evicted) => {
                    debug!(client_addr = %addr, "empty classifying connection evicted");
                }
                Err(e) => {
                    warn!(client_addr = %addr, error = %e, "classification error, dropping connection");
                    metrics.inc_dropped();
                }
            }
        });
    }

    fn handle_claimed_stream(
        stream: Arc<TcpStream>,
        addr: SocketAddr,
        permit: TcpAdmissionPermit,
        claim_handler: &ClaimHandler,
        metrics: &Metrics,
        verdict: Verdict,
    ) {
        debug!(client_addr = %addr, verdict = ?verdict, "connection claimed");
        let Some(stream) = Arc::into_inner(stream) else {
            error!(client_addr = %addr, "classified TCP stream still has shared owners");
            metrics.inc_dropped();
            return;
        };
        metrics.inc_claimed();
        drop(permit);
        claim_handler(stream, addr);
    }

    async fn handle_pass_stream(
        stream: Arc<TcpStream>,
        addr: SocketAddr,
        upstream: SocketAddr,
        metrics: &Metrics,
        verdict: Verdict,
    ) {
        debug!(client_addr = %addr, verdict = ?verdict, upstream_addr = %upstream, "passing connection to upstream");
        let Some(stream) = Arc::into_inner(stream) else {
            error!(client_addr = %addr, "classified TCP stream still has shared owners");
            metrics.inc_dropped();
            return;
        };
        metrics.inc_passed();
        if let Err(e) = proxy_to_upstream(stream, upstream).await {
            warn!(client_addr = %addr, upstream_addr = %upstream, error = %e, "upstream proxy error");
        }
    }
}
