//! TCP front-door handling.

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use parking_lot::Mutex;
use slt_core::classifier::{Verdict, classify_tcp_client_hello};
use slt_core::config::ServerConfig;
use slt_core::types::SharedSecret;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use super::metrics::Metrics;

const PEEK_LEN: usize = 16 * 1024;
const CLASSIFY_RETRY_DELAY: Duration = Duration::from_millis(5);
const CLASSIFY_STABLE_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);
const EMPTY_EVICTION_SCAN_LIMIT: usize = 32;
const EMPTY_EVICTION_SCAN_PASSES: usize = 2;

type ClaimHandler = dyn Fn(TcpStream, SocketAddr) + Send + Sync + 'static;

#[derive(Debug)]
struct TcpAdmission {
    cap: usize,
    state: Mutex<TcpAdmissionState>,
}

#[derive(Debug, Default)]
struct TcpAdmissionState {
    active: usize,
    next_id: u64,
    no_data: HashMap<u64, NoDataAdmission>,
    no_data_head: Option<u64>,
    no_data_tail: Option<u64>,
}

#[derive(Debug, Clone)]
struct NoDataAdmission {
    id: u64,
    cancel: CancellationToken,
    released: Arc<AtomicBool>,
    stream: Weak<TcpStream>,
    prev: Option<u64>,
    next: Option<u64>,
}

#[derive(Debug)]
struct TcpAdmissionAttempt {
    permit: Option<TcpAdmissionPermit>,
    evicted_empty: bool,
}

#[derive(Debug)]
struct TcpAdmissionPermit {
    id: u64,
    cancel: CancellationToken,
    released: Arc<AtomicBool>,
    admission: Arc<TcpAdmission>,
}

impl TcpAdmission {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            state: Mutex::new(TcpAdmissionState::default()),
        }
    }

    fn admit_or_evict_empty(self: &Arc<Self>) -> TcpAdmissionAttempt {
        let mut evict_cancel = None;
        let mut evicted_empty = false;
        let mut permit = self.admit_if_under_cap();

        if permit.is_none() {
            for _ in 0..EMPTY_EVICTION_SCAN_PASSES {
                let mut removed_stale = false;

                for entry in self.eviction_candidates() {
                    if entry.is_empty() {
                        if let Some(cancel) = self.try_evict_empty(entry.id) {
                            evict_cancel = Some(cancel);
                            evicted_empty = true;
                            break;
                        }
                    } else {
                        self.remove_stale_no_data(entry.id);
                        removed_stale = true;
                    }
                }

                if evict_cancel.is_some() || !removed_stale {
                    break;
                }

                permit = self.admit_if_under_cap();
                if permit.is_some() {
                    break;
                }
            }

            if permit.is_none() {
                permit = self.admit_if_under_cap();
            }
        }

        if let Some(cancel) = evict_cancel {
            cancel.cancel();
        }

        TcpAdmissionAttempt {
            permit,
            evicted_empty,
        }
    }

    fn admit_if_under_cap(self: &Arc<Self>) -> Option<TcpAdmissionPermit> {
        let mut state = self.state.lock();
        if state.active < self.cap {
            Some(Self::admit_locked(self, &mut state))
        } else {
            None
        }
    }

    fn eviction_candidates(&self) -> Vec<NoDataAdmission> {
        let state = self.state.lock();
        if state.active < self.cap {
            return Vec::new();
        }

        let mut candidates = Vec::with_capacity(EMPTY_EVICTION_SCAN_LIMIT);
        let mut id = state.no_data_head;
        while candidates.len() < EMPTY_EVICTION_SCAN_LIMIT {
            let Some(current_id) = id else { break };
            let Some(entry) = state.no_data.get(&current_id) else {
                break;
            };
            id = entry.next;
            candidates.push(entry.clone());
        }
        drop(state);
        candidates
    }

    fn try_evict_empty(&self, id: u64) -> Option<CancellationToken> {
        let mut state = self.state.lock();
        if state.active < self.cap {
            return None;
        }

        let entry = Self::remove_no_data_locked(&mut state, id)?;
        if entry.released.swap(true, Ordering::AcqRel) {
            return None;
        }

        state.active = state.active.saturating_sub(1);
        drop(state);
        Some(entry.cancel)
    }

    fn remove_stale_no_data(&self, id: u64) {
        let mut state = self.state.lock();
        if Self::remove_no_data_locked(&mut state, id).is_some() {
            // The owner saw no data earlier but data is buffered now; it will
            // stay non-evictable unless a later classifier loop observes empty.
        }
    }

    fn insert_no_data_locked(state: &mut TcpAdmissionState, mut entry: NoDataAdmission) {
        let id = entry.id;
        entry.prev = state.no_data_tail;
        entry.next = None;

        if let Some(tail) = state.no_data_tail {
            if let Some(tail_entry) = state.no_data.get_mut(&tail) {
                tail_entry.next = Some(id);
            }
        } else {
            state.no_data_head = Some(id);
        }

        state.no_data_tail = Some(id);
        state.no_data.insert(id, entry);
    }

    fn remove_no_data_locked(state: &mut TcpAdmissionState, id: u64) -> Option<NoDataAdmission> {
        let entry = state.no_data.remove(&id)?;

        if let Some(prev) = entry.prev {
            if let Some(prev_entry) = state.no_data.get_mut(&prev) {
                prev_entry.next = entry.next;
            }
        } else {
            state.no_data_head = entry.next;
        }

        if let Some(next) = entry.next {
            if let Some(next_entry) = state.no_data.get_mut(&next) {
                next_entry.prev = entry.prev;
            }
        } else {
            state.no_data_tail = entry.prev;
        }

        Some(entry)
    }

    fn admit_locked(self: &Arc<Self>, state: &mut TcpAdmissionState) -> TcpAdmissionPermit {
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        state.active += 1;

        let cancel = CancellationToken::new();
        let released = Arc::new(AtomicBool::new(false));

        TcpAdmissionPermit {
            id,
            cancel,
            released,
            admission: self.clone(),
        }
    }
}

impl NoDataAdmission {
    fn is_empty(&self) -> bool {
        self.stream
            .upgrade()
            .is_some_and(|stream| stream_has_no_buffered_data(&stream))
    }
}

impl TcpAdmissionPermit {
    fn is_released(&self) -> bool {
        self.released.load(Ordering::Acquire)
    }

    fn mark_no_data_if_empty(&self, stream: &Arc<TcpStream>) -> bool {
        if !stream_has_no_buffered_data(stream) {
            return self.mark_data_seen();
        }

        let mut state = self.admission.state.lock();
        if self.released.load(Ordering::Acquire) {
            return false;
        }
        if !state.no_data.contains_key(&self.id) {
            TcpAdmission::insert_no_data_locked(
                &mut state,
                NoDataAdmission {
                    id: self.id,
                    cancel: self.cancel.clone(),
                    released: self.released.clone(),
                    stream: Arc::downgrade(stream),
                    prev: None,
                    next: None,
                },
            );
        }
        drop(state);
        true
    }

    fn mark_data_seen(&self) -> bool {
        let mut state = self.admission.state.lock();
        if self.released.load(Ordering::Acquire) {
            return false;
        }
        TcpAdmission::remove_no_data_locked(&mut state, self.id);
        true
    }
}

impl Drop for TcpAdmissionPermit {
    fn drop(&mut self) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }

        let mut state = self.admission.state.lock();
        state.active = state.active.saturating_sub(1);
        TcpAdmission::remove_no_data_locked(&mut state, self.id);
        drop(state);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassificationOutcome {
    Verdict(Verdict),
    Evicted,
}

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
        match Self::classify_stream_fast(&stream, server_secret) {
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
            match Self::classify_admitted_stream(
                &stream,
                server_secret,
                classification_timeout,
                &permit,
            )
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
        if let Err(e) = Self::proxy_to_upstream(stream, upstream).await {
            warn!(client_addr = %addr, upstream_addr = %upstream, error = %e, "upstream proxy error");
        }
    }

    /// Proxy a TCP stream to the nginx upstream.
    ///
    /// Connects to the upstream server and performs bidirectional copying
    /// of data between the inbound client stream and the upstream stream.
    ///
    /// # Arguments
    ///
    /// * `inbound` - Client TCP stream
    /// * `upstream` - Nginx upstream address to connect to
    ///
    /// # Errors
    ///
    /// Returns an error if connecting to upstream or bidirectional copy fails.
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

    /// Classify a TCP stream by inspecting its TLS `ClientHello`.
    ///
    /// Peeks at the stream data with retries to handle slow arrivals,
    /// classifies the buffer, and returns a verdict. Respects the
    /// classification timeout and drops connections that send no data.
    ///
    /// # Arguments
    ///
    /// * `stream` - TCP stream to classify
    /// * `server_secret` - Secret key for HMAC verification
    ///
    /// # Returns
    ///
    /// The classification verdict (Claim, Pass, Drop, or Incomplete).
    ///
    /// # Errors
    ///
    /// Returns an error if peeking at the stream fails.
    #[cfg(test)]
    async fn classify_stream(
        stream: &TcpStream,
        server_secret: SharedSecret,
        classification_timeout: Duration,
    ) -> io::Result<Verdict> {
        match Self::classify_stream_inner(stream, server_secret, classification_timeout, None)
            .await?
        {
            ClassificationOutcome::Verdict(verdict) => Ok(verdict),
            ClassificationOutcome::Evicted => Ok(Verdict::Drop),
        }
    }

    async fn classify_admitted_stream(
        stream: &Arc<TcpStream>,
        server_secret: SharedSecret,
        classification_timeout: Duration,
        permit: &TcpAdmissionPermit,
    ) -> io::Result<ClassificationOutcome> {
        Self::classify_stream_inner(
            stream,
            server_secret,
            classification_timeout,
            Some((permit, stream)),
        )
        .await
    }

    async fn classify_stream_inner(
        stream: &TcpStream,
        server_secret: SharedSecret,
        classification_timeout: Duration,
        permit: Option<(&TcpAdmissionPermit, &Arc<TcpStream>)>,
    ) -> io::Result<ClassificationOutcome> {
        let mut buf = vec![0u8; PEEK_LEN];
        let deadline = tokio::time::Instant::now() + classification_timeout;
        let mut attempts = 0usize;
        let mut data_seen = false;
        let mut last_incomplete_len = None;
        let mut incomplete_retry_delay = CLASSIFY_RETRY_DELAY;

        trace!(
            timeout_ms = classification_timeout.as_millis(),
            retry_delay_ms = CLASSIFY_RETRY_DELAY.as_millis(),
            buf_size = PEEK_LEN,
            "starting stream classification"
        );

        loop {
            if permit.is_some_and(|(permit, _)| permit.is_released()) {
                return Ok(ClassificationOutcome::Evicted);
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                debug!(
                    attempts = attempts,
                    timeout_ms = classification_timeout.as_millis(),
                    "classification timed out, verdict incomplete"
                );
                return Ok(ClassificationOutcome::Verdict(Verdict::Incomplete));
            }

            let remaining = deadline.saturating_duration_since(now);
            let attempt = attempts;
            attempts += 1;

            if !data_seen
                && let Some((permit, stream)) = permit
                && !permit.mark_no_data_if_empty(stream)
            {
                return Ok(ClassificationOutcome::Evicted);
            }

            let n = match Self::peek_with_deadline(
                stream,
                &mut buf,
                remaining,
                permit.map(|(permit, _)| permit),
                attempts,
                classification_timeout,
            )
            .await?
            {
                Ok(n) => n,
                Err(outcome) => return Ok(outcome),
            };
            trace!(attempt = attempt, bytes_peeked = n, "peeked at stream");

            if permit.is_some_and(|(permit, _)| permit.is_released()) {
                return Ok(ClassificationOutcome::Evicted);
            }

            if n == 0 {
                debug!("received zero bytes on peek, dropping connection");
                return Ok(ClassificationOutcome::Verdict(Verdict::Drop));
            }

            if !data_seen {
                if let Some((permit, _)) = permit
                    && !permit.mark_data_seen()
                {
                    return Ok(ClassificationOutcome::Evicted);
                }
                data_seen = true;
            }

            let verdict = classify_tcp_client_hello(&buf[..n], &server_secret);
            trace!(attempt = attempt, bytes_peeked = n, verdict = ?verdict, "classification attempt");

            if verdict != Verdict::Incomplete {
                debug!(attempts = attempt + 1, final_bytes_peeked = n, verdict = ?verdict, "classification complete");
                return Ok(ClassificationOutcome::Verdict(verdict));
            }

            trace!(
                attempt = attempt,
                bytes_peeked = n,
                "classification incomplete, waiting for more data"
            );

            let retry_delay = next_incomplete_retry_delay(
                &mut last_incomplete_len,
                &mut incomplete_retry_delay,
                n,
            );

            let wait =
                retry_delay.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
            if wait.is_zero() {
                continue;
            }
            if let Some((permit, _)) = permit {
                tokio::select! {
                    () = permit.cancel.cancelled() => {
                        return Ok(ClassificationOutcome::Evicted);
                    }
                    () = tokio::time::sleep(wait) => {}
                }
            } else {
                tokio::time::sleep(wait).await;
            }
        }
    }

    async fn peek_with_deadline(
        stream: &TcpStream,
        buf: &mut [u8],
        remaining: Duration,
        permit: Option<&TcpAdmissionPermit>,
        attempts: usize,
        classification_timeout: Duration,
    ) -> io::Result<Result<usize, ClassificationOutcome>> {
        let peek = tokio::time::timeout(remaining, stream.peek(buf));
        let res = if let Some(permit) = permit {
            tokio::select! {
                () = permit.cancel.cancelled() => {
                    return Ok(Err(ClassificationOutcome::Evicted));
                }
                res = peek => res,
            }
        } else {
            peek.await
        };

        if let Ok(res) = res {
            return Ok(Ok(res?));
        }

        debug!(
            attempts = attempts,
            timeout_ms = classification_timeout.as_millis(),
            "classification timed out waiting for stream data"
        );
        Ok(Err(ClassificationOutcome::Verdict(Verdict::Incomplete)))
    }

    fn classify_stream_fast(
        stream: &TcpStream,
        server_secret: SharedSecret,
    ) -> io::Result<Verdict> {
        let mut buf = vec![0u8; PEEK_LEN];
        match peek_stream_now(stream, &mut buf) {
            Ok(0) => Ok(Verdict::Drop),
            Ok(n) => Ok(classify_tcp_client_hello(&buf[..n], &server_secret)),
            Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(Verdict::Incomplete),
            Err(err) => Err(err),
        }
    }
}

fn next_incomplete_retry_delay(
    last_incomplete_len: &mut Option<usize>,
    incomplete_retry_delay: &mut Duration,
    bytes_peeked: usize,
) -> Duration {
    if *last_incomplete_len == Some(bytes_peeked) {
        *incomplete_retry_delay = incomplete_retry_delay
            .saturating_mul(2)
            .min(CLASSIFY_STABLE_RETRY_MAX_DELAY);
        return *incomplete_retry_delay;
    }

    *last_incomplete_len = Some(bytes_peeked);
    *incomplete_retry_delay = CLASSIFY_RETRY_DELAY;
    CLASSIFY_RETRY_DELAY
}

#[cfg(unix)]
fn peek_stream_now(stream: &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::fd::AsRawFd;

    let flags = libc::MSG_PEEK | libc::MSG_DONTWAIT;
    // Tokio's mio TCP readiness is level-triggered; MSG_PEEK does not consume
    // bytes, so this probe coexists with the async peek/read path.
    // SAFETY: `buf` points to writable memory for `buf.len()` bytes, and the
    // borrowed TCP file descriptor remains valid for the duration of this call.
    loop {
        let n = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                flags,
            )
        };

        if n >= 0 {
            return Ok(n.cast_unsigned());
        }

        let err = io::Error::last_os_error();
        if err.kind() != ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(not(unix))]
fn peek_stream_now(_stream: &TcpStream, _buf: &mut [u8]) -> io::Result<usize> {
    Err(io::Error::from(ErrorKind::WouldBlock))
}

#[cfg(unix)]
fn stream_has_no_buffered_data(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match peek_stream_now(stream, &mut buf) {
        Ok(0) => true,
        Err(err) if err.kind() == ErrorKind::WouldBlock => true,
        Ok(_) | Err(_) => false,
    }
}

#[cfg(not(unix))]
fn stream_has_no_buffered_data(_stream: &TcpStream) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use slt_core::classifier::Verdict;
    use slt_core::config::ServerConfig;
    use slt_core::testing::generate_client_hello_tls_record;
    use slt_core::types::{
        ClientId, PubKeyEd25519, ServerClient, ServerNetworkConfig, ServerTimingConfig,
        ServerTlsConfig, ServerTransportConfig, SharedSecret, TlsMaterial, TunConfig,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use super::{
        CLASSIFY_RETRY_DELAY, CLASSIFY_STABLE_RETRY_MAX_DELAY, EMPTY_EVICTION_SCAN_LIMIT,
        TcpAdmission, TcpFrontDoor, next_incomplete_retry_delay,
    };
    use crate::metrics::Metrics;

    /// Create a test config with listen address set to "127.0.0.1:0" (any available port)
    /// and the upstream address set to the provided address.
    fn test_config(upstream_addr: SocketAddr) -> ServerConfig {
        ServerConfig {
            server_secret: SharedSecret([0x42u8; 32]),
            network: ServerNetworkConfig {
                listen_tcp: "127.0.0.1:0".parse().unwrap(),
                listen_udp: "127.0.0.1:0".parse().unwrap(),
                nginx_tcp_upstream: upstream_addr,
                nginx_udp_upstream: upstream_addr,
            },
            tls: ServerTlsConfig {
                tls_cert: TlsMaterial::Pem(String::new()),
                tls_key: TlsMaterial::Pem(String::new()),
            },
            tun: TunConfig {
                tun_name: "tun0".to_string(),
                tun_mtu: 1280,
                tun_ipv4: Ipv4Addr::new(10, 10, 0, 1),
                tun_prefix: 24,
            },
            timing: ServerTimingConfig {
                ping_min: Duration::from_secs(10),
                ping_max: Duration::from_secs(20),
                auth_timeout: Duration::from_secs(10),
                idle_timeout: Duration::from_mins(1),
                metrics_interval: Duration::from_mins(5),
                tcp_classification_timeout: Duration::from_secs(60),
            },
            transport: ServerTransportConfig::default(),
            udp_nat_max_entries: 1024,
            session_queue_size: 256,
            max_auth_inflight: 128,
            tcp_connection_cap: 512,
            clients: vec![ServerClient {
                client_id: ClientId([0u8; 16]),
                pubkey_ed25519: PubKeyEd25519([0u8; 32]),
                assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
                enabled: true,
            }],
        }
    }

    fn test_config_with_tcp_limits(
        upstream_addr: SocketAddr,
        tcp_connection_cap: usize,
        tcp_classification_timeout: Duration,
    ) -> ServerConfig {
        let mut config = test_config(upstream_addr);
        config.tcp_connection_cap = tcp_connection_cap;
        config.timing.tcp_classification_timeout = tcp_classification_timeout;
        config
    }

    #[test]
    fn incomplete_retry_delay_backs_off_until_buffer_grows() {
        let mut last_len = None;
        let mut delay = CLASSIFY_RETRY_DELAY;

        assert_eq!(
            next_incomplete_retry_delay(&mut last_len, &mut delay, 4),
            CLASSIFY_RETRY_DELAY
        );
        assert_eq!(
            next_incomplete_retry_delay(&mut last_len, &mut delay, 4),
            Duration::from_millis(10)
        );
        assert_eq!(
            next_incomplete_retry_delay(&mut last_len, &mut delay, 4),
            Duration::from_millis(20)
        );
        assert_eq!(
            next_incomplete_retry_delay(&mut last_len, &mut delay, 5),
            CLASSIFY_RETRY_DELAY
        );

        for _ in 0..16 {
            let _ = next_incomplete_retry_delay(&mut last_len, &mut delay, 5);
        }
        assert_eq!(delay, CLASSIFY_STABLE_RETRY_MAX_DELAY);
    }

    #[test]
    fn admission_does_not_mark_fresh_permit_as_empty() {
        let admission = Arc::new(TcpAdmission::new(1));

        let first = admission.admit_or_evict_empty();
        assert!(first.permit.is_some());
        assert!(!first.evicted_empty);

        let second = admission.admit_or_evict_empty();
        assert!(second.permit.is_none());
        assert!(!second.evicted_empty);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn admission_does_not_evict_data_ready_empty_candidate() {
        let admission = Arc::new(TcpAdmission::new(1));
        let permit = admission
            .admit_or_evict_empty()
            .permit
            .expect("first connection should be admitted");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let server = Arc::new(server);

        assert!(permit.mark_no_data_if_empty(&server));
        client.write_all(&[0x16]).await.unwrap();
        timeout(Duration::from_secs(1), async {
            while super::stream_has_no_buffered_data(&server) {
                server.readable().await.unwrap();
            }
        })
        .await
        .expect("server byte should become visible to nonblocking peek");

        let second = admission.admit_or_evict_empty();
        assert!(second.permit.is_none());
        assert!(!second.evicted_empty);
        assert!(permit.mark_data_seen());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mark_data_seen_reports_concurrent_eviction() {
        let admission = Arc::new(TcpAdmission::new(1));
        let permit = admission
            .admit_or_evict_empty()
            .permit
            .expect("first connection should be admitted");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let server = Arc::new(server);

        assert!(permit.mark_no_data_if_empty(&server));

        let second = admission.admit_or_evict_empty();
        assert!(second.permit.is_some());
        assert!(second.evicted_empty);
        assert!(!permit.mark_data_seen());

        drop(client);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn admission_rescans_once_after_unlinking_stale_no_data_entries() {
        let admission = Arc::new(TcpAdmission::new(EMPTY_EVICTION_SCAN_LIMIT + 1));
        let mut permits = Vec::new();
        let mut clients = Vec::new();
        let mut servers = Vec::new();

        for _ in 0..=EMPTY_EVICTION_SCAN_LIMIT {
            let permit = admission
                .admit_or_evict_empty()
                .permit
                .expect("connection should be admitted below cap");

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).await.unwrap();
            let (server, _) = listener.accept().await.unwrap();
            let server = Arc::new(server);

            assert!(permit.mark_no_data_if_empty(&server));
            permits.push(permit);
            clients.push(client);
            servers.push(server);
        }

        for (client, server) in clients
            .iter_mut()
            .zip(servers.iter())
            .take(EMPTY_EVICTION_SCAN_LIMIT)
        {
            client.write_all(&[0x16]).await.unwrap();
            timeout(Duration::from_secs(1), async {
                while super::stream_has_no_buffered_data(server) {
                    server.readable().await.unwrap();
                }
            })
            .await
            .expect("server byte should become visible to nonblocking peek");
        }

        let attempt = admission.admit_or_evict_empty();
        assert!(attempt.evicted_empty);
        assert!(attempt.permit.is_some());

        drop(permits);
        drop(clients);
        drop(servers);
    }

    #[test]
    fn classify_delegates_to_classifier() {
        let secret = SharedSecret([0x42u8; 32]);
        let client_hello = generate_client_hello_tls_record(secret);

        let metrics = Arc::new(Metrics::default());
        // Bind upstream first to reserve its port (avoid TOCTOU race)
        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Keep upstream_listener alive until front_door binds
            let _upstream = upstream_listener;
            let front_door = TcpFrontDoor::bind(&config, metrics).await.unwrap();

            // Claim verdict for matching secret
            assert_eq!(
                front_door.classify(&client_hello),
                slt_core::classifier::Verdict::Claim
            );

            // Pass verdict for non-matching secret
            let wrong_secret_client_hello =
                generate_client_hello_tls_record(SharedSecret([0x99u8; 32]));
            assert_eq!(
                front_door.classify(&wrong_secret_client_hello),
                slt_core::classifier::Verdict::Pass
            );

            // Incomplete for empty buffer
            assert_eq!(
                front_door.classify(&[]),
                slt_core::classifier::Verdict::Incomplete
            );

            // Incomplete for buffer smaller than TLS record header (5 bytes)
            assert_eq!(
                front_door.classify(&[0x00, 0x01, 0x02]),
                slt_core::classifier::Verdict::Incomplete
            );

            // Pass for non-TLS handshake data (content_type != 0x16)
            assert_eq!(
                front_door.classify(&[0x00, 0x03, 0x03, 0x00, 0x10]),
                slt_core::classifier::Verdict::Pass
            );
        });
    }

    #[tokio::test]
    async fn bind_creates_listener_on_configured_address() {
        let metrics = Arc::new(Metrics::default());
        // Bind upstream first to reserve its port
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        // Keep upstream_listener alive until front_door binds
        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics).await.unwrap();

        // Verify listener is bound to localhost
        let addr = front_door.listener().local_addr().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn listener_returns_bound_socket() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics).await.unwrap();
        let listener = front_door.listener();

        let addr = listener.local_addr().unwrap();
        assert!(!addr.ip().is_unspecified() || addr.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn run_exits_on_cancellation() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics).await.unwrap();
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        cancel.cancel();

        let result = timeout(Duration::from_millis(500), run_task).await;
        assert!(result.is_ok(), "run should exit quickly on cancellation");
        assert!(result.unwrap().is_ok(), "run should return Ok(())");
    }

    #[tokio::test]
    async fn run_invokes_claim_handler_for_matching_client_hello() {
        let secret = SharedSecret([0x42u8; 32]);
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let claim_count = Arc::new(AtomicUsize::new(0));
        let claim_count_clone = claim_count.clone();
        let cancel_for_run = cancel.clone();
        let cancel_for_handler = cancel.clone();

        let run_task = tokio::spawn(async move {
            front_door
                .run(cancel_for_run, move |_, _| {
                    claim_count_clone.fetch_add(1, Ordering::SeqCst);
                    cancel_for_handler.cancel();
                })
                .await
        });

        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        let client_hello = generate_client_hello_tls_record(secret);
        stream.write_all(&client_hello).await.unwrap();

        let result = timeout(Duration::from_secs(2), run_task).await;
        assert!(result.is_ok(), "run should exit after claim");
        assert_eq!(
            claim_count.load(Ordering::SeqCst),
            1,
            "claim handler should be called once"
        );

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 1);
        assert_eq!(snapshot.claimed, 1);
    }

    #[tokio::test]
    async fn run_proxies_to_upstream_for_non_matching_client_hello() {
        let metrics = Arc::new(Metrics::default());
        // Bind upstream first to reserve its port
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        // Accept on upstream
        let upstream_task = tokio::spawn(async move {
            let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 1024];
            let n = upstream_stream.read(&mut buf).await.unwrap();
            upstream_stream.write_all(&buf[..n]).await.unwrap();
        });

        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        let wrong_secret = SharedSecret([0x99u8; 32]);
        let client_hello = generate_client_hello_tls_record(wrong_secret);
        stream.write_all(&client_hello).await.unwrap();

        let upstream_result = timeout(Duration::from_secs(2), upstream_task).await;
        assert!(
            upstream_result.is_ok(),
            "upstream should receive connection"
        );

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 1);
        assert_eq!(snapshot.passed, 1);
    }

    #[tokio::test]
    async fn run_drops_connection_on_zero_byte_peek() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        // Connect and immediately close without sending data
        {
            let _stream = TcpStream::connect(listen_addr).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 1);
        assert_eq!(snapshot.dropped, 1);
    }

    #[tokio::test]
    async fn run_handles_multiple_connections_concurrently() {
        let secret = SharedSecret([0x42u8; 32]);
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let claim_count = Arc::new(AtomicUsize::new(0));
        let claim_count_clone = claim_count.clone();
        let (tx, mut rx) = mpsc::channel::<()>(3);

        let cancel_clone = cancel.clone();
        let tx_clone = tx.clone();
        let run_task = tokio::spawn(async move {
            front_door
                .run(cancel_clone, move |_, _| {
                    claim_count_clone.fetch_add(1, Ordering::SeqCst);
                    let _ = tx_clone.try_send(());
                })
                .await
        });

        let mut handles = vec![];
        for _ in 0..3 {
            let addr = listen_addr;
            let handle = tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                let client_hello = generate_client_hello_tls_record(secret);
                stream.write_all(&client_hello).await.unwrap();
            });
            handles.push(handle);
        }

        for _ in 0..3 {
            let result = timeout(Duration::from_secs(2), rx.recv()).await;
            assert!(result.is_ok(), "should receive claim notification");
        }

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        assert_eq!(claim_count.load(Ordering::SeqCst), 3);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 3);
        assert_eq!(snapshot.claimed, 3);
    }

    /// Test that `Verdict::Incomplete` times out and drops without upstream proxying.
    #[tokio::test]
    async fn run_drops_incomplete_verdict_after_classification_timeout() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config_with_tcp_limits(upstream_addr, 512, Duration::from_millis(50));

        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        let upstream_task = tokio::spawn(async move {
            timeout(Duration::from_millis(250), upstream_listener.accept()).await
        });

        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        stream.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(stream);

        let upstream_result = upstream_task.await.unwrap();
        assert_eq!(
            upstream_result.unwrap_err().to_string(),
            "deadline has elapsed"
        );

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 1);
        assert_eq!(snapshot.passed, 0);
        assert_eq!(snapshot.dropped, 1);
        assert_eq!(snapshot.tcp_classification_timeouts, 1);
    }

    #[tokio::test]
    async fn run_evicts_oldest_empty_classifier_under_cap_pressure() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config_with_tcp_limits(upstream_addr, 1, Duration::from_secs(2));

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        let first = TcpStream::connect(listen_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let second = TcpStream::connect(listen_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 2);
        assert_eq!(snapshot.tcp_empty_classification_evictions, 1);
        assert_eq!(snapshot.tcp_frontdoor_cap_drops, 0);
        assert_eq!(snapshot.dropped, 1);

        drop(first);
        drop(second);
        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;
    }

    #[tokio::test]
    async fn run_drops_new_over_cap_connection_when_no_empty_slot_exists() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config_with_tcp_limits(upstream_addr, 1, Duration::from_secs(2));

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        let mut first = TcpStream::connect(listen_addr).await.unwrap();
        first.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let second = TcpStream::connect(listen_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 2);
        assert_eq!(snapshot.tcp_empty_classification_evictions, 0);
        assert_eq!(snapshot.tcp_frontdoor_cap_drops, 1);
        assert_eq!(snapshot.dropped, 1);

        drop(first);
        drop(second);
        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;
    }

    #[tokio::test]
    async fn fast_classification_claims_when_full_client_hello_is_buffered() {
        let secret = SharedSecret([0x42u8; 32]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_hello = generate_client_hello_tls_record(secret);
        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(&client_hello).await.unwrap();
            client
        });

        let (stream, _) = listener.accept().await.unwrap();
        let client = client_task.await.unwrap();

        let verdict = TcpFrontDoor::classify_stream_fast(&stream, secret).unwrap();
        assert_eq!(verdict, Verdict::Claim);

        drop(client);
    }

    /// Test upstream connect failure path (lines 100, 121).
    /// When upstream is unreachable, the proxy should handle the error gracefully.
    #[tokio::test]
    async fn run_handles_upstream_connect_failure() {
        let metrics = Arc::new(Metrics::default());
        // Use a non-routable address to trigger connect failure
        // 10.255.255.1 is typically not routed
        let non_routable_upstream: SocketAddr = "10.255.255.1:12345".parse().unwrap();
        let config = test_config(non_routable_upstream);

        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let (tx, mut rx) = mpsc::channel::<()>(1);
        let tx_clone = tx.clone();
        let run_task = tokio::spawn(async move {
            front_door
                .run(cancel_clone, move |_, _| {
                    let _ = tx_clone.try_send(());
                })
                .await
        });

        // Send non-matching ClientHello to trigger upstream routing
        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        let wrong_secret = SharedSecret([0x99u8; 32]);
        let client_hello = generate_client_hello_tls_record(wrong_secret);
        stream.write_all(&client_hello).await.unwrap();

        // Wait for the connection attempt to complete (with timeout since connect will fail)
        // The run loop should continue despite the failure
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify the front door is still running by sending another connection
        let mut stream2 = TcpStream::connect(listen_addr).await.unwrap();
        stream2.write_all(&client_hello).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 2);
        assert_eq!(
            snapshot.passed, 2,
            "both connections should be passed to upstream"
        );
        // Verify claim handler was never called
        assert!(
            rx.try_recv().is_err(),
            "claim handler should not be called for non-matching ClientHello"
        );
    }

    /// Test upstream bidirectional copy failure path (line 123).
    /// When upstream closes connection during proxy, error should be handled.
    #[tokio::test]
    async fn run_handles_upstream_copy_failure() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        // Accept upstream connection and immediately close it
        let upstream_task = tokio::spawn(async move {
            let (upstream_stream, _) = timeout(Duration::from_secs(2), upstream_listener.accept())
                .await
                .expect("upstream should receive connection")
                .expect("accept should succeed");
            // Immediately drop to cause copy failure
            drop(upstream_stream);
        });

        // Send non-matching ClientHello
        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        let wrong_secret = SharedSecret([0x99u8; 32]);
        let client_hello = generate_client_hello_tls_record(wrong_secret);
        stream.write_all(&client_hello).await.unwrap();

        // Wait for upstream to close
        let upstream_result = timeout(Duration::from_secs(2), upstream_task).await;
        assert!(upstream_result.is_ok(), "upstream task should complete");

        // Give time for the proxy error to be handled
        tokio::time::sleep(Duration::from_millis(100)).await;

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 1);
        assert_eq!(snapshot.passed, 1);
    }

    /// Test `bind()` error path when address is already in use (line 36).
    #[tokio::test]
    async fn bind_fails_when_address_in_use() {
        let metrics = Arc::new(Metrics::default());

        // Bind to a specific port first
        let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound_addr = first_listener.local_addr().unwrap();

        // Create config with the same address
        let mut config = test_config("127.0.0.1:0".parse().unwrap());
        config.network.listen_tcp = bound_addr;

        // Keep first listener alive and try to bind to same address
        let _first = first_listener;
        let result = TcpFrontDoor::bind(&config, metrics).await;

        assert!(
            result.is_err(),
            "bind should fail when address is already in use"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AddrInUse,
            "error should be AddrInUse"
        );
    }

    /// Test that `classify_stream` correctly classifies complete `ClientHello` data.
    /// This verifies the peek loop logic works correctly when full data is available.
    #[tokio::test]
    async fn classify_stream_classifies_complete_client_hello() {
        let secret = SharedSecret([0x42u8; 32]);

        // Create a listener for our test connection
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task that accepts connection and classifies it
        let classify_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TcpFrontDoor::classify_stream(&stream, secret, Duration::from_secs(2)).await
        });

        // Connect and send complete ClientHello
        let mut client = TcpStream::connect(addr).await.unwrap();
        let client_hello = generate_client_hello_tls_record(secret);
        client.write_all(&client_hello).await.unwrap();
        client.flush().await.unwrap();

        // Classification should succeed with complete data
        let result = tokio::select! {
            result = classify_task => result,
            () = tokio::time::sleep(Duration::from_secs(2)) => {
                panic!("classification timed out");
            }
        };

        let verdict = result
            .expect("task should not panic")
            .expect("classification should not error");
        assert!(
            matches!(verdict, slt_core::classifier::Verdict::Claim),
            "should claim valid ClientHello"
        );

        drop(client);
    }

    /// Test that classification timeout returns Incomplete.
    /// When data never arrives to complete classification, it should return Incomplete.
    #[tokio::test]
    async fn classify_stream_returns_incomplete_after_classification_timeout() {
        let secret = SharedSecret([0x42u8; 32]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let classify_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TcpFrontDoor::classify_stream(&stream, secret, Duration::from_millis(50)).await
        });

        // Connect and send minimal data that triggers Incomplete
        let mut client = TcpStream::connect(addr).await.unwrap();
        // Send just 4 bytes - too small for TLS record header (needs 5)
        client.write_all(&[0x16, 0x03, 0x01, 0x00]).await.unwrap();

        // Don't send more data - let classification timeout expire
        let result = timeout(Duration::from_secs(2), classify_task).await;
        assert!(result.is_ok(), "classification should complete");
        let verdict = result
            .expect("classification should complete")
            .expect("task should not panic")
            .expect("classification should not error");
        assert!(
            matches!(verdict, slt_core::classifier::Verdict::Incomplete),
            "should return Incomplete when classification timeout expires without complete data"
        );
    }

    #[tokio::test]
    async fn classify_stream_returns_incomplete_when_no_data_arrives() {
        let secret = SharedSecret([0x42u8; 32]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let classify_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TcpFrontDoor::classify_stream(&stream, secret, Duration::from_millis(50)).await
        });

        // Connect but never send data.
        let _client = TcpStream::connect(addr).await.unwrap();

        let result = timeout(Duration::from_secs(2), classify_task).await;
        assert!(result.is_ok(), "classification should complete");
        let verdict = result
            .expect("classification should complete")
            .expect("task should not panic")
            .expect("classification should not error");
        assert!(
            matches!(verdict, slt_core::classifier::Verdict::Incomplete),
            "should return Incomplete when no bytes arrive before classification timeout"
        );
    }
}
