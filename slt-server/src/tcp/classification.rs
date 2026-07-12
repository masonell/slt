use std::io::{self, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use slt_core::classifier::{Verdict, classify_tcp_client_hello};
use slt_core::crypto::client_hello::MAX_TCP_CLIENT_HELLO_WIRE_LEN;
use slt_core::types::SharedSecret;
use tokio::net::TcpStream;
use tracing::{debug, trace};

use super::admission::TcpAdmissionPermit;
use super::stream_io::peek_stream_now;

const PEEK_LEN: usize = MAX_TCP_CLIENT_HELLO_WIRE_LEN;
pub(super) const CLASSIFY_RETRY_DELAY: Duration = Duration::from_millis(5);
pub(super) const CLASSIFY_STABLE_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClassificationOutcome {
    Verdict(Verdict),
    Evicted,
}

/// Classify a TCP stream by inspecting its TLS `ClientHello`.
///
/// Peeks at the stream data with retries to handle slow arrivals,
/// classifies the buffer, and returns a verdict. Respects the
/// classification timeout and drops connections that send no data.
///
/// # Errors
///
/// Returns an error if peeking at the stream fails.
#[cfg(test)]
pub(super) async fn classify_stream(
    stream: &TcpStream,
    server_secret: SharedSecret,
    classification_timeout: Duration,
) -> io::Result<Verdict> {
    match classify_stream_inner(stream, server_secret, classification_timeout, None).await? {
        ClassificationOutcome::Verdict(verdict) => Ok(verdict),
        ClassificationOutcome::Evicted => Ok(Verdict::Drop),
    }
}

pub(super) async fn classify_admitted_stream(
    stream: &Arc<TcpStream>,
    server_secret: SharedSecret,
    classification_timeout: Duration,
    permit: &TcpAdmissionPermit,
) -> io::Result<ClassificationOutcome> {
    classify_stream_inner(
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

        let n = match peek_with_deadline(
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

        let retry_delay =
            next_incomplete_retry_delay(&mut last_incomplete_len, &mut incomplete_retry_delay, n);

        let wait = retry_delay.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
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

pub(super) fn classify_stream_fast(
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

pub(super) fn next_incomplete_retry_delay(
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
