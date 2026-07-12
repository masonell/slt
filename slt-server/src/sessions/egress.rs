//! Session egress and transport-failure recovery.

use std::future::{Future, poll_fn};
use std::io;
use std::task::Poll;
use std::time::Duration;

use slt_core::crypto::udp_qsp::QuicQspSession;
use slt_core::proto::{CloseCode, ClosePayload, FallbackToTcpPayload, Message, encode_message};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;
use tracing::{debug, info, warn};

use super::error::{SessionError, UdpQspError};
use super::{ActiveTransport, ClientSessionBase, UdpSessionIo};
use crate::tun::TunDeviceIo;

pub(super) const BEST_EFFORT_IO_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
pub(super) enum UdpFailureRecovery {
    RetryMessageOnTcp,
    SignalTcpFallback,
    RetireOnly,
}

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, I: UdpSessionIo>
    ClientSessionBase<T, S, I>
{
    pub(super) async fn send_tcp_message(
        &mut self,
        message: Message<'_>,
    ) -> Result<(), SessionError> {
        if self.tcp_write_interrupted {
            return Err(SessionError::Connection {
                source: io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "TCP frame write was interrupted",
                ),
            });
        }

        // This marker deliberately remains set if the future is dropped by the
        // managed-shutdown select. `write_all` may already have sent a frame
        // prefix, so another framed write on the stream would be unsafe.
        self.tcp_write_interrupted = true;
        let result = self.send_tcp_message_inner(message).await;
        self.tcp_write_interrupted = false;
        result
    }

    async fn send_tcp_message_inner(&mut self, message: Message<'_>) -> Result<(), SessionError> {
        let timeout = self.timeouts.tcp_write_timeout;
        let write = self.tcp.write_message(message);
        tokio::pin!(write);

        // Most writes complete on their first poll. Only register a Tokio timer
        // after socket/TLS backpressure actually makes the write pending.
        let first_poll = poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await;
        let result = match first_poll {
            Poll::Ready(result) => result,
            Poll::Pending => {
                let Ok(result) = time::timeout(timeout, write.as_mut()).await else {
                    warn!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        timeout_ms = timeout.as_millis(),
                        "tcp message write timed out"
                    );
                    return Err(SessionError::Connection {
                        source: io::Error::new(
                            io::ErrorKind::TimedOut,
                            "tcp message write timed out",
                        ),
                    });
                };
                result
            }
        };

        result.map_err(|err| match err {
            slt_core::transport::tcp::TcpWriteError::Frame(frame) => SessionError::Frame(frame),
            slt_core::transport::tcp::TcpWriteError::Io(source) => {
                SessionError::Connection { source }
            }
        })
    }

    /// Send a message via UDP-QSP.
    ///
    /// This method is only called when either:
    /// - `active_transport == UdpQsp` (meaning we've switched to UDP after receiving a packet)
    /// - We're inside `handle_udp_claim` responding to an incoming UDP message
    ///
    /// In both cases, the session's peer has already been set by `handle_udp_claim`,
    /// so we can safely send without checking for a valid peer address.
    async fn queue_udp_message(&mut self, message: Message<'_>) -> Result<(), UdpQspError> {
        let Some(session) = self.udp_session.as_mut() else {
            return Ok(());
        };

        self.udp_write_buf.clear();
        encode_message(message, &mut self.udp_write_buf)?;
        let tx_phase_before = session.tx_key_phase();
        match session.send(&self.udp_write_buf).await {
            Ok(()) => {
                if session.tx_key_phase() != tx_phase_before {
                    self.metrics.inc_udp_qsp_tx_key_phase_transition();
                    info!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        key_phase = session.tx_key_phase(),
                        "UDP-QSP TX key phase transitioned"
                    );
                }
                Ok(())
            }
            Err(err) => Err(UdpQspError::Qsp(err)),
        }
    }

    pub(super) async fn send_udp_message(
        &mut self,
        message: Message<'_>,
        recovery: UdpFailureRecovery,
    ) -> Result<(), SessionError> {
        match self.queue_udp_message(message).await {
            Ok(()) => Ok(()),
            Err(err) => {
                self.recover_from_udp_send_error(message, recovery, err)
                    .await
            }
        }
    }

    pub(super) async fn send_udp_message_and_flush(
        &mut self,
        message: Message<'_>,
        recovery: UdpFailureRecovery,
    ) -> Result<(), SessionError> {
        self.send_udp_message(message, recovery).await?;
        match self.flush_udp_session().await {
            Ok(()) => Ok(()),
            Err(source) => {
                self.recover_from_udp_flush_error(Some(message), recovery, source)
                    .await
            }
        }
    }

    async fn flush_udp_session(&mut self) -> io::Result<()> {
        if let Some(session) = self.udp_session.as_mut() {
            session.flush().await?;
        }
        Ok(())
    }

    async fn recover_from_udp_send_error(
        &mut self,
        message: Message<'_>,
        recovery: UdpFailureRecovery,
        err: UdpQspError,
    ) -> Result<(), SessionError> {
        if !matches!(err, UdpQspError::Qsp(_) | UdpQspError::Io(_)) {
            return Err(err.into());
        }

        warn!(
            session_id = self.session_id,
            client_id = %self.client_id,
            error = %err,
            "UDP-QSP send failed; clearing udp state"
        );
        self.retire_udp_transport();
        self.apply_udp_failure_recovery(Some(message), recovery, err.into())
            .await
    }

    pub(super) async fn recover_from_udp_flush_error(
        &mut self,
        message: Option<Message<'_>>,
        recovery: UdpFailureRecovery,
        source: io::Error,
    ) -> Result<(), SessionError> {
        warn!(
            session_id = self.session_id,
            client_id = %self.client_id,
            error = %source,
            "UDP-QSP flush failed; clearing udp state"
        );
        self.retire_udp_transport();
        self.apply_udp_failure_recovery(
            message,
            recovery,
            SessionError::UdpQsp(UdpQspError::Io(source)),
        )
        .await
    }

    async fn apply_udp_failure_recovery(
        &mut self,
        message: Option<Message<'_>>,
        recovery: UdpFailureRecovery,
        fallback_error: SessionError,
    ) -> Result<(), SessionError> {
        if !self.tcp_alive {
            return Err(fallback_error);
        }

        self.set_active_transport(ActiveTransport::Tcp);
        match recovery {
            UdpFailureRecovery::RetryMessageOnTcp => {
                self.send_tcp_fallback_request().await?;
                let Some(message) = message else {
                    return Ok(());
                };
                self.send_tcp_message(message).await
            }
            UdpFailureRecovery::SignalTcpFallback => self.send_tcp_fallback_request().await,
            UdpFailureRecovery::RetireOnly => Ok(()),
        }
    }

    pub(super) async fn send_tcp_fallback_request(&mut self) -> Result<(), SessionError> {
        if self.pending_tcp_fallback.is_some() {
            return Ok(());
        }

        let fallback_id = fastrand::u64(..);
        let fallback = FallbackToTcpPayload { fallback_id };
        let mut buf = Vec::with_capacity(8);
        fallback.encode(&mut buf);
        self.send_tcp_message(Message::FallbackToTcp { payload: &buf })
            .await?;
        self.pending_tcp_fallback = Some(fallback_id);
        debug!(
            session_id = self.session_id,
            client_id = %self.client_id,
            fallback_id,
            "requested tcp fallback"
        );
        Ok(())
    }

    pub(super) fn retire_udp_transport(&mut self) {
        self.registry.remove_cids_for_session(self.session_id);
        self.udp_session = None;
        self.udp_peer_packet_number = None;
        self.last_authenticated_udp_activity = None;
        self.reset_udp_upgrade_state();
    }

    pub(super) async fn flush_pending_udp_session_best_effort(&mut self) {
        let Some(session) = self.udp_session.as_mut() else {
            return;
        };
        if !session.has_pending_flush() {
            return;
        }
        match time::timeout(BEST_EFFORT_IO_TIMEOUT, session.flush()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                debug!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    error = %err,
                    "failed to flush pending udp-qsp packets during shutdown"
                );
            }
            Err(_) => {
                debug!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    timeout_ms = BEST_EFFORT_IO_TIMEOUT.as_millis(),
                    "timed out flushing pending udp-qsp packets during shutdown"
                );
            }
        }
    }

    pub(super) fn has_pending_udp_flush(&self) -> bool {
        self.active_transport == ActiveTransport::UdpQsp
            && self
                .udp_session
                .as_ref()
                .is_some_and(QuicQspSession::has_pending_flush)
    }

    fn encode_close_payload(code: CloseCode) -> Vec<u8> {
        let payload = ClosePayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        buf
    }

    pub(super) async fn send_close_over_tcp(
        &mut self,
        code: CloseCode,
    ) -> Result<(), SessionError> {
        if !self.tcp_alive || self.tcp_write_interrupted {
            return Err(SessionError::Connection {
                source: io::Error::new(io::ErrorKind::NotConnected, "TCP unavailable for CLOSE"),
            });
        }

        let buf = Self::encode_close_payload(code);
        self.send_tcp_message(Message::Close { payload: &buf })
            .await
    }

    pub(super) async fn send_close_over_udp(
        &mut self,
        code: CloseCode,
    ) -> Result<(), SessionError> {
        if self.udp_session.is_none() {
            return Err(SessionError::Connection {
                source: io::Error::new(
                    io::ErrorKind::NotConnected,
                    "UDP-QSP unavailable for CLOSE",
                ),
            });
        }

        let buf = Self::encode_close_payload(code);
        self.queue_udp_message(Message::Close { payload: &buf })
            .await?;
        self.flush_udp_session()
            .await
            .map_err(|source| SessionError::UdpQsp(UdpQspError::Io(source)))
    }

    pub(super) async fn send_close(&mut self, code: CloseCode) -> Result<(), SessionError> {
        // Prefer TCP for close messages to maximize delivery reliability.
        // Only use UDP when TCP is no longer available.
        if self.tcp_alive && !self.tcp_write_interrupted {
            self.send_close_over_tcp(code).await
        } else {
            self.send_close_over_udp(code).await
        }
    }
}
