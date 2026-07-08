//! UDP message handling for client sessions.

use fastrand;
use slt_core::crypto::udp_qsp::QspSessionError;
use slt_core::proto::{Message, PingPayload, PongPayload, decode_message};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, trace, warn};

use super::error::SessionError;
use super::types::SessionControl;
use super::{ActiveTransport, ClientSessionBase, UdpSessionIo};
use crate::quic::UdpClaim;
use crate::tun::TunDeviceIo;

/// Outcome of decrypting an inbound UDP-QSP packet in [`ClientSessionBase`]'s
/// `open_udp_packet`.
enum UdpOpenOutcome {
    /// Decrypted; plaintext written to the reused output buffer.
    Opened,
    /// Dropped (replay / too-old / crypto / other). Already counted and logged.
    Dropped,
    /// Too many decrypt failures; the UDP-QSP channel is dead. CID routes, the
    /// UDP session, and upgrade state have been cleared. The caller lands the
    /// session on TCP (and signals the peer) or closes if TCP is also gone.
    ChannelDead,
}

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, I: UdpSessionIo>
    ClientSessionBase<T, S, I>
{
    /// Processes a UDP packet claimed for this session.
    ///
    /// Handles the full UDP message pipeline:
    /// 1. Decrypts and validates the packet with UDP-QSP
    /// 2. Decodes the inner VPN message
    /// 3. Dispatches the message to the appropriate handler
    ///
    /// # Parameters
    ///
    /// * `claim` - The claimed UDP packet containing peer address and payload
    ///
    /// # Returns
    ///
    /// * `Ok(SessionControl::Continue)` if the packet was processed or dropped
    /// * `Ok(SessionControl::Close)` if the message requested session termination
    /// * `Err(SessionError)` if a non-recoverable error occurs
    pub(super) async fn handle_udp_claim(
        &mut self,
        claim: UdpClaim,
    ) -> Result<SessionControl, SessionError> {
        let peer = claim.peer;

        trace!(
            session_id = self.session_id,
            client_id = %self.client_id,
            peer = %peer,
            dcid_prefix = ?claim.dcid_prefix,
            "UDP claim received"
        );

        let mut opened = std::mem::take(&mut self.udp_opened_payload_buf);
        let control = match self.open_udp_packet(&claim.payload, &mut opened) {
            UdpOpenOutcome::Opened => {
                self.update_udp_peer(peer);
                match self.decode_udp_message(&opened) {
                    Ok(Some(message)) => self.dispatch_udp_message(message).await,
                    Ok(None) => Ok(SessionControl::Continue),
                    Err(err) => Err(err),
                }
            }
            UdpOpenOutcome::Dropped => Ok(SessionControl::Continue),
            UdpOpenOutcome::ChannelDead => self.complete_dead_channel_fallback().await,
        };
        self.udp_opened_payload_buf = opened;

        control
    }

    /// Decrypts and validates a UDP-QSP packet.
    ///
    /// Opens the packet using the session's UDP-QSP crypto state, handling
    /// various error conditions (replay, too old, dead channel, crypto failures).
    /// Tracks key phase transitions for metrics.
    ///
    /// # Parameters
    ///
    /// * `payload` - The encrypted UDP-QSP packet bytes
    /// * `out` - Reused output buffer for decrypted payload bytes
    ///
    /// # Returns
    ///
    /// * [`UdpOpenOutcome::Opened`] - The decrypted plaintext payload was written to `out`
    /// * [`UdpOpenOutcome::Dropped`] - The packet should be dropped (logged + counted)
    /// * [`UdpOpenOutcome::ChannelDead`] - The channel is dead; CID routes, UDP session,
    ///   and upgrade state have been cleared. The caller lands the session via
    ///   [`complete_dead_channel_fallback`].
    ///
    /// On replay/old/crypto errors, logs and returns [`UdpOpenOutcome::Dropped`].
    /// Tracks RX key phase transitions for metrics.
    fn open_udp_packet(&mut self, payload: &[u8], out: &mut Vec<u8>) -> UdpOpenOutcome {
        out.clear();
        let Some(session) = self.udp_session.as_mut() else {
            return UdpOpenOutcome::Dropped;
        };
        let rx_phase_before = session.rx_key_phase();

        match session.open_packet(payload) {
            Ok(opened) => {
                out.extend_from_slice(opened.payload);
            }
            Err(QspSessionError::Replay) => {
                self.metrics.inc_udp_qsp_decrypt_fail_replay();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "replay",
                    "UDP packet dropped: decrypt failure"
                );
                return UdpOpenOutcome::Dropped;
            }
            Err(QspSessionError::TooOld) => {
                self.metrics.inc_udp_qsp_decrypt_fail_too_old();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "too_old",
                    "UDP packet dropped: decrypt failure"
                );
                return UdpOpenOutcome::Dropped;
            }
            Err(QspSessionError::DeadChannel) => {
                self.metrics.inc_udp_qsp_dead_channel();
                warn!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    "UDP-QSP channel marked dead; clearing udp state"
                );
                self.registry.remove_cids_for_session(self.session_id);
                self.udp_session = None;
                self.reset_udp_upgrade_state();
                return UdpOpenOutcome::ChannelDead;
            }
            Err(QspSessionError::Crypto(err)) => {
                self.metrics.inc_udp_qsp_decrypt_fail_crypto();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "crypto",
                    error = ?err,
                    "UDP packet dropped: decrypt failure"
                );
                return UdpOpenOutcome::Dropped;
            }
            Err(err) => {
                self.metrics.inc_udp_qsp_decrypt_fail_other();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "other",
                    error = ?err,
                    "UDP packet dropped: decrypt failure"
                );
                return UdpOpenOutcome::Dropped;
            }
        }

        // Check for key phase transition after the match to avoid borrow conflicts.
        if let Some(session) = self.udp_session.as_ref()
            && session.rx_key_phase() != rx_phase_before
        {
            self.metrics.inc_udp_qsp_rx_key_phase_transition();
            info!(
                session_id = self.session_id,
                client_id = %self.client_id,
                key_phase = session.rx_key_phase(),
                "UDP-QSP RX key phase transitioned"
            );
        }

        UdpOpenOutcome::Opened
    }

    /// Land the session after [`open_udp_packet`] reported the UDP-QSP channel dead.
    ///
    /// With a live TCP path this switches to TCP and sends an immediate ping. A TCP
    /// ping arriving while the peer is still on UDP-QSP flips it to TCP
    /// (`switch_to_tcp_on_server_traffic`, reason `ServerInitiated`) within ~RTT,
    /// rather than waiting up to one ping interval for the next scheduled ping to
    /// carry the implicit signal.
    ///
    /// With TCP already closed there is no fallback path and no way to notify the
    /// peer — a `Close` over the dead UDP-QSP channel would not decrypt, and TCP is
    /// gone — so the session tears itself down. The peer recovers via its own idle
    /// timeout / reconnect.
    async fn complete_dead_channel_fallback(&mut self) -> Result<SessionControl, SessionError> {
        if self.tcp_alive {
            self.set_active_transport(ActiveTransport::Tcp);
            let nonce = fastrand::u64(..);
            let ping = PingPayload { nonce };
            let mut buf = Vec::with_capacity(8);
            ping.encode(&mut buf);
            debug!(
                session_id = self.session_id,
                client_id = %self.client_id,
                "sent immediate tcp ping after udp-qsp dead-channel fallback"
            );
            self.send_tcp_message(Message::Ping { payload: &buf })
                .await?;
            return Ok(SessionControl::Continue);
        }
        self.metrics.inc_disconnect_close();
        info!(
            session_id = self.session_id,
            client_id = %self.client_id,
            reason = "udp_dead_channel_no_tcp",
            "session disconnect; udp-qsp channel dead and tcp closed"
        );
        Ok(SessionControl::Close)
    }

    /// Decodes a VPN message from the decrypted UDP payload.
    ///
    /// Parses the first message and ignores trailing bytes.
    ///
    /// UDP-QSP payloads may carry trailing bytes after the first frame
    /// (for example, padding added to satisfy header-protection sampling rules).
    /// Per protocol, receivers decode the first frame and ignore the rest.
    ///
    /// # Parameters
    ///
    /// * `payload` - The decrypted plaintext payload from UDP-QSP
    ///
    /// # Returns
    ///
    /// * `Ok(Some(message))` - A valid message was decoded
    /// * `Ok(None)` - The payload was empty or incomplete
    /// * `Err(SessionError)` - The message was malformed
    fn decode_udp_message<'a>(
        &self,
        payload: &'a [u8],
    ) -> Result<Option<Message<'a>>, SessionError> {
        let decoded = decode_message(payload, self.limits)?;
        let Some((message, _consumed)) = decoded else {
            return Ok(None);
        };
        Ok(Some(message))
    }

    /// Dispatches a decoded UDP message to its appropriate handler.
    ///
    /// Routes the message based on type:
    /// - Ping: Responds with Pong
    /// - Pong: Logs and continues
    /// - Data: Forwards to TUN device if valid
    /// - `UpgradeProbe`: Sends UDP probe ack and may trigger TCP switch commit
    /// - Close: Initiates session shutdown
    /// - `RegisterCid`: Fails as a protocol violation
    /// - Other control messages: Silently ignored
    ///
    /// # Parameters
    ///
    /// * `message` - The decoded message to dispatch
    ///
    /// # Returns
    ///
    /// * `Ok(SessionControl::Continue)` for most messages
    /// * `Ok(SessionControl::Close)` if the message requested termination
    /// * `Err(SessionError)` if message handling fails
    async fn dispatch_udp_message(
        &mut self,
        message: Message<'_>,
    ) -> Result<SessionControl, SessionError> {
        match message {
            Message::Ping { payload } => {
                let payload = Self::pong_payload_for_ping(payload)?;
                self.send_udp_message_and_flush(Message::Pong { payload: &payload })
                    .await?;
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong_in = PongPayload::decode(payload)?;
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    nonce = pong_in.nonce,
                    "received udp pong"
                );
                Ok(SessionControl::Continue)
            }
            Message::Data { packet } => {
                if self.active_transport != ActiveTransport::UdpQsp {
                    trace!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        "UDP data dropped: not active transport"
                    );
                    return Ok(SessionControl::Continue);
                }
                if self.should_forward_packet_to_tun(packet) {
                    self.tun.send(packet).await?;
                }
                Ok(SessionControl::Continue)
            }
            Message::UpgradeProbe { payload } => self.handle_upgrade_probe(payload).await,
            Message::Close { .. } => Ok(self.peer_close_control(false)),
            Message::RegisterCid { .. } => Err(SessionError::ProtocolViolation),
            Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. }
            | Message::UpgradeProbeAck { .. }
            | Message::UdpReady { .. }
            | Message::SwitchToUdp { .. }
            | Message::SwitchAck { .. } => Ok(SessionControl::Continue),
        }
    }
}
