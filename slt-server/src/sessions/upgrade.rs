//! UDP upgrade control-message handlers.

use slt_core::proto::{
    Message, SwitchAckPayload, SwitchToUdpPayload, UdpReadyPayload, UpgradeProbeAckPayload,
    UpgradeProbePayload,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use super::error::SessionError;
use super::{ClientSessionBase, SessionControl, UdpFailureRecovery, UdpSessionIo};
use crate::tun::TunDeviceIo;

const MAX_STALE_UPGRADE_IDS: usize = 16;

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, I: UdpSessionIo>
    ClientSessionBase<T, S, I>
{
    pub(super) fn reset_udp_upgrade_state(&mut self) {
        self.udp_upgrade = super::UdpUpgradeState::default();
    }

    const fn reset_udp_upgrade_attempt_preserving_history(&mut self) {
        self.udp_upgrade.upgrade_id = None;
        self.udp_upgrade.probe_seen = false;
        self.udp_upgrade.ready_seen = false;
        self.udp_upgrade.switch_to_udp_sent = false;
    }

    fn remember_stale_upgrade_id(&mut self, upgrade_id: u64) {
        if self.udp_upgrade.stale_upgrade_ids.contains(&upgrade_id) {
            return;
        }
        if self.udp_upgrade.stale_upgrade_ids.len() >= MAX_STALE_UPGRADE_IDS {
            let _ = self.udp_upgrade.stale_upgrade_ids.pop_front();
        }
        self.udp_upgrade.stale_upgrade_ids.push_back(upgrade_id);
    }

    fn note_upgrade_id(&mut self, upgrade_id: u64, source: &'static str) -> bool {
        if source == "upgrade_probe" && self.udp_upgrade.stale_upgrade_ids.contains(&upgrade_id) {
            debug!(
                session_id = self.session_id,
                client_id = %self.client_id,
                upgrade_id,
                "ignoring stale udp upgrade probe id from superseded attempt"
            );
            return false;
        }

        match self.udp_upgrade.upgrade_id {
            Some(existing) if existing == upgrade_id => true,
            Some(existing) => {
                if source == "upgrade_probe" {
                    warn!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        previous_upgrade_id = existing,
                        received_upgrade_id = upgrade_id,
                        probe_seen = self.udp_upgrade.probe_seen,
                        ready_seen = self.udp_upgrade.ready_seen,
                        switch_to_udp_sent = self.udp_upgrade.switch_to_udp_sent,
                        "observed new udp upgrade probe id; superseding current upgrade attempt"
                    );
                    self.remember_stale_upgrade_id(existing);
                    self.reset_udp_upgrade_attempt_preserving_history();
                    self.udp_upgrade.upgrade_id = Some(upgrade_id);
                    return true;
                }
                warn!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    expected_upgrade_id = existing,
                    received_upgrade_id = upgrade_id,
                    source,
                    "ignoring mismatched udp upgrade id"
                );
                false
            }
            None => {
                self.udp_upgrade.upgrade_id = Some(upgrade_id);
                true
            }
        }
    }

    pub(super) async fn handle_upgrade_probe(
        &mut self,
        payload: &[u8],
    ) -> Result<SessionControl, SessionError> {
        let probe = UpgradeProbePayload::decode(payload)?;
        if !self.note_upgrade_id(probe.upgrade_id, "upgrade_probe") {
            return Ok(SessionControl::Continue);
        }

        self.udp_upgrade.probe_seen = true;

        let ack = UpgradeProbeAckPayload {
            upgrade_id: probe.upgrade_id,
            nonce: probe.nonce,
        };
        let mut ack_buf = Vec::with_capacity(16);
        ack.encode(&mut ack_buf);
        self.send_udp_message_and_flush(
            Message::UpgradeProbeAck { payload: &ack_buf },
            UdpFailureRecovery::RetireOnly,
        )
        .await?;
        self.maybe_send_switch_to_udp().await?;
        Ok(SessionControl::Continue)
    }

    pub(super) async fn handle_udp_ready(
        &mut self,
        payload: &[u8],
    ) -> Result<SessionControl, SessionError> {
        let ready = UdpReadyPayload::decode(payload)?;
        if !self.note_upgrade_id(ready.upgrade_id, "udp_ready") {
            return Ok(SessionControl::Continue);
        }

        self.udp_upgrade.ready_seen = true;
        self.maybe_send_switch_to_udp().await?;
        Ok(SessionControl::Continue)
    }

    pub(super) fn handle_switch_ack(
        &mut self,
        payload: &[u8],
    ) -> Result<SessionControl, SessionError> {
        let ack = SwitchAckPayload::decode(payload)?;
        let Some(expected_upgrade_id) = self.udp_upgrade.upgrade_id else {
            debug!(
                session_id = self.session_id,
                client_id = %self.client_id,
                upgrade_id = ack.upgrade_id,
                "ignoring switch ack without upgrade state"
            );
            return Ok(SessionControl::Continue);
        };
        if expected_upgrade_id != ack.upgrade_id {
            warn!(
                session_id = self.session_id,
                client_id = %self.client_id,
                expected_upgrade_id,
                received_upgrade_id = ack.upgrade_id,
                "ignoring mismatched switch ack upgrade id"
            );
            return Ok(SessionControl::Continue);
        }
        if !self.udp_upgrade.switch_to_udp_sent {
            debug!(
                session_id = self.session_id,
                client_id = %self.client_id,
                upgrade_id = ack.upgrade_id,
                "ignoring switch ack before switch commit"
            );
            return Ok(SessionControl::Continue);
        }

        self.set_active_transport(super::ActiveTransport::UdpQsp);
        info!(
            session_id = self.session_id,
            client_id = %self.client_id,
            upgrade_id = ack.upgrade_id,
            "udp upgrade committed"
        );
        self.remember_stale_upgrade_id(ack.upgrade_id);
        self.reset_udp_upgrade_attempt_preserving_history();
        Ok(SessionControl::Continue)
    }

    async fn maybe_send_switch_to_udp(&mut self) -> Result<(), SessionError> {
        if self.udp_upgrade.switch_to_udp_sent
            || !self.udp_upgrade.probe_seen
            || !self.udp_upgrade.ready_seen
        {
            return Ok(());
        }
        let Some(upgrade_id) = self.udp_upgrade.upgrade_id else {
            return Ok(());
        };

        let payload = SwitchToUdpPayload { upgrade_id };
        let mut buf = Vec::with_capacity(8);
        payload.encode(&mut buf);
        self.send_tcp_message(Message::SwitchToUdp { payload: &buf })
            .await?;
        self.udp_upgrade.switch_to_udp_sent = true;
        info!(
            session_id = self.session_id,
            client_id = %self.client_id,
            upgrade_id,
            "sent switch_to_udp commit"
        );
        Ok(())
    }
}
