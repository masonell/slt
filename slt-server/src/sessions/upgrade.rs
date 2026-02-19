//! UDP upgrade control-message handlers.

use std::io;

use slt_core::proto::{
    Message, SwitchAckPayload, SwitchToUdpPayload, UdpReadyPayload, UpgradeProbeAckPayload,
    UpgradeProbePayload,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use super::{ClientSessionBase, SessionControl, UdpSocketIo, map_payload_error};
use crate::tun::TunDeviceIo;

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, U: UdpSocketIo>
    ClientSessionBase<T, S, U>
{
    pub(super) fn reset_udp_upgrade_state(&mut self) {
        self.udp_upgrade = super::UdpUpgradeState::default();
    }

    fn note_upgrade_id(&mut self, upgrade_id: u64, source: &'static str) -> bool {
        match self.udp_upgrade.upgrade_id {
            Some(existing) if existing == upgrade_id => true,
            Some(existing) => {
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
    ) -> io::Result<SessionControl> {
        let probe = UpgradeProbePayload::decode(payload).map_err(map_payload_error)?;
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
        self.send_udp_message(Message::UpgradeProbeAck { payload: &ack_buf })
            .await?;
        self.maybe_send_switch_to_udp().await?;
        Ok(SessionControl::Continue)
    }

    pub(super) async fn handle_udp_ready(&mut self, payload: &[u8]) -> io::Result<SessionControl> {
        let ready = UdpReadyPayload::decode(payload).map_err(map_payload_error)?;
        if !self.note_upgrade_id(ready.upgrade_id, "udp_ready") {
            return Ok(SessionControl::Continue);
        }

        self.udp_upgrade.ready_seen = true;
        self.maybe_send_switch_to_udp().await?;
        Ok(SessionControl::Continue)
    }

    pub(super) fn handle_switch_ack(&mut self, payload: &[u8]) -> io::Result<SessionControl> {
        let ack = SwitchAckPayload::decode(payload).map_err(map_payload_error)?;
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
        self.reset_udp_upgrade_state();
        Ok(SessionControl::Continue)
    }

    async fn maybe_send_switch_to_udp(&mut self) -> io::Result<()> {
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
