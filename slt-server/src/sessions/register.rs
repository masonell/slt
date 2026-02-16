//! `RegisterCid` handling for client sessions.

use std::io;
use std::net::SocketAddr;

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{
    Message, RegisterCidPayload, RegisterFailCode, RegisterFailPayload, RegisterOkPayload,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

use super::types::SessionControl;
use super::udp_io::UdpIo;
use super::{ClientSessionBase, UdpSocketIo, map_payload_error};
use crate::registry::CidInsertError;
use crate::tun::TunDeviceIo;

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, U: UdpSocketIo>
    ClientSessionBase<T, S, U>
{
    #[allow(clippy::too_many_lines)]
    pub(super) async fn handle_register_cid(
        &mut self,
        payload: &[u8],
    ) -> io::Result<SessionControl> {
        let Ok(register) = RegisterCidPayload::decode(payload) else {
            warn!(
                session_id = self.session_id,
                client_id = %self.client_id,
                active_transport = ?self.active_transport,
                reason = "decode_failed",
                "register_cid rejected"
            );
            self.send_register_fail(RegisterFailCode::InvalidCid)
                .await?;
            return Ok(SessionControl::Continue);
        };

        let Ok(keys) = UdpQspKeys::from_register(&register) else {
            warn!(
                session_id = self.session_id,
                client_id = %self.client_id,
                active_transport = ?self.active_transport,
                reason = "invalid_keys",
                "register_cid rejected"
            );
            self.send_register_fail(RegisterFailCode::InvalidKeys)
                .await?;
            return Ok(SessionControl::Continue);
        };

        if let Err(CidInsertError::PrefixCollision(_)) =
            self.registry
                .insert_cid(self.session_id, register.dcid.prefix(), self.tx.clone())
        {
            warn!(
                session_id = self.session_id,
                client_id = %self.client_id,
                active_transport = ?self.active_transport,
                dcid_prefix = ?register.dcid.prefix(),
                reason = "prefix_collision",
                "register_cid rejected"
            );
            self.send_register_fail(RegisterFailCode::InvalidCid)
                .await?;
            return Ok(SessionControl::Continue);
        }

        self.registry
            .remove_cids_for_session_except(self.session_id, register.dcid.prefix());

        // Create the UDP session with a placeholder peer address. The actual peer
        // is set by `handle_udp_claim` when the first UDP packet arrives.
        // This is safe because:
        // 1. We don't switch `active_transport` to UDP until after the first valid UDP claim
        // 2. `send_udp_message` is only called when `active_transport == UdpQsp`
        // 3. Therefore, we never send to this placeholder address
        let placeholder_peer = SocketAddr::from(([0, 0, 0, 0], 0));
        let io = UdpIo::new(self.udp_socket.clone(), placeholder_peer);
        let udp = slt_core::crypto::udp_qsp::QuicQspSession::new(
            io,
            register.scid,
            register.dcid,
            keys,
            register.pn_start,
            register.pn_start_rx,
            register.key_phase,
        );

        self.udp_session = Some(udp);
        // Do not switch transport until the first valid UDP claim arrives.
        // This ensures the session's peer address is set before we send any data.

        debug!(
            session_id = self.session_id,
            client_id = %self.client_id,
            active_transport = ?self.active_transport,
            dcid_prefix = ?register.dcid.prefix(),
            scid = ?register.scid,
            "register_cid accepted"
        );

        let ok = RegisterOkPayload {
            dcid: register.dcid,
        };
        let mut ok_buf = Vec::new();
        ok.encode(&mut ok_buf).map_err(map_payload_error)?;
        self.send_message(Message::RegisterOk { payload: &ok_buf })
            .await?;

        Ok(SessionControl::Continue)
    }

    async fn send_register_fail(&mut self, code: RegisterFailCode) -> io::Result<()> {
        let payload = RegisterFailPayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        self.send_message(Message::RegisterFail { payload: &buf })
            .await
    }
}
