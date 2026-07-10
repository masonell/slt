//! `RegisterCid` handling for client sessions.

use std::net::SocketAddr;

use slt_core::crypto::udp_qsp::{QspCryptoError, UdpQspKeys};
use slt_core::proto::{
    Message, PayloadError, RegisterCidPayload, RegisterFailCode, RegisterFailPayload,
    RegisterOkPayload,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

use super::error::SessionError;
use super::types::SessionControl;
use super::{ClientSessionBase, UdpSessionIo};
use crate::registry::CidInsertError;
use crate::tun::TunDeviceIo;

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, I: UdpSessionIo>
    ClientSessionBase<T, S, I>
{
    /// Handles an incoming `RegisterCid` message from the client.
    ///
    /// This message registers the client's UDP-QSP connection IDs (DCID/SCID) and
    /// cryptographic keys, enabling the session to switch to UDP transport. The function:
    ///
    /// 1. Decodes and validates the registration payload
    /// 2. Extracts UDP-QSP keys from the payload
    /// 3. Registers the DCID prefix in the session registry for packet routing
    /// 4. Creates a new UDP-QSP session with the provided parameters
    /// 5. Sends a `RegisterOk` response on success
    ///
    /// # Parameters
    ///
    /// * `payload` - The encoded `RegisterCidPayload` from the client message
    ///
    /// # Returns
    ///
    /// * `Ok(SessionControl::Continue)` if registration succeeds or fails gracefully
    /// * `Err(SessionError)` if sending the response fails
    ///
    /// # Behavior
    ///
    /// - Sends `RegisterFail` with `InvalidCid` if the payload is malformed
    /// - Sends `RegisterFail` with `InvalidKeys` if key derivation fails
    /// - Sends `RegisterFail` with `InvalidCid` if the session is stale or the
    ///   DCID prefix collides
    /// - Resets upgrade-tracking state and waits for explicit upgrade commit
    #[allow(clippy::too_many_lines)]
    pub(super) async fn handle_register_cid(
        &mut self,
        payload: &[u8],
    ) -> Result<SessionControl, SessionError> {
        let register = match RegisterCidPayload::decode(payload) {
            Ok(register) => register,
            Err(err) => {
                let code = register_decode_fail_code(&err);
                warn!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    active_transport = ?self.active_transport,
                    reason = "decode_failed",
                    error = %err,
                    code = ?code,
                    "register_cid rejected"
                );
                self.send_register_fail(code).await?;
                return Ok(SessionControl::Continue);
            }
        };

        if !self.udp_qsp_config.allows(register.cipher) {
            warn!(
                session_id = self.session_id,
                client_id = %self.client_id,
                active_transport = ?self.active_transport,
                cipher = ?register.cipher,
                reason = "cipher_disallowed",
                "register_cid rejected"
            );
            self.send_register_fail(RegisterFailCode::InvalidCipher)
                .await?;
            return Ok(SessionControl::Continue);
        }

        let keys = match UdpQspKeys::from_register(&register) {
            Ok(keys) => keys,
            Err(err) => {
                let code = crypto_fail_code(err);
                warn!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    active_transport = ?self.active_transport,
                    cipher = ?register.cipher,
                    reason = "invalid_keys",
                    error = %err,
                    code = ?code,
                    "register_cid rejected"
                );
                self.send_register_fail(code).await?;
                return Ok(SessionControl::Continue);
            }
        };

        let Some(dcid_prefix) = register.client_to_server_cid.prefix().ok() else {
            warn!(
                session_id = self.session_id,
                client_id = %self.client_id,
                active_transport = ?self.active_transport,
                cid_len = register.client_to_server_cid.len(),
                reason = "cid_too_short_for_prefix",
                "register_cid rejected"
            );
            self.send_register_fail(RegisterFailCode::InvalidCid)
                .await?;
            return Ok(SessionControl::Continue);
        };

        match self.registry.insert_cid(
            self.client_id,
            self.session_id,
            dcid_prefix,
            self.tx.clone(),
        ) {
            Ok(()) => {}
            Err(CidInsertError::PrefixCollision(_)) => {
                warn!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    active_transport = ?self.active_transport,
                    dcid_prefix = ?dcid_prefix,
                    reason = "prefix_collision",
                    "register_cid rejected"
                );
                self.send_register_fail(RegisterFailCode::InvalidCid)
                    .await?;
                return Ok(SessionControl::Continue);
            }
            Err(CidInsertError::StaleSession {
                active_session_id, ..
            }) => {
                warn!(
                    session_id = self.session_id,
                    active_session_id = ?active_session_id,
                    client_id = %self.client_id,
                    active_transport = ?self.active_transport,
                    dcid_prefix = ?dcid_prefix,
                    reason = "stale_session",
                    "register_cid rejected"
                );
                self.send_register_fail(RegisterFailCode::InvalidCid)
                    .await?;
                return Ok(SessionControl::Continue);
            }
        }

        self.registry
            .remove_cids_for_session_except(self.session_id, dcid_prefix);

        // Create the UDP session with a placeholder peer address. The actual peer
        // is set by `handle_udp_claim` when the first UDP packet arrives.
        // This is safe because:
        // 1. We keep `active_transport` on TCP until `SwitchAck` commits the upgrade
        // 2. `send_udp_message` is only called when `active_transport == UdpQsp`
        // 3. Therefore, we never send to this placeholder address pre-commit
        let placeholder_peer = SocketAddr::from(([0, 0, 0, 0], 0));
        let io = self
            .udp_io_factory
            .create(placeholder_peer)
            .map_err(|source| SessionError::Connection { source })?;
        let udp = slt_core::crypto::udp_qsp::QuicQspSession::new(
            io,
            register.client_to_server_cid,
            register.server_to_client_cid,
            keys,
            register.pn_start,
            register.pn_start_rx,
            register.key_phase,
        );

        self.udp_session = Some(udp);
        self.last_authenticated_udp_activity = None;
        self.reset_udp_upgrade_state();
        // Keep TCP preferred until explicit switch commit.

        debug!(
            session_id = self.session_id,
            client_id = %self.client_id,
            active_transport = ?self.active_transport,
            cipher = ?register.cipher,
            dcid_prefix = ?dcid_prefix,
            scid = ?register.server_to_client_cid,
            "register_cid accepted"
        );

        let ok = RegisterOkPayload {
            client_to_server_cid: register.client_to_server_cid,
        };
        let mut ok_buf = Vec::new();
        ok.encode(&mut ok_buf)?;
        self.send_message(Message::RegisterOk { payload: &ok_buf })
            .await?;

        Ok(SessionControl::Continue)
    }

    /// Sends a `RegisterFail` message to the client.
    ///
    /// Encodes the failure code into a payload and sends it via the currently
    /// preferred transport (TCP or UDP-QSP).
    ///
    /// # Parameters
    ///
    /// * `code` - The specific failure reason to report to the client
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the message was sent successfully
    /// * `Err(SessionError)` if sending fails
    async fn send_register_fail(&mut self, code: RegisterFailCode) -> Result<(), SessionError> {
        let payload = RegisterFailPayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        self.send_message(Message::RegisterFail { payload: &buf })
            .await
    }
}

const fn register_decode_fail_code(err: &PayloadError) -> RegisterFailCode {
    match err {
        PayloadError::InvalidCipher(_) => RegisterFailCode::InvalidCipher,
        PayloadError::LengthMismatch { .. } | PayloadError::InvalidKeyPhase(_) => {
            RegisterFailCode::InvalidKeys
        }
        PayloadError::LengthTooShort { .. }
        | PayloadError::InvalidClientToServerCidLen(_)
        | PayloadError::InvalidServerToClientCidLen(_)
        | PayloadError::InvalidAuthFailCode(_)
        | PayloadError::InvalidRegisterFailCode(_)
        | PayloadError::InvalidCloseCode(_) => RegisterFailCode::InvalidCid,
    }
}

const fn crypto_fail_code(err: QspCryptoError) -> RegisterFailCode {
    match err {
        QspCryptoError::UnsupportedCipher => RegisterFailCode::InvalidCipher,
        QspCryptoError::PacketTooShort
        | QspCryptoError::InvalidHeader
        | QspCryptoError::InvalidPacketNumber
        | QspCryptoError::CryptoFail
        | QspCryptoError::InvalidCid => RegisterFailCode::InvalidKeys,
    }
}
