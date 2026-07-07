use std::net::Ipv4Addr;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::types::{Cid, ClientId, MAX_DCID_LEN};
/// Length of the authentication challenge in bytes.
pub const AUTH_CHALLENGE_LEN: usize = 32;
/// Length of the Ed25519 signature in bytes.
pub const AUTH_SIGNATURE_LEN: usize = 64;
/// Length of the header protection key in bytes.
pub const HP_KEY_LEN: usize = 16;
/// Length of the AEAD key in bytes.
pub const AEAD_KEY_LEN: usize = 16;
/// Length of ChaCha20-Poly1305 key material in bytes.
pub const CHACHA20_POLY1305_KEY_LEN: usize = 32;
/// Maximum header protection key length in bytes.
pub const MAX_HP_KEY_LEN: usize = CHACHA20_POLY1305_KEY_LEN;
/// Maximum AEAD key length in bytes.
pub const MAX_AEAD_KEY_LEN: usize = CHACHA20_POLY1305_KEY_LEN;
/// Length of the AEAD IV in bytes.
pub const AEAD_IV_LEN: usize = 12;
/// Length of a UDP-QSP directional traffic secret in bytes.
pub const UDP_QSP_TRAFFIC_SECRET_LEN: usize = 32;
/// Length of the AUTH payload in bytes.
pub const AUTH_PAYLOAD_LEN: usize = 16 + 4 + AUTH_CHALLENGE_LEN + AUTH_SIGNATURE_LEN;
/// Length of the PING/PONG payload in bytes.
pub const PING_PAYLOAD_LEN: usize = 8;
/// Length of upgrade identifier payloads in bytes.
pub const UPGRADE_ID_PAYLOAD_LEN: usize = 8;
/// Length of UDP upgrade probe/ack payloads in bytes.
pub const UPGRADE_PROBE_PAYLOAD_LEN: usize = 16;
/// Length of the CLOSE payload in bytes.
pub const CLOSE_PAYLOAD_LEN: usize = 1;

/// Maximum encoded length of any control (non-DATA) frame.
///
/// Currently bounded by `REGISTER_CID`. When adding new message types or
/// changing payload layouts, verify this value still exceeds all control
/// payloads. See `protocol.md` for wire format specification.
pub const MAX_CONTROL_FRAME_LEN: usize =
    1 + MAX_DCID_LEN + 1 + MAX_DCID_LEN + 1 + (UDP_QSP_TRAFFIC_SECRET_LEN * 2) + 8 + 8 + 1;

/// Cipher identifiers for UDP-QSP payload protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum CipherSuite {
    /// AES-128-GCM.
    Aes128Gcm = 0x01,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305 = 0x02,
}

impl CipherSuite {
    /// Length of header protection key material for this cipher suite.
    #[must_use]
    pub const fn hp_key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => HP_KEY_LEN,
            Self::ChaCha20Poly1305 => CHACHA20_POLY1305_KEY_LEN,
        }
    }

    /// Length of AEAD key material for this cipher suite.
    #[must_use]
    pub const fn aead_key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => AEAD_KEY_LEN,
            Self::ChaCha20Poly1305 => CHACHA20_POLY1305_KEY_LEN,
        }
    }

    /// Length of AEAD IV material for this cipher suite.
    #[must_use]
    pub const fn iv_len(self) -> usize {
        AEAD_IV_LEN
    }
}

/// Authentication failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum AuthFailCode {
    /// Unspecified failure.
    Unknown = 0x00,
    /// Client is not in the allowlist.
    UnknownClient = 0x01,
    /// Client is disabled in the config.
    Disabled = 0x02,
    /// Signature verification failed.
    BadSignature = 0x03,
    /// Assigned IP does not match config.
    IpMismatch = 0x04,
    /// Challenge is expired or invalid.
    ChallengeInvalid = 0x05,
}

/// Register-CID failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum RegisterFailCode {
    /// Unspecified failure.
    Unknown = 0x00,
    /// Client is not authenticated.
    NotAuthenticated = 0x01,
    /// Unsupported or invalid cipher suite.
    InvalidCipher = 0x02,
    /// Invalid CID length or format.
    InvalidCid = 0x03,
    /// Invalid key material.
    InvalidKeys = 0x04,
}

/// Close reasons for terminating a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum CloseCode {
    /// Normal shutdown.
    Normal = 0x00,
    /// Authentication timeout.
    AuthTimeout = 0x01,
    /// Idle timeout.
    IdleTimeout = 0x02,
    /// Protocol error.
    ProtocolError = 0x03,
    /// Server shutdown or restart.
    ServerRestart = 0x04,
}

/// Authentication message payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthPayload {
    /// Client identifier.
    pub client_id: ClientId,
    /// Assigned IPv4 address.
    pub assigned_ipv4: Ipv4Addr,
    /// Server-provided challenge bytes.
    pub challenge: [u8; AUTH_CHALLENGE_LEN],
    /// Ed25519 signature over the challenge and context.
    pub signature: [u8; AUTH_SIGNATURE_LEN],
}

impl AuthPayload {
    /// Decode an AUTH payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` if the payload length is not
    /// exactly `AUTH_PAYLOAD_LEN` (116 bytes).
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != AUTH_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: AUTH_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }

        let mut client_id_bytes = [0u8; 16];
        client_id_bytes.copy_from_slice(&payload[..16]);
        let client_id = ClientId(client_id_bytes);

        let assigned_ipv4 = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);

        let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
        challenge.copy_from_slice(&payload[20..20 + AUTH_CHALLENGE_LEN]);

        let mut signature = [0u8; AUTH_SIGNATURE_LEN];
        signature.copy_from_slice(
            &payload[20 + AUTH_CHALLENGE_LEN..20 + AUTH_CHALLENGE_LEN + AUTH_SIGNATURE_LEN],
        );

        Ok(Self {
            client_id,
            assigned_ipv4,
            challenge,
            signature,
        })
    }

    /// Encode an AUTH payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(AUTH_PAYLOAD_LEN);
        out.extend_from_slice(self.client_id.as_bytes());
        out.extend_from_slice(&self.assigned_ipv4.octets());
        out.extend_from_slice(&self.challenge);
        out.extend_from_slice(&self.signature);
    }
}

/// `AUTH_OK` payload (currently empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthOkPayload;

impl AuthOkPayload {
    /// Decode an `AUTH_OK` payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` if the payload is not empty.
    pub const fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if !payload.is_empty() {
            return Err(PayloadError::LengthMismatch {
                expected: 0,
                actual: payload.len(),
            });
        }
        Ok(Self)
    }

    /// Encode an `AUTH_OK` payload.
    pub const fn encode(&self, _out: &mut Vec<u8>) {}
}

/// `AUTH_FAIL` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthFailPayload {
    /// Failure reason code.
    pub code: AuthFailCode,
}

impl AuthFailPayload {
    /// Decode an `AUTH_FAIL` payload.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload length is not exactly 1
    /// - The failure code byte is invalid
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != 1 {
            return Err(PayloadError::LengthMismatch {
                expected: 1,
                actual: payload.len(),
            });
        }
        let code = AuthFailCode::try_from(payload[0])
            .map_err(|_| PayloadError::InvalidAuthFailCode(payload[0]))?;
        Ok(Self { code })
    }

    /// Encode an `AUTH_FAIL` payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(self.code));
    }
}

/// `REGISTER_CID` payload.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisterCidPayload {
    /// CID for client->server packets (must be exactly `MAX_DCID_LEN` bytes).
    pub client_to_server_cid: Cid,
    /// CID for server->client packets (can be 0..=`MAX_DCID_LEN` bytes).
    pub server_to_client_cid: Cid,
    /// Cipher suite for packet protection.
    pub cipher: CipherSuite,
    /// Traffic secret for packets sent by the server.
    pub secret_tx: [u8; UDP_QSP_TRAFFIC_SECRET_LEN],
    /// Traffic secret for packets received by the server.
    pub secret_rx: [u8; UDP_QSP_TRAFFIC_SECRET_LEN],
    /// Initial packet number for the server->client direction.
    pub pn_start: u64,
    /// Initial packet number expected from the client.
    pub pn_start_rx: u64,
    /// Initial key phase (false = 0, true = 1).
    pub key_phase: bool,
}

impl RegisterCidPayload {
    const fn encoded_len_for(
        c2s_cid_len: usize,
        s2c_cid_len: usize,
        _cipher: CipherSuite,
    ) -> usize {
        1 + c2s_cid_len + 1 + s2c_cid_len + 1 + (UDP_QSP_TRAFFIC_SECRET_LEN * 2) + 8 + 8 + 1
    }

    fn read_secret(payload: &[u8], offset: &mut usize) -> [u8; UDP_QSP_TRAFFIC_SECRET_LEN] {
        let mut out = [0u8; UDP_QSP_TRAFFIC_SECRET_LEN];
        out.copy_from_slice(&payload[*offset..*offset + UDP_QSP_TRAFFIC_SECRET_LEN]);
        *offset += UDP_QSP_TRAFFIC_SECRET_LEN;
        out
    }

    fn read_u64(
        payload: &[u8],
        offset: &mut usize,
        expected_len: usize,
    ) -> Result<u64, PayloadError> {
        let value = u64::from_be_bytes(payload[*offset..*offset + 8].try_into().map_err(|_| {
            PayloadError::LengthMismatch {
                expected: expected_len,
                actual: payload.len(),
            }
        })?);
        *offset += 8;
        Ok(value)
    }

    /// Decode a `REGISTER_CID` payload.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload is too short
    /// - The `client_to_server_cid` length is not exactly `MAX_DCID_LEN`
    /// - The `server_to_client_cid` length exceeds `MAX_DCID_LEN`
    /// - The payload length doesn't match the expected length
    /// - The cipher suite is invalid
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.is_empty() {
            return Err(PayloadError::LengthTooShort {
                min: 1,
                actual: payload.len(),
            });
        }
        let c2s_cid_len = payload[0] as usize;
        if c2s_cid_len != MAX_DCID_LEN {
            return Err(PayloadError::InvalidClientToServerCidLen(c2s_cid_len));
        }
        let s2c_cid_len_offset = 1 + c2s_cid_len;
        if payload.len() < s2c_cid_len_offset + 1 {
            return Err(PayloadError::LengthTooShort {
                min: s2c_cid_len_offset + 1,
                actual: payload.len(),
            });
        }

        let s2c_cid_len = payload[s2c_cid_len_offset] as usize;
        if s2c_cid_len > MAX_DCID_LEN {
            return Err(PayloadError::InvalidServerToClientCidLen(s2c_cid_len));
        }
        let cipher_offset = s2c_cid_len_offset + 1 + s2c_cid_len;
        if payload.len() < cipher_offset + 1 {
            return Err(PayloadError::LengthTooShort {
                min: cipher_offset + 1,
                actual: payload.len(),
            });
        }

        let cipher = CipherSuite::try_from(payload[cipher_offset])
            .map_err(|_| PayloadError::InvalidCipher(payload[cipher_offset]))?;
        let expected_len = Self::encoded_len_for(c2s_cid_len, s2c_cid_len, cipher);
        if payload.len() != expected_len {
            return Err(PayloadError::LengthMismatch {
                expected: expected_len,
                actual: payload.len(),
            });
        }
        let mut offset = 1;
        let client_to_server_cid = Cid::try_from(&payload[offset..offset + c2s_cid_len])
            .map_err(|_| PayloadError::InvalidClientToServerCidLen(c2s_cid_len))?;
        offset += c2s_cid_len;
        offset += 1; // s2c_cid_len
        let server_to_client_cid = Cid::try_from(&payload[offset..offset + s2c_cid_len])
            .map_err(|_| PayloadError::InvalidServerToClientCidLen(s2c_cid_len))?;
        offset += s2c_cid_len;
        offset += 1;
        let secret_tx = Self::read_secret(payload, &mut offset);
        let secret_rx = Self::read_secret(payload, &mut offset);
        let pn_start = Self::read_u64(payload, &mut offset, expected_len)?;
        let pn_start_rx = Self::read_u64(payload, &mut offset, expected_len)?;
        let key_phase = match payload[offset] {
            0 => false,
            1 => true,
            other => return Err(PayloadError::InvalidKeyPhase(other)),
        };

        Ok(Self {
            client_to_server_cid,
            server_to_client_cid,
            cipher,
            secret_tx,
            secret_rx,
            pn_start,
            pn_start_rx,
            key_phase,
        })
    }

    /// Encode a `REGISTER_CID` payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::InvalidClientToServerCidLen` if the
    /// `client_to_server_cid` length is not exactly `MAX_DCID_LEN`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), PayloadError> {
        if self.client_to_server_cid.len() != MAX_DCID_LEN {
            return Err(PayloadError::InvalidClientToServerCidLen(
                self.client_to_server_cid.len(),
            ));
        }
        let expected_len = self.encoded_len();
        out.reserve(expected_len);
        #[allow(clippy::cast_possible_truncation)]
        let c2s_len = self.client_to_server_cid.len() as u8; // bounded by MAX_DCID_LEN (<= 20)
        out.push(c2s_len);
        out.extend_from_slice(self.client_to_server_cid.as_slice());
        #[allow(clippy::cast_possible_truncation)]
        let s2c_len = self.server_to_client_cid.len() as u8; // bounded by MAX_DCID_LEN (<= 20)
        out.push(s2c_len);
        out.extend_from_slice(self.server_to_client_cid.as_slice());
        out.push(u8::from(self.cipher));
        out.extend_from_slice(&self.secret_tx);
        out.extend_from_slice(&self.secret_rx);
        out.extend_from_slice(&self.pn_start.to_be_bytes());
        out.extend_from_slice(&self.pn_start_rx.to_be_bytes());
        out.push(u8::from(self.key_phase));
        Ok(())
    }

    /// Encoded payload length for this registration.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        Self::encoded_len_for(
            self.client_to_server_cid.len(),
            self.server_to_client_cid.len(),
            self.cipher,
        )
    }
}

/// `REGISTER_OK` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterOkPayload {
    /// The acknowledged CID (must be exactly `MAX_DCID_LEN` bytes).
    pub client_to_server_cid: Cid,
}

impl RegisterOkPayload {
    /// Decode a `REGISTER_OK` payload.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload is too short
    /// - The CID length is not exactly `MAX_DCID_LEN`
    /// - The payload length doesn't match the expected length
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.is_empty() {
            return Err(PayloadError::LengthTooShort {
                min: 1,
                actual: payload.len(),
            });
        }

        let cid_len = payload[0] as usize;
        if cid_len != MAX_DCID_LEN {
            return Err(PayloadError::InvalidClientToServerCidLen(cid_len));
        }

        let expected_len = 1 + cid_len;
        if payload.len() != expected_len {
            return Err(PayloadError::LengthMismatch {
                expected: expected_len,
                actual: payload.len(),
            });
        }

        Ok(Self {
            client_to_server_cid: Cid::try_from(&payload[1..=cid_len])
                .map_err(|_| PayloadError::InvalidClientToServerCidLen(cid_len))?,
        })
    }

    /// Encode a `REGISTER_OK` payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::InvalidClientToServerCidLen` if the CID length
    /// is not exactly `MAX_DCID_LEN`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), PayloadError> {
        if self.client_to_server_cid.len() != MAX_DCID_LEN {
            return Err(PayloadError::InvalidClientToServerCidLen(
                self.client_to_server_cid.len(),
            ));
        }
        out.reserve(1 + self.client_to_server_cid.len());
        #[allow(clippy::cast_possible_truncation)]
        let cid_len = self.client_to_server_cid.len() as u8; // bounded by MAX_DCID_LEN (<= 20)
        out.push(cid_len);
        out.extend_from_slice(self.client_to_server_cid.as_slice());
        Ok(())
    }
}

/// `REGISTER_FAIL` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterFailPayload {
    /// Failure reason code.
    pub code: RegisterFailCode,
}

impl RegisterFailPayload {
    /// Decode a `REGISTER_FAIL` payload.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload length is not exactly 1
    /// - The failure code byte is invalid
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != 1 {
            return Err(PayloadError::LengthMismatch {
                expected: 1,
                actual: payload.len(),
            });
        }
        let code = RegisterFailCode::try_from(payload[0])
            .map_err(|_| PayloadError::InvalidRegisterFailCode(payload[0]))?;
        Ok(Self { code })
    }

    /// Encode a `REGISTER_FAIL` payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(self.code));
    }
}

/// UDP upgrade probe payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeProbePayload {
    /// Unique identifier for this upgrade attempt.
    pub upgrade_id: u64,
    /// Probe nonce echoed by the acknowledgement.
    pub nonce: u64,
}

impl UpgradeProbePayload {
    /// Decode an `UPGRADE_PROBE` payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` if the payload length is not
    /// exactly `UPGRADE_PROBE_PAYLOAD_LEN` (16 bytes).
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != UPGRADE_PROBE_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: UPGRADE_PROBE_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }

        let upgrade_id =
            u64::from_be_bytes(payload[..UPGRADE_ID_PAYLOAD_LEN].try_into().map_err(|_| {
                PayloadError::LengthMismatch {
                    expected: UPGRADE_PROBE_PAYLOAD_LEN,
                    actual: payload.len(),
                }
            })?);
        let nonce =
            u64::from_be_bytes(payload[UPGRADE_ID_PAYLOAD_LEN..].try_into().map_err(|_| {
                PayloadError::LengthMismatch {
                    expected: UPGRADE_PROBE_PAYLOAD_LEN,
                    actual: payload.len(),
                }
            })?);

        Ok(Self { upgrade_id, nonce })
    }

    /// Encode an `UPGRADE_PROBE` payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.upgrade_id.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
    }
}

/// UDP upgrade probe acknowledgement payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeProbeAckPayload {
    /// Identifier of the upgrade attempt being acknowledged.
    pub upgrade_id: u64,
    /// Echo of the probe nonce.
    pub nonce: u64,
}

impl UpgradeProbeAckPayload {
    /// Decode an `UPGRADE_PROBE_ACK` payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` if the payload length is not
    /// exactly `UPGRADE_PROBE_PAYLOAD_LEN` (16 bytes).
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != UPGRADE_PROBE_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: UPGRADE_PROBE_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }

        let upgrade_id =
            u64::from_be_bytes(payload[..UPGRADE_ID_PAYLOAD_LEN].try_into().map_err(|_| {
                PayloadError::LengthMismatch {
                    expected: UPGRADE_PROBE_PAYLOAD_LEN,
                    actual: payload.len(),
                }
            })?);
        let nonce =
            u64::from_be_bytes(payload[UPGRADE_ID_PAYLOAD_LEN..].try_into().map_err(|_| {
                PayloadError::LengthMismatch {
                    expected: UPGRADE_PROBE_PAYLOAD_LEN,
                    actual: payload.len(),
                }
            })?);

        Ok(Self { upgrade_id, nonce })
    }

    /// Encode an `UPGRADE_PROBE_ACK` payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.upgrade_id.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
    }
}

/// Client readiness signal payload for UDP upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpReadyPayload {
    /// Identifier of the upgrade attempt.
    pub upgrade_id: u64,
}

impl UdpReadyPayload {
    /// Decode a `UDP_READY` payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` if the payload length is not
    /// exactly `UPGRADE_ID_PAYLOAD_LEN` (8 bytes).
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != UPGRADE_ID_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: UPGRADE_ID_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }

        let upgrade_id =
            u64::from_be_bytes(
                payload
                    .try_into()
                    .map_err(|_| PayloadError::LengthMismatch {
                        expected: UPGRADE_ID_PAYLOAD_LEN,
                        actual: payload.len(),
                    })?,
            );

        Ok(Self { upgrade_id })
    }

    /// Encode a `UDP_READY` payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.upgrade_id.to_be_bytes());
    }
}

/// Server switch commit payload for UDP upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchToUdpPayload {
    /// Identifier of the upgrade attempt being committed.
    pub upgrade_id: u64,
}

impl SwitchToUdpPayload {
    /// Decode a `SWITCH_TO_UDP` payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` if the payload length is not
    /// exactly `UPGRADE_ID_PAYLOAD_LEN` (8 bytes).
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != UPGRADE_ID_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: UPGRADE_ID_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }

        let upgrade_id =
            u64::from_be_bytes(
                payload
                    .try_into()
                    .map_err(|_| PayloadError::LengthMismatch {
                        expected: UPGRADE_ID_PAYLOAD_LEN,
                        actual: payload.len(),
                    })?,
            );

        Ok(Self { upgrade_id })
    }

    /// Encode a `SWITCH_TO_UDP` payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.upgrade_id.to_be_bytes());
    }
}

/// Client acknowledgement payload for UDP switch commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchAckPayload {
    /// Identifier of the acknowledged upgrade attempt.
    pub upgrade_id: u64,
}

impl SwitchAckPayload {
    /// Decode a `SWITCH_ACK` payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` if the payload length is not
    /// exactly `UPGRADE_ID_PAYLOAD_LEN` (8 bytes).
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != UPGRADE_ID_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: UPGRADE_ID_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }

        let upgrade_id =
            u64::from_be_bytes(
                payload
                    .try_into()
                    .map_err(|_| PayloadError::LengthMismatch {
                        expected: UPGRADE_ID_PAYLOAD_LEN,
                        actual: payload.len(),
                    })?,
            );

        Ok(Self { upgrade_id })
    }

    /// Encode a `SWITCH_ACK` payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.upgrade_id.to_be_bytes());
    }
}

/// PING payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingPayload {
    /// Ping nonce.
    pub nonce: u64,
}

impl PingPayload {
    /// Decode a PING payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` if the payload length is not
    /// exactly `PING_PAYLOAD_LEN` (8 bytes).
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != PING_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: PING_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let nonce = u64::from_be_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        Ok(Self { nonce })
    }

    /// Encode a PING payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.nonce.to_be_bytes());
    }
}

/// PONG payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PongPayload {
    /// Pong nonce.
    pub nonce: u64,
}

impl PongPayload {
    /// Decode a PONG payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` if the payload length is not
    /// exactly `PING_PAYLOAD_LEN` (8 bytes).
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != PING_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: PING_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let nonce = u64::from_be_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        Ok(Self { nonce })
    }

    /// Encode a PONG payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.nonce.to_be_bytes());
    }
}

/// CLOSE payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosePayload {
    /// Close reason code.
    pub code: CloseCode,
}

impl ClosePayload {
    /// Decode a CLOSE payload.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload length is not exactly `CLOSE_PAYLOAD_LEN` (1 byte)
    /// - The close code byte is invalid
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != CLOSE_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: CLOSE_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let code = CloseCode::try_from(payload[0])
            .map_err(|_| PayloadError::InvalidCloseCode(payload[0]))?;
        Ok(Self { code })
    }

    /// Encode a CLOSE payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(self.code));
    }
}

/// Payload parsing errors.
///
/// This is a real [`std::error::Error`] type (it derives [`thiserror::Error`])
/// so downstream layers can preserve it via `#[from]` rather than flattening it
/// into an `io::Error`. It stays `Copy` — callers rely on that, and `thiserror`
/// is compatible with `Copy` enums as long as every field is `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// Payload length does not match the expected length.
    #[error("payload length mismatch: expected {expected}, got {actual}")]
    LengthMismatch {
        /// Expected payload length for the message type.
        expected: usize,
        /// Actual payload length that was decoded.
        actual: usize,
    },
    /// Payload is shorter than the minimum required length.
    #[error("payload too short: need at least {min} bytes, got {actual}")]
    LengthTooShort {
        /// Minimum payload length required to continue parsing.
        min: usize,
        /// Actual payload length that was decoded.
        actual: usize,
    },
    /// Client-to-server CID length is invalid.
    #[error("invalid client-to-server cid length: {0}")]
    InvalidClientToServerCidLen(usize),
    /// Server-to-client CID length is invalid.
    #[error("invalid server-to-client cid length: {0}")]
    InvalidServerToClientCidLen(usize),
    /// Cipher identifier is unknown.
    #[error("unknown cipher suite identifier: {0:#02x}")]
    InvalidCipher(u8),
    /// Auth failure code is unknown.
    #[error("unknown auth failure code: {0:#02x}")]
    InvalidAuthFailCode(u8),
    /// Register failure code is unknown.
    #[error("unknown register failure code: {0:#02x}")]
    InvalidRegisterFailCode(u8),
    /// Close code is unknown.
    #[error("unknown close code: {0:#02x}")]
    InvalidCloseCode(u8),
    /// Key phase is not 0 or 1.
    #[error("invalid key phase: {0:#02x}")]
    InvalidKeyPhase(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_register_payload_eq(actual: &RegisterCidPayload, expected: &RegisterCidPayload) {
        assert_eq!(actual.client_to_server_cid, expected.client_to_server_cid);
        assert_eq!(actual.server_to_client_cid, expected.server_to_client_cid);
        assert_eq!(actual.cipher, expected.cipher);
        assert_eq!(actual.secret_tx, expected.secret_tx);
        assert_eq!(actual.secret_rx, expected.secret_rx);
        assert_eq!(actual.pn_start, expected.pn_start);
        assert_eq!(actual.pn_start_rx, expected.pn_start_rx);
        assert_eq!(actual.key_phase, expected.key_phase);
    }

    fn assert_register_decode_err(payload: &[u8], expected: PayloadError) {
        match RegisterCidPayload::decode(payload) {
            Ok(_) => panic!("REGISTER_CID decode unexpectedly succeeded"),
            Err(actual) => assert_eq!(actual, expected),
        }
    }

    #[test]
    fn auth_payload_roundtrip() {
        let payload = AuthPayload {
            client_id: ClientId([0x11; 16]),
            assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
            challenge: [0x22; AUTH_CHALLENGE_LEN],
            signature: [0x33; AUTH_SIGNATURE_LEN],
        };

        let mut buf = Vec::new();
        payload.encode(&mut buf);
        let decoded = AuthPayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn auth_ok_requires_empty_payload() {
        let buf = [0x01];
        assert_eq!(
            AuthOkPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: 0,
                actual: 1
            })
        );
    }

    #[test]
    fn register_cid_roundtrip() {
        let c2s_cid = Cid::from([0x55u8; MAX_DCID_LEN]);
        let s2c_cid = Cid::new(&[0x44u8; 8]).unwrap(); // Can be shorter
        let payload = RegisterCidPayload {
            client_to_server_cid: c2s_cid,
            server_to_client_cid: s2c_cid,
            cipher: CipherSuite::Aes128Gcm,
            secret_tx: [0x01; UDP_QSP_TRAFFIC_SECRET_LEN],
            secret_rx: [0x02; UDP_QSP_TRAFFIC_SECRET_LEN],
            pn_start: 42,
            pn_start_rx: 9001,
            key_phase: true,
        };

        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();
        let decoded = RegisterCidPayload::decode(&buf).unwrap();
        assert_eq!(decoded.client_to_server_cid, payload.client_to_server_cid);
        assert_eq!(decoded.server_to_client_cid, payload.server_to_client_cid);
        assert_eq!(decoded.cipher, payload.cipher);
        assert_eq!(decoded.secret_tx, payload.secret_tx);
        assert_eq!(decoded.secret_rx, payload.secret_rx);
        assert_eq!(decoded.pn_start, payload.pn_start);
        assert_eq!(decoded.pn_start_rx, payload.pn_start_rx);
        assert_eq!(decoded.key_phase, payload.key_phase);
    }

    #[test]
    fn register_cid_roundtrip_with_empty_scid() {
        let c2s_cid = Cid::from([0x55u8; MAX_DCID_LEN]);
        let s2c_cid = Cid::new(&[]).unwrap(); // Empty SCID (Chrome behavior)
        let payload = RegisterCidPayload {
            client_to_server_cid: c2s_cid,
            server_to_client_cid: s2c_cid,
            cipher: CipherSuite::Aes128Gcm,
            secret_tx: [0x01; UDP_QSP_TRAFFIC_SECRET_LEN],
            secret_rx: [0x02; UDP_QSP_TRAFFIC_SECRET_LEN],
            pn_start: 42,
            pn_start_rx: 9001,
            key_phase: false,
        };

        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();
        let decoded = RegisterCidPayload::decode(&buf).unwrap();
        assert_eq!(decoded.client_to_server_cid, payload.client_to_server_cid);
        assert_eq!(decoded.server_to_client_cid, payload.server_to_client_cid);
        assert!(decoded.server_to_client_cid.is_empty());
    }

    #[test]
    fn register_cid_roundtrip_max_len() {
        let c2s_cid = Cid::new(&[0x55u8; MAX_DCID_LEN]).unwrap();
        let s2c_cid = Cid::new(&[0x44u8; MAX_DCID_LEN]).unwrap();
        let payload = RegisterCidPayload {
            client_to_server_cid: c2s_cid,
            server_to_client_cid: s2c_cid,
            cipher: CipherSuite::Aes128Gcm,
            secret_tx: [0x01; UDP_QSP_TRAFFIC_SECRET_LEN],
            secret_rx: [0x02; UDP_QSP_TRAFFIC_SECRET_LEN],
            pn_start: 42,
            pn_start_rx: 9001,
            key_phase: true,
        };

        let expected_len = 1
            + payload.client_to_server_cid.len()
            + 1
            + payload.server_to_client_cid.len()
            + 1
            + (UDP_QSP_TRAFFIC_SECRET_LEN * 2)
            + 8
            + 8
            + 1;

        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), expected_len);

        let decoded = RegisterCidPayload::decode(&buf).unwrap();
        assert_register_payload_eq(&decoded, &payload);
    }

    #[test]
    fn register_cid_roundtrip_chacha_uses_fixed_size_secrets() {
        let c2s_cid = Cid::new(&[0x55u8; MAX_DCID_LEN]).unwrap();
        let s2c_cid = Cid::new(&[0x44u8; MAX_DCID_LEN]).unwrap();
        let payload = RegisterCidPayload {
            client_to_server_cid: c2s_cid,
            server_to_client_cid: s2c_cid,
            cipher: CipherSuite::ChaCha20Poly1305,
            secret_tx: [0x01; UDP_QSP_TRAFFIC_SECRET_LEN],
            secret_rx: [0x02; UDP_QSP_TRAFFIC_SECRET_LEN],
            pn_start: 42,
            pn_start_rx: 9001,
            key_phase: true,
        };

        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), payload.encoded_len());

        let decoded = RegisterCidPayload::decode(&buf).unwrap();
        assert_register_payload_eq(&decoded, &payload);
    }

    #[test]
    fn register_cid_decode_rejects_short_secret_payload() {
        let c2s_cid = Cid::from([0x55u8; MAX_DCID_LEN]);
        let s2c_cid = Cid::from([0x44u8; MAX_DCID_LEN]);

        let mut buf = vec![];
        buf.push(c2s_cid.len() as u8);
        buf.extend_from_slice(c2s_cid.as_slice());
        buf.push(s2c_cid.len() as u8);
        buf.extend_from_slice(s2c_cid.as_slice());
        buf.push(CipherSuite::ChaCha20Poly1305 as u8);
        buf.extend_from_slice(&[0x01; (UDP_QSP_TRAFFIC_SECRET_LEN * 2) - 1]);
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.push(0);

        assert_register_decode_err(
            &buf,
            PayloadError::LengthMismatch {
                expected: RegisterCidPayload::encoded_len_for(
                    c2s_cid.len(),
                    s2c_cid.len(),
                    CipherSuite::ChaCha20Poly1305,
                ),
                actual: buf.len(),
            },
        );
    }

    #[test]
    fn register_ok_roundtrip() {
        let c2s_cid = Cid::from([0xAAu8; MAX_DCID_LEN]);
        let payload = RegisterOkPayload {
            client_to_server_cid: c2s_cid,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();
        let decoded = RegisterOkPayload::decode(&buf).unwrap();
        assert_eq!(decoded.client_to_server_cid, payload.client_to_server_cid);
    }

    #[test]
    fn upgrade_probe_roundtrip() {
        let payload = UpgradeProbePayload {
            upgrade_id: 0x1122_3344_5566_7788,
            nonce: 0x99aa_bbcc_ddee_ff00,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf);
        let decoded = UpgradeProbePayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn upgrade_probe_ack_roundtrip() {
        let payload = UpgradeProbeAckPayload {
            upgrade_id: 0x0123_4567_89ab_cdef,
            nonce: 0xfedc_ba98_7654_3210,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf);
        let decoded = UpgradeProbeAckPayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn udp_ready_roundtrip() {
        let payload = UdpReadyPayload {
            upgrade_id: 0x1122_3344_5566_7788,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf);
        let decoded = UdpReadyPayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn switch_to_udp_roundtrip() {
        let payload = SwitchToUdpPayload {
            upgrade_id: 0xaabb_ccdd_eeff_0011,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf);
        let decoded = SwitchToUdpPayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn switch_ack_roundtrip() {
        let payload = SwitchAckPayload {
            upgrade_id: 0x1234_5678_9abc_def0,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf);
        let decoded = SwitchAckPayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn ping_pong_roundtrip() {
        let ping = PingPayload {
            nonce: 0x1122_3344_5566_7788,
        };
        let mut buf = Vec::new();
        ping.encode(&mut buf);
        let decoded_ping = PingPayload::decode(&buf).unwrap();
        assert_eq!(decoded_ping, ping);

        buf.clear();
        let pong_response = PongPayload {
            nonce: 0x1122_3344_5566_7788,
        };
        pong_response.encode(&mut buf);
        let decoded_pong_response = PongPayload::decode(&buf).unwrap();
        assert_eq!(decoded_pong_response, pong_response);
    }

    #[test]
    fn close_payload_invalid_code() {
        let buf = [0xff];
        assert_eq!(
            ClosePayload::decode(&buf),
            Err(PayloadError::InvalidCloseCode(0xff))
        );
    }

    #[test]
    fn auth_ok_roundtrip() {
        let payload = AuthOkPayload;
        let mut buf = Vec::new();
        payload.encode(&mut buf);
        assert!(buf.is_empty());
        let decoded = AuthOkPayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn close_payload_roundtrip() {
        let payload = ClosePayload {
            code: CloseCode::IdleTimeout,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf);
        let decoded = ClosePayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn auth_payload_length_mismatch() {
        // Too short
        let buf = [0u8; AUTH_PAYLOAD_LEN - 1];
        assert_eq!(
            AuthPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: AUTH_PAYLOAD_LEN,
                actual: AUTH_PAYLOAD_LEN - 1
            })
        );

        // Too long
        let buf = [0u8; AUTH_PAYLOAD_LEN + 1];
        assert_eq!(
            AuthPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: AUTH_PAYLOAD_LEN,
                actual: AUTH_PAYLOAD_LEN + 1
            })
        );
    }

    #[test]
    fn ping_payload_length_mismatch() {
        // Too short
        let buf = [0u8; PING_PAYLOAD_LEN - 1];
        assert_eq!(
            PingPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: PING_PAYLOAD_LEN,
                actual: PING_PAYLOAD_LEN - 1
            })
        );

        // Too long
        let buf = [0u8; PING_PAYLOAD_LEN + 1];
        assert_eq!(
            PingPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: PING_PAYLOAD_LEN,
                actual: PING_PAYLOAD_LEN + 1
            })
        );
    }

    #[test]
    fn pong_payload_length_mismatch() {
        // Too short
        let buf = [0u8; PING_PAYLOAD_LEN - 1];
        assert_eq!(
            PongPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: PING_PAYLOAD_LEN,
                actual: PING_PAYLOAD_LEN - 1
            })
        );

        // Too long
        let buf = [0u8; PING_PAYLOAD_LEN + 1];
        assert_eq!(
            PongPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: PING_PAYLOAD_LEN,
                actual: PING_PAYLOAD_LEN + 1
            })
        );
    }

    #[test]
    fn close_payload_length_mismatch() {
        // Too short (empty)
        let buf: [u8; 0] = [];
        assert_eq!(
            ClosePayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: CLOSE_PAYLOAD_LEN,
                actual: 0
            })
        );

        // Too long
        let buf = [0u8; 2];
        assert_eq!(
            ClosePayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: CLOSE_PAYLOAD_LEN,
                actual: 2
            })
        );
    }

    #[test]
    fn auth_fail_payload_length_mismatch() {
        // Too short (empty)
        let buf: [u8; 0] = [];
        assert_eq!(
            AuthFailPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: 1,
                actual: 0
            })
        );

        // Too long
        let buf = [0u8; 2];
        assert_eq!(
            AuthFailPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: 1,
                actual: 2
            })
        );
    }

    #[test]
    fn register_fail_payload_length_mismatch() {
        // Too short (empty)
        let buf: [u8; 0] = [];
        assert_eq!(
            RegisterFailPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: 1,
                actual: 0
            })
        );

        // Too long
        let buf = [0u8; 2];
        assert_eq!(
            RegisterFailPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: 1,
                actual: 2
            })
        );
    }

    #[test]
    fn upgrade_probe_payload_length_mismatch() {
        let short = [0u8; UPGRADE_PROBE_PAYLOAD_LEN - 1];
        assert_eq!(
            UpgradeProbePayload::decode(&short),
            Err(PayloadError::LengthMismatch {
                expected: UPGRADE_PROBE_PAYLOAD_LEN,
                actual: UPGRADE_PROBE_PAYLOAD_LEN - 1
            })
        );
    }

    #[test]
    fn upgrade_probe_ack_payload_length_mismatch() {
        let long = [0u8; UPGRADE_PROBE_PAYLOAD_LEN + 1];
        assert_eq!(
            UpgradeProbeAckPayload::decode(&long),
            Err(PayloadError::LengthMismatch {
                expected: UPGRADE_PROBE_PAYLOAD_LEN,
                actual: UPGRADE_PROBE_PAYLOAD_LEN + 1
            })
        );
    }

    #[test]
    fn udp_ready_payload_length_mismatch() {
        let short = [0u8; UPGRADE_ID_PAYLOAD_LEN - 1];
        assert_eq!(
            UdpReadyPayload::decode(&short),
            Err(PayloadError::LengthMismatch {
                expected: UPGRADE_ID_PAYLOAD_LEN,
                actual: UPGRADE_ID_PAYLOAD_LEN - 1
            })
        );
    }

    #[test]
    fn switch_to_udp_payload_length_mismatch() {
        let long = [0u8; UPGRADE_ID_PAYLOAD_LEN + 1];
        assert_eq!(
            SwitchToUdpPayload::decode(&long),
            Err(PayloadError::LengthMismatch {
                expected: UPGRADE_ID_PAYLOAD_LEN,
                actual: UPGRADE_ID_PAYLOAD_LEN + 1
            })
        );
    }

    #[test]
    fn switch_ack_payload_length_mismatch() {
        let short = [0u8; UPGRADE_ID_PAYLOAD_LEN - 1];
        assert_eq!(
            SwitchAckPayload::decode(&short),
            Err(PayloadError::LengthMismatch {
                expected: UPGRADE_ID_PAYLOAD_LEN,
                actual: UPGRADE_ID_PAYLOAD_LEN - 1
            })
        );
    }

    #[test]
    fn register_cid_invalid_c2s_cid_len() {
        // client_to_server_cid length must be exactly MAX_DCID_LEN
        let mut buf = vec![(MAX_DCID_LEN - 1) as u8]; // c2s_cid_len = 19
        buf.extend_from_slice(&[0u8; MAX_DCID_LEN - 1]);

        assert_register_decode_err(
            &buf,
            PayloadError::InvalidClientToServerCidLen(MAX_DCID_LEN - 1),
        );
    }

    #[test]
    fn register_cid_invalid_s2c_cid_len() {
        let c2s_cid = Cid::from([0x55u8; MAX_DCID_LEN]);
        let mut buf = vec![];
        buf.push(c2s_cid.len() as u8);
        buf.extend_from_slice(c2s_cid.as_slice());
        buf.push((MAX_DCID_LEN + 1) as u8); // s2c_cid_len = 21 (too long)

        assert_register_decode_err(
            &buf,
            PayloadError::InvalidServerToClientCidLen(MAX_DCID_LEN + 1),
        );
    }

    #[test]
    fn register_ok_invalid_cid_len() {
        // CID length must be exactly MAX_DCID_LEN
        let buf = vec![0u8]; // cid_len = 0

        assert_eq!(
            RegisterOkPayload::decode(&buf),
            Err(PayloadError::InvalidClientToServerCidLen(0))
        );

        // CID length too long (exceeds MAX_DCID_LEN)
        let mut buf = vec![(MAX_DCID_LEN + 1) as u8];
        buf.extend_from_slice(&[0u8; MAX_DCID_LEN + 1]);

        assert_eq!(
            RegisterOkPayload::decode(&buf),
            Err(PayloadError::InvalidClientToServerCidLen(MAX_DCID_LEN + 1))
        );
    }

    #[test]
    fn register_ok_length_mismatch() {
        let c2s_cid = Cid::from([0xAAu8; MAX_DCID_LEN]);
        let mut buf = vec![];
        buf.push(c2s_cid.len() as u8);
        buf.extend_from_slice(c2s_cid.as_slice());
        buf.push(0xFF); // extra byte

        assert_eq!(
            RegisterOkPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: 1 + c2s_cid.len(),
                actual: 1 + c2s_cid.len() + 1
            })
        );
    }

    #[test]
    fn auth_fail_invalid_code() {
        let buf = [0xFF];
        assert_eq!(
            AuthFailPayload::decode(&buf),
            Err(PayloadError::InvalidAuthFailCode(0xFF))
        );
    }

    #[test]
    fn register_fail_invalid_code() {
        let buf = [0xFF];
        assert_eq!(
            RegisterFailPayload::decode(&buf),
            Err(PayloadError::InvalidRegisterFailCode(0xFF))
        );
    }

    #[test]
    fn register_cid_invalid_cipher() {
        let c2s_cid = Cid::from([0x55u8; MAX_DCID_LEN]);
        let s2c_cid = Cid::from([0x44u8; MAX_DCID_LEN]);

        let mut buf = vec![];
        buf.push(c2s_cid.len() as u8);
        buf.extend_from_slice(c2s_cid.as_slice());
        buf.push(s2c_cid.len() as u8);
        buf.extend_from_slice(s2c_cid.as_slice());
        buf.push(0xFF); // invalid cipher
        buf.extend_from_slice(&[0x01; UDP_QSP_TRAFFIC_SECRET_LEN * 2]);
        buf.extend_from_slice(&0u64.to_be_bytes()); // pn_start
        buf.extend_from_slice(&0u64.to_be_bytes()); // pn_start_rx
        buf.push(0); // key_phase

        assert_register_decode_err(&buf, PayloadError::InvalidCipher(0xFF));
    }

    #[test]
    fn register_cid_invalid_key_phase() {
        let c2s_cid = Cid::from([0x55u8; MAX_DCID_LEN]);
        let s2c_cid = Cid::from([0x44u8; MAX_DCID_LEN]);

        let mut buf = vec![];
        buf.push(c2s_cid.len() as u8);
        buf.extend_from_slice(c2s_cid.as_slice());
        buf.push(s2c_cid.len() as u8);
        buf.extend_from_slice(s2c_cid.as_slice());
        buf.push(CipherSuite::Aes128Gcm as u8);
        buf.extend_from_slice(&[0x01; UDP_QSP_TRAFFIC_SECRET_LEN * 2]);
        buf.extend_from_slice(&0u64.to_be_bytes()); // pn_start
        buf.extend_from_slice(&0u64.to_be_bytes()); // pn_start_rx
        buf.push(0xFF); // invalid key phase

        assert_register_decode_err(&buf, PayloadError::InvalidKeyPhase(0xFF));
    }
}
