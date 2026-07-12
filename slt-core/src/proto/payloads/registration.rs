use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::PayloadError;
use crate::types::{Cid, MAX_DCID_LEN};

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

    fn read_u64(payload: &[u8], offset: &mut usize) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&payload[*offset..*offset + 8]);
        *offset += 8;
        u64::from_be_bytes(bytes)
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
        let pn_start = Self::read_u64(payload, &mut offset);
        let pn_start_rx = Self::read_u64(payload, &mut offset);
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

        let cid_offset = 1;
        let cid_end = cid_offset + cid_len;
        Ok(Self {
            client_to_server_cid: Cid::try_from(&payload[cid_offset..cid_end])
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
    fn register_cid_roundtrip() {
        let c2s_cid = Cid::from([0x55u8; MAX_DCID_LEN]);
        let s2c_cid = Cid::new(&[0x44u8; 8]).unwrap();
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
        assert_register_payload_eq(&decoded, &payload);
    }

    #[test]
    fn register_cid_roundtrip_with_empty_scid() {
        let c2s_cid = Cid::from([0x55u8; MAX_DCID_LEN]);
        let s2c_cid = Cid::new(&[]).unwrap();
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
    fn register_fail_payload_length_mismatch() {
        let buf: [u8; 0] = [];
        assert_eq!(
            RegisterFailPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: 1,
                actual: 0
            })
        );

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
    fn register_cid_invalid_c2s_cid_len() {
        let mut buf = vec![(MAX_DCID_LEN - 1) as u8];
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
        buf.push((MAX_DCID_LEN + 1) as u8);

        assert_register_decode_err(
            &buf,
            PayloadError::InvalidServerToClientCidLen(MAX_DCID_LEN + 1),
        );
    }

    #[test]
    fn register_ok_invalid_cid_len() {
        let buf = vec![0u8];

        assert_eq!(
            RegisterOkPayload::decode(&buf),
            Err(PayloadError::InvalidClientToServerCidLen(0))
        );

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
        buf.push(0xFF);

        assert_eq!(
            RegisterOkPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: 1 + c2s_cid.len(),
                actual: 1 + c2s_cid.len() + 1
            })
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
        buf.push(0xFF);
        buf.extend_from_slice(&[0x01; UDP_QSP_TRAFFIC_SECRET_LEN * 2]);
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.push(0);

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
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.push(0xFF);

        assert_register_decode_err(&buf, PayloadError::InvalidKeyPhase(0xFF));
    }
}
