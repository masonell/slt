use std::net::Ipv4Addr;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::PayloadError;
use crate::types::ClientId;

/// Length of the authentication challenge in bytes.
pub const AUTH_CHALLENGE_LEN: usize = 32;
/// Length of the Ed25519 signature in bytes.
pub const AUTH_SIGNATURE_LEN: usize = 64;
/// Length of the AUTH payload in bytes.
pub const AUTH_PAYLOAD_LEN: usize = 16 + 4 + 2 + AUTH_CHALLENGE_LEN + AUTH_SIGNATURE_LEN;

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
    /// Client and server TUN MTUs do not match.
    MtuMismatch = 0x06,
}

/// Authentication message payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthPayload {
    /// Client identifier.
    pub client_id: ClientId,
    /// Assigned IPv4 address.
    pub assigned_ipv4: Ipv4Addr,
    /// Client TUN interface MTU.
    pub tun_mtu: u16,
    /// Server-provided challenge bytes.
    pub challenge: [u8; AUTH_CHALLENGE_LEN],
    /// Ed25519 signature over the authentication context.
    pub signature: [u8; AUTH_SIGNATURE_LEN],
}

impl AuthPayload {
    /// Decode an AUTH payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` if the payload length is not
    /// exactly `AUTH_PAYLOAD_LEN` (118 bytes).
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
        let tun_mtu = u16::from_be_bytes([payload[20], payload[21]]);

        let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
        challenge.copy_from_slice(&payload[22..22 + AUTH_CHALLENGE_LEN]);

        let mut signature = [0u8; AUTH_SIGNATURE_LEN];
        signature.copy_from_slice(
            &payload[22 + AUTH_CHALLENGE_LEN..22 + AUTH_CHALLENGE_LEN + AUTH_SIGNATURE_LEN],
        );

        Ok(Self {
            client_id,
            assigned_ipv4,
            tun_mtu,
            challenge,
            signature,
        })
    }

    /// Encode an AUTH payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(AUTH_PAYLOAD_LEN);
        out.extend_from_slice(self.client_id.as_bytes());
        out.extend_from_slice(&self.assigned_ipv4.octets());
        out.extend_from_slice(&self.tun_mtu.to_be_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_payload_roundtrip() {
        let payload = AuthPayload {
            client_id: ClientId([0x11; 16]),
            assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
            tun_mtu: 1280,
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
    fn auth_ok_roundtrip() {
        let payload = AuthOkPayload;
        let mut buf = Vec::new();
        payload.encode(&mut buf);
        assert!(buf.is_empty());
        let decoded = AuthOkPayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn auth_payload_length_mismatch() {
        let buf = [0u8; AUTH_PAYLOAD_LEN - 1];
        assert_eq!(
            AuthPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: AUTH_PAYLOAD_LEN,
                actual: AUTH_PAYLOAD_LEN - 1
            })
        );

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
    fn auth_fail_payload_length_mismatch() {
        let buf: [u8; 0] = [];
        assert_eq!(
            AuthFailPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: 1,
                actual: 0
            })
        );

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
    fn auth_fail_invalid_code() {
        let buf = [0xFF];
        assert_eq!(
            AuthFailPayload::decode(&buf),
            Err(PayloadError::InvalidAuthFailCode(0xFF))
        );
    }
}
