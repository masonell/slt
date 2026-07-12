use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::PayloadError;

/// Length of the PING/PONG payload in bytes.
pub const PING_PAYLOAD_LEN: usize = 8;
/// Length of TCP fallback identifier payloads in bytes.
pub const FALLBACK_ID_PAYLOAD_LEN: usize = 8;
/// Length of the CLOSE payload in bytes.
pub const CLOSE_PAYLOAD_LEN: usize = 1;

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

/// Request payload for switching outbound traffic back to TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallbackToTcpPayload {
    /// Identifier echoed by the peer in `FALLBACK_OK`.
    pub fallback_id: u64,
}

impl FallbackToTcpPayload {
    /// Decode a `FALLBACK_TO_TCP` payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` unless the payload is exactly
    /// [`FALLBACK_ID_PAYLOAD_LEN`] bytes.
    pub const fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != FALLBACK_ID_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: FALLBACK_ID_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let mut bytes = [0; FALLBACK_ID_PAYLOAD_LEN];
        bytes.copy_from_slice(payload);
        Ok(Self {
            fallback_id: u64::from_be_bytes(bytes),
        })
    }

    /// Encode a `FALLBACK_TO_TCP` payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.fallback_id.to_be_bytes());
    }
}

/// Acknowledgement payload for a TCP fallback request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallbackOkPayload {
    /// Identifier copied from the corresponding `FALLBACK_TO_TCP`.
    pub fallback_id: u64,
}

impl FallbackOkPayload {
    /// Decode a `FALLBACK_OK` payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` unless the payload is exactly
    /// [`FALLBACK_ID_PAYLOAD_LEN`] bytes.
    pub const fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != FALLBACK_ID_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: FALLBACK_ID_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let mut bytes = [0; FALLBACK_ID_PAYLOAD_LEN];
        bytes.copy_from_slice(payload);
        Ok(Self {
            fallback_id: u64::from_be_bytes(bytes),
        })
    }

    /// Encode a `FALLBACK_OK` payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.fallback_id.to_be_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_payloads_roundtrip() {
        let request = FallbackToTcpPayload {
            fallback_id: 0xf011_bacc_1234_5678,
        };
        let mut buf = Vec::new();
        request.encode(&mut buf);
        assert_eq!(FallbackToTcpPayload::decode(&buf).unwrap(), request);

        let ok = FallbackOkPayload {
            fallback_id: request.fallback_id,
        };
        buf.clear();
        ok.encode(&mut buf);
        assert_eq!(FallbackOkPayload::decode(&buf).unwrap(), ok);
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
    fn ping_payload_length_mismatch() {
        let buf = [0u8; PING_PAYLOAD_LEN - 1];
        assert_eq!(
            PingPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: PING_PAYLOAD_LEN,
                actual: PING_PAYLOAD_LEN - 1
            })
        );

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
        let buf = [0u8; PING_PAYLOAD_LEN - 1];
        assert_eq!(
            PongPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: PING_PAYLOAD_LEN,
                actual: PING_PAYLOAD_LEN - 1
            })
        );

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
        let buf: [u8; 0] = [];
        assert_eq!(
            ClosePayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: CLOSE_PAYLOAD_LEN,
                actual: 0
            })
        );

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
    fn fallback_payload_length_mismatch() {
        let short = [0u8; FALLBACK_ID_PAYLOAD_LEN - 1];
        let expected = PayloadError::LengthMismatch {
            expected: FALLBACK_ID_PAYLOAD_LEN,
            actual: FALLBACK_ID_PAYLOAD_LEN - 1,
        };
        assert_eq!(FallbackToTcpPayload::decode(&short), Err(expected));
        assert_eq!(FallbackOkPayload::decode(&short), Err(expected));
    }
}
