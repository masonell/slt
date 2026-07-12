use super::PayloadError;

/// Length of upgrade identifier payloads in bytes.
pub const UPGRADE_ID_PAYLOAD_LEN: usize = 8;
/// Length of UDP upgrade probe/ack payloads in bytes.
pub const UPGRADE_PROBE_PAYLOAD_LEN: usize = 16;

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

/// Server switch request payload for UDP upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchToUdpPayload {
    /// Identifier of the upgrade attempt being switched.
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

/// Client acceptance payload for a UDP switch request.
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

/// Server confirmation payload for a completed UDP switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchOkPayload {
    /// Identifier of the committed upgrade attempt.
    pub upgrade_id: u64,
}

impl SwitchOkPayload {
    /// Decode a `SWITCH_OK` payload.
    ///
    /// # Errors
    ///
    /// Returns `PayloadError::LengthMismatch` unless the payload is exactly
    /// [`UPGRADE_ID_PAYLOAD_LEN`] bytes.
    pub const fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != UPGRADE_ID_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: UPGRADE_ID_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let mut bytes = [0; UPGRADE_ID_PAYLOAD_LEN];
        bytes.copy_from_slice(payload);
        Ok(Self {
            upgrade_id: u64::from_be_bytes(bytes),
        })
    }

    /// Encode a `SWITCH_OK` payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.upgrade_id.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn switch_ok_roundtrip() {
        let payload = SwitchOkPayload {
            upgrade_id: 0x0fed_cba9_8765_4321,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf);
        assert_eq!(SwitchOkPayload::decode(&buf).unwrap(), payload);
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
    fn switch_ok_payload_length_mismatch() {
        let short = [0u8; UPGRADE_ID_PAYLOAD_LEN - 1];
        assert_eq!(
            SwitchOkPayload::decode(&short),
            Err(PayloadError::LengthMismatch {
                expected: UPGRADE_ID_PAYLOAD_LEN,
                actual: UPGRADE_ID_PAYLOAD_LEN - 1
            })
        );
    }
}
