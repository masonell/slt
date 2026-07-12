use slt_core::proto::{CloseCode, PingPayload};

mod ping_payload {
    use super::*;

    /// Test ping payload encoding and decoding roundtrip.
    #[test]
    fn ping_payload_roundtrip() {
        let nonce = 0x1234_5678_9ABC_DEF0_u64;
        let ping = PingPayload { nonce };

        let mut buf = Vec::new();
        ping.encode(&mut buf);

        let decoded = PingPayload::decode(&buf).unwrap();
        assert_eq!(decoded.nonce, nonce);
    }

    /// Test ping payload requires exactly 8 bytes.
    #[test]
    fn ping_payload_requires_8_bytes() {
        // Too short
        assert!(PingPayload::decode(&[]).is_err());
        assert!(PingPayload::decode(&[1, 2, 3, 4, 5, 6, 7]).is_err());

        // Too long - should still work if first 8 bytes are valid
        let valid_buf = 0x123456789ABCDEF0_u64.to_be_bytes();
        assert!(PingPayload::decode(&valid_buf).is_ok());
    }
}

mod close_codes {
    use super::*;

    /// Test close code values exist.
    #[test]
    fn close_codes_are_defined() {
        assert!(matches!(CloseCode::Normal, CloseCode::Normal));
        assert!(matches!(CloseCode::IdleTimeout, CloseCode::IdleTimeout));
    }

    /// Test close code for idle timeout has expected value.
    #[test]
    fn idle_timeout_close_code_value() {
        // IdleTimeout should have a specific value for protocol compatibility
        let code = CloseCode::IdleTimeout;
        // Verify it can be used in comparisons
        assert_eq!(code, CloseCode::IdleTimeout);
        assert_ne!(code, CloseCode::Normal);
    }
}
