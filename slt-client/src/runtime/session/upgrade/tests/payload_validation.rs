use super::super::*;

mod register_fail_payload_decode {
    use slt_core::proto::{RegisterFailCode, RegisterFailPayload};

    use super::*;

    #[test]
    fn valid_payload_with_unknown_code_decodes() {
        // RegisterFailPayload has no encode method, so we build the buffer manually
        // Format: 1 byte for the code
        let buf = [u8::from(RegisterFailCode::Unknown)];
        let decoded = RegisterFailPayload::decode(&buf).unwrap();
        assert_eq!(decoded.code, RegisterFailCode::Unknown);
    }

    #[test]
    fn valid_payload_with_not_authenticated_decodes() {
        let buf = [u8::from(RegisterFailCode::NotAuthenticated)];
        let decoded = RegisterFailPayload::decode(&buf).unwrap();
        assert_eq!(decoded.code, RegisterFailCode::NotAuthenticated);
    }

    #[test]
    fn valid_payload_with_invalid_cipher_decodes() {
        let buf = [u8::from(RegisterFailCode::InvalidCipher)];
        let decoded = RegisterFailPayload::decode(&buf).unwrap();
        assert_eq!(decoded.code, RegisterFailCode::InvalidCipher);
    }

    #[test]
    fn valid_payload_with_invalid_cid_decodes() {
        let buf = [u8::from(RegisterFailCode::InvalidCid)];
        let decoded = RegisterFailPayload::decode(&buf).unwrap();
        assert_eq!(decoded.code, RegisterFailCode::InvalidCid);
    }

    #[test]
    fn valid_payload_with_invalid_keys_decodes() {
        let buf = [u8::from(RegisterFailCode::InvalidKeys)];
        let decoded = RegisterFailPayload::decode(&buf).unwrap();
        assert_eq!(decoded.code, RegisterFailCode::InvalidKeys);
    }

    #[test]
    fn empty_payload_fails() {
        let result = RegisterFailPayload::decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_code_fails() {
        // 0xFF is not a valid RegisterFailCode
        let result = RegisterFailPayload::decode(&[0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_error_preserved_as_session_error() {
        let result = RegisterFailPayload::decode(&[]);
        assert!(result.is_err());

        // The payload decode error is preserved as a typed `SessionError`,
        // carrying the proto detail.
        let err = SessionError::from(result.unwrap_err());
        assert!(matches!(err, SessionError::Payload(_)));
        assert_eq!(err.exit(), SessionExit::ProtocolError);
    }

    #[test]
    fn too_long_payload_fails() {
        // Payload must be exactly 1 byte
        let result = RegisterFailPayload::decode(&[0x00, 0x01]);
        assert!(result.is_err());
    }
}

mod register_ok_payload_decode {
    use slt_core::proto::RegisterOkPayload;
    use slt_core::types::{Cid, MAX_DCID_LEN};

    use super::*;

    #[test]
    fn valid_payload_decodes() {
        let c2s_cid = Cid::from([0xAA; MAX_DCID_LEN]);
        let payload = RegisterOkPayload {
            client_to_server_cid: c2s_cid,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();

        let decoded = RegisterOkPayload::decode(&buf).unwrap();
        assert_eq!(decoded.client_to_server_cid, c2s_cid);
    }

    #[test]
    fn empty_payload_fails() {
        let result = RegisterOkPayload::decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_payload_fails() {
        // Only 4 bytes, need 20 for cid
        let result = RegisterOkPayload::decode(&[0x01, 0x02, 0x03, 0x04]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_error_preserved_as_session_error() {
        let result = RegisterOkPayload::decode(&[]);
        assert!(result.is_err());

        let err = SessionError::from(result.unwrap_err());
        assert!(matches!(err, SessionError::Payload(_)));
        assert_eq!(err.exit(), SessionExit::ProtocolError);
    }
}

/// The DCID-mismatch and missing-session branches in `handle_register_ok`
/// emit `SessionError::ProtocolViolation` with specific `detail` strings
/// (the variants the producer builds, not synthetic io::Errors). Each must
/// project to the fatal `ProtocolError` exit and render its detail.
///
/// The DCID-mismatch site formats the offending value into a `Cow::Owned`
/// detail (verified separately by `register_ok_dcid_mismatch_carries_value`);
/// the strings iterated here are the common prefixes both producer shapes
/// render, so the substring assertion holds for the literal and the owned
/// shape alike.
#[test]
fn register_ok_failure_variants_are_typed_protocol_violations() {
    use crate::runtime::session::SessionExit;

    for detail in [
        "register_ok client_to_server_cid mismatch",
        "udp-qsp session missing",
    ] {
        let err = SessionError::ProtocolViolation {
            detail: detail.into(),
        };
        assert_eq!(err.exit(), SessionExit::ProtocolError);
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("session protocol violation"),
            "missing stage framing: {rendered:?}"
        );
        assert!(
            rendered.contains(detail),
            "missing producer detail: {rendered:?}"
        );
    }
}

/// The DCID-mismatch producer carries the offending value: the two CIDs are
/// formatted into the `Cow::Owned` detail (not discarded). Pin that both the
/// expected and received CID bytes survive in the terminal `{:#}` render.
#[test]
fn register_ok_dcid_mismatch_carries_offending_value() {
    use slt_core::types::{Cid, MAX_DCID_LEN};

    let expected = Cid::from([0x11; MAX_DCID_LEN]);
    let got = Cid::from([0x22; MAX_DCID_LEN]);
    let err = SessionError::ProtocolViolation {
        detail: format!(
            "register_ok client_to_server_cid mismatch: expected={expected:?}, got={got:?}",
        )
        .into(),
    };
    let rendered = format!("{err:#}");
    // Both offending CID values survive the render (the whole point of
    // widening `detail` to `Cow<'static, str>`). `Cid`'s `Debug` emits the
    // raw byte values, so we assert on the decimal byte values.
    assert!(
        rendered.contains("17, 17, 17, 17"),
        "expected CID bytes missing from render: {rendered:?}"
    );
    assert!(
        rendered.contains("34, 34, 34, 34"),
        "received CID bytes missing from render: {rendered:?}"
    );
}

mod unexpected_message_handling {
    use slt_core::proto::{RegisterFailCode, RegisterFailPayload};

    #[test]
    fn register_fail_payload_with_unknown_decodes() {
        let buf = [u8::from(RegisterFailCode::Unknown)];
        let decoded = RegisterFailPayload::decode(&buf).unwrap();
        assert_eq!(decoded.code, RegisterFailCode::Unknown);
    }

    #[test]
    fn register_fail_payload_with_not_authenticated_decodes() {
        let buf = [u8::from(RegisterFailCode::NotAuthenticated)];
        let decoded = RegisterFailPayload::decode(&buf).unwrap();
        assert_eq!(decoded.code, RegisterFailCode::NotAuthenticated);
    }
}
