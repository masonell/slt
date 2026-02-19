use std::io;

use slt_core::proto::{FrameError, MessageError, PayloadError};

/// Map a protocol framing error into an `io::Error`.
///
/// Converts `FrameError` variants into `io::Error` with `InvalidData` kind,
/// preserving the original error context in the message.
///
/// # Arguments
///
/// * `err` - The framing error to convert
///
/// # Returns
///
/// An `io::Error` with `InvalidData` kind containing the framing error details.
pub fn map_frame_error(err: FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("frame error: {err:?}"))
}

/// Map a protocol message error into an `io::Error`.
///
/// Converts `MessageError` variants into `io::Error` with `InvalidData` kind,
/// preserving the original error context in the message.
///
/// # Arguments
///
/// * `err` - The message error to convert
///
/// # Returns
///
/// An `io::Error` with `InvalidData` kind containing the message error details.
pub fn map_message_error(err: MessageError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("message error: {err:?}"),
    )
}

/// Map a protocol payload decode error into an `io::Error`.
///
/// Converts `PayloadError` variants into `io::Error` with `InvalidData` kind,
/// preserving the original error context in the message.
///
/// # Arguments
///
/// * `err` - The payload error to convert
///
/// # Returns
///
/// An `io::Error` with `InvalidData` kind containing the payload error details.
pub fn map_payload_error(err: PayloadError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("payload error: {err:?}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_io_error(err: &io::Error, expected_kind: io::ErrorKind, prefix: &str) {
        assert_eq!(err.kind(), expected_kind);
        let msg = err.to_string();
        assert!(
            msg.starts_with(prefix),
            "error message '{msg}' should start with '{prefix}'"
        );
    }

    mod frame_error {
        use super::*;

        #[test]
        fn maps_unknown_type() {
            let err = map_frame_error(FrameError::UnknownType(0xFF));
            assert_io_error(&err, io::ErrorKind::InvalidData, "frame error: ");
            assert!(err.to_string().contains("UnknownType"));
            assert!(err.to_string().contains("255"));
        }

        #[test]
        fn maps_length_too_large() {
            let err = map_frame_error(FrameError::LengthTooLarge {
                len: 65536,
                max: 16384,
            });
            assert_io_error(&err, io::ErrorKind::InvalidData, "frame error: ");
            assert!(err.to_string().contains("LengthTooLarge"));
            assert!(err.to_string().contains("65536"));
            assert!(err.to_string().contains("16384"));
        }

        #[test]
        fn maps_length_overflow() {
            let err = map_frame_error(FrameError::LengthOverflow(usize::MAX));
            assert_io_error(&err, io::ErrorKind::InvalidData, "frame error: ");
            assert!(err.to_string().contains("LengthOverflow"));
        }
    }

    mod message_error {
        use super::*;

        #[test]
        fn maps_frame_error() {
            let frame_err = FrameError::UnknownType(0xAB);
            let err = map_message_error(MessageError::Frame(frame_err));
            assert_io_error(&err, io::ErrorKind::InvalidData, "message error: ");
            assert!(err.to_string().contains("Frame"));
            assert!(err.to_string().contains("UnknownType"));
        }

        #[test]
        fn maps_data_too_large() {
            let err = map_message_error(MessageError::DataTooLarge {
                len: 10000,
                max: 1500,
            });
            assert_io_error(&err, io::ErrorKind::InvalidData, "message error: ");
            assert!(err.to_string().contains("DataTooLarge"));
            assert!(err.to_string().contains("10000"));
            assert!(err.to_string().contains("1500"));
        }
    }

    mod payload_error {
        use super::*;

        #[test]
        fn maps_length_mismatch() {
            let err = map_payload_error(PayloadError::LengthMismatch {
                expected: 32,
                actual: 16,
            });
            assert_io_error(&err, io::ErrorKind::InvalidData, "payload error: ");
            assert!(err.to_string().contains("LengthMismatch"));
            assert!(err.to_string().contains("32"));
            assert!(err.to_string().contains("16"));
        }

        #[test]
        fn maps_length_too_short() {
            let err = map_payload_error(PayloadError::LengthTooShort { min: 8, actual: 4 });
            assert_io_error(&err, io::ErrorKind::InvalidData, "payload error: ");
            assert!(err.to_string().contains("LengthTooShort"));
        }

        #[test]
        fn maps_invalid_dcid_len() {
            let err = map_payload_error(PayloadError::InvalidClientToServerCidLen(5));
            assert_io_error(&err, io::ErrorKind::InvalidData, "payload error: ");
            assert!(err.to_string().contains("InvalidClientToServerCidLen"));
            assert!(err.to_string().contains("5"));
        }

        #[test]
        fn maps_invalid_scid_len() {
            let err = map_payload_error(PayloadError::InvalidServerToClientCidLen(9));
            assert_io_error(&err, io::ErrorKind::InvalidData, "payload error: ");
            assert!(err.to_string().contains("InvalidServerToClientCidLen"));
        }

        #[test]
        fn maps_invalid_cipher() {
            let err = map_payload_error(PayloadError::InvalidCipher(0x99));
            assert_io_error(&err, io::ErrorKind::InvalidData, "payload error: ");
            assert!(err.to_string().contains("InvalidCipher"));
        }

        #[test]
        fn maps_invalid_auth_fail_code() {
            let err = map_payload_error(PayloadError::InvalidAuthFailCode(0x05));
            assert_io_error(&err, io::ErrorKind::InvalidData, "payload error: ");
            assert!(err.to_string().contains("InvalidAuthFailCode"));
        }

        #[test]
        fn maps_invalid_register_fail_code() {
            let err = map_payload_error(PayloadError::InvalidRegisterFailCode(0x03));
            assert_io_error(&err, io::ErrorKind::InvalidData, "payload error: ");
            assert!(err.to_string().contains("InvalidRegisterFailCode"));
        }

        #[test]
        fn maps_invalid_close_code() {
            let err = map_payload_error(PayloadError::InvalidCloseCode(0xFF));
            assert_io_error(&err, io::ErrorKind::InvalidData, "payload error: ");
            assert!(err.to_string().contains("InvalidCloseCode"));
        }

        #[test]
        fn maps_invalid_key_phase() {
            let err = map_payload_error(PayloadError::InvalidKeyPhase(2));
            assert_io_error(&err, io::ErrorKind::InvalidData, "payload error: ");
            assert!(err.to_string().contains("InvalidKeyPhase"));
        }
    }
}
