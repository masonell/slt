use std::io;

use boring::error::ErrorStack;
use slt_core::crypto::udp_qsp::{QspCryptoError, QspSessionError};
use slt_core::proto::{FrameError, MessageError, PayloadError};
use tokio_util::sync::CancellationToken;

use super::representative_cases;
use crate::runtime::session::{SessionError, SessionExit, SessionOutcome};
use crate::runtime::{SessionAction, handle_session_exit};
use crate::transport::udp_qsp::UdpQspError;

/// Every variant must project to one of the known `SessionExit` reasons.
/// Pins the `exit()` mapping so a careless edit is caught loudly.
#[test]
fn exit_is_defined_for_every_variant() {
    for err in representative_cases() {
        let exit = err.exit();
        assert!(
            matches!(
                exit,
                SessionExit::ProtocolError
                    | SessionExit::PermissionDenied
                    | SessionExit::UdpUpgradeRequired
                    | SessionExit::ConnectionError
            ),
            "variant {err:?} projected to unexpected exit {exit:?}"
        );
    }
}

/// The fatal-vs-reconnect projection, pinned per variant. Guardrail against
/// re-introducing `ErrorKind`-based guesswork on the session path.
#[test]
fn exit_matches_policy_table() {
    assert_eq!(
        SessionError::ProtocolViolation { detail: "x".into() }.exit(),
        SessionExit::ProtocolError
    );
    assert_eq!(
        SessionError::PermissionDenied {
            source: io::Error::from(io::ErrorKind::PermissionDenied)
        }
        .exit(),
        SessionExit::PermissionDenied
    );
    assert_eq!(
        SessionError::UdpUpgradeRequired.exit(),
        SessionExit::UdpUpgradeRequired
    );
    assert_eq!(
        SessionError::Frame(FrameError::UnknownType(1)).exit(),
        SessionExit::ProtocolError
    );
    assert_eq!(
        SessionError::Message(MessageError::DataTooLarge { len: 9, max: 1 }).exit(),
        SessionExit::ProtocolError
    );
    assert_eq!(
        SessionError::Crypto(ErrorStack::internal_error(io::Error::other("x"))).exit(),
        SessionExit::ProtocolError
    );
    assert_eq!(
        SessionError::UdpQspKeys(QspCryptoError::CryptoFail).exit(),
        SessionExit::ProtocolError
    );

    assert_eq!(
        SessionError::Connection {
            source: io::Error::from(io::ErrorKind::ConnectionReset)
        }
        .exit(),
        SessionExit::ConnectionError
    );
    assert_eq!(
        SessionError::Connection {
            source: io::Error::from(io::ErrorKind::PermissionDenied)
        }
        .exit(),
        SessionExit::PermissionDenied
    );
    assert_eq!(
        SessionError::Io(io::Error::other("x")).exit(),
        SessionExit::ConnectionError
    );
    assert_eq!(
        SessionError::Io(io::Error::from(io::ErrorKind::PermissionDenied)).exit(),
        SessionExit::PermissionDenied
    );
    assert_eq!(
        SessionError::Payload(PayloadError::InvalidCipher(0x99)).exit(),
        SessionExit::ProtocolError
    );
    assert_eq!(
        SessionError::UdpQsp(UdpQspError::from(QspSessionError::PacketNumberOverflow)).exit(),
        SessionExit::ConnectionError
    );
}

/// A protocol error must be distinct from a connection error: classification
/// is by stage, not by `ErrorKind`.
#[test]
fn protocol_and_connection_errors_are_distinct() {
    assert_ne!(
        SessionError::ProtocolViolation { detail: "x".into() }.exit(),
        SessionError::Connection {
            source: io::Error::other("net")
        }
        .exit()
    );
}

/// Each `SessionError`'s effective runtime action must match the intended
/// fatal/reconnect policy after composing `SessionError::exit()` with
/// `handle_session_exit`.
#[test]
fn session_error_effective_action_matches_policy() {
    let cancel = CancellationToken::new();
    for err in representative_cases() {
        let disc = std::mem::discriminant(&err);
        let exit = err.exit();
        let outcome = SessionOutcome::from_error(err);
        let action = handle_session_exit(outcome, &cancel);
        let is_fatal = matches!(action, SessionAction::Fatal(_));
        let is_reconnect = matches!(action, SessionAction::Reconnect);

        let expected_fatal = matches!(
            exit,
            SessionExit::ProtocolError
                | SessionExit::PermissionDenied
                | SessionExit::UdpUpgradeRequired
        );
        let expected_reconnect = matches!(exit, SessionExit::ConnectionError);

        assert!(
            expected_fatal != expected_reconnect,
            "test harness bug: exit {exit:?} is neither fatal nor reconnect"
        );
        assert_eq!(
            is_fatal, expected_fatal,
            "variant {disc:?} fatal-policy mismatch (is_fatal={is_fatal}, exit={exit:?})"
        );
        assert_eq!(
            is_reconnect, expected_reconnect,
            "variant {disc:?} reconnect-policy mismatch \
             (is_reconnect={is_reconnect}, exit={exit:?})"
        );
    }
}
