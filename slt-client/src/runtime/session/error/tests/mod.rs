use std::io;

use boring::error::ErrorStack;
use slt_core::crypto::udp_qsp::{QspCryptoError, QspSessionError};
use slt_core::proto::{FrameError, MessageError, PayloadError};

use crate::runtime::session::SessionError;
use crate::transport::udp_qsp::UdpQspError;

mod conversions;
mod policy;
mod rendering;
mod udp_qsp;

/// One representative `SessionError` per variant, so coverage tests can't
/// miss a variant. The asserted length is the number of `SessionError`
/// variants; adding a variant without a representative case fails loudly.
fn representative_cases() -> Vec<SessionError> {
    let cases = vec![
        SessionError::ProtocolViolation {
            detail: "unexpected control message".into(),
        },
        SessionError::PermissionDenied {
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        },
        SessionError::UdpUpgradeRequired,
        SessionError::Connection {
            source: io::Error::from(io::ErrorKind::ConnectionReset),
        },
        SessionError::Io(io::Error::other("generic")),
        SessionError::UdpQsp(UdpQspError::from(QspSessionError::Replay)),
        SessionError::Crypto(ErrorStack::internal_error(io::Error::other("rand"))),
        SessionError::UdpQspKeys(QspCryptoError::CryptoFail),
        SessionError::Frame(FrameError::UnknownType(0xFF)),
        SessionError::Message(MessageError::DataTooLarge { len: 10, max: 5 }),
        SessionError::Payload(PayloadError::InvalidCipher(0x99)),
    ];
    assert_eq!(
        cases.len(),
        11,
        "representative_cases must contain exactly 11 cases; update when adding a variant"
    );
    // Distinct variants via a HashSet of Discriminant values (a `Vec::dedup`
    // would only catch *adjacent* duplicates and so could miss a misplaced
    // case). 11 = the number of SessionError variants.
    let distinct: std::collections::HashSet<_> = cases.iter().map(std::mem::discriminant).collect();
    assert_eq!(
        distinct.len(),
        11,
        "representative_cases must cover all 11 distinct SessionError variants exactly once"
    );
    let udp: Vec<&SessionError> = cases
        .iter()
        .filter(|err| matches!(err, SessionError::UdpQsp(_)))
        .collect();
    assert_eq!(
        udp.len(),
        1,
        "expected exactly one UdpQsp representative case"
    );
    assert!(
        udp.iter().any(|err| err.is_udp_qsp_recoverable()),
        "one UdpQsp case must be the recoverable shape"
    );
    cases
}
