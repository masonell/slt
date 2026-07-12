use std::io;
use std::net::SocketAddr;

use super::representative_cases;
use crate::error::{ConnectError, Stage};

/// Every variant's `stage()` must be one of the documented stages, and the
/// match in `stage()` must be exhaustive (the compiler enforces this, but
/// this test pins the mapping so a careless edit is caught loudly).
#[test]
fn stage_is_defined_for_a_representative_variant_per_branch() {
    for err in representative_cases() {
        // Every representative case must map to one of the known stages —
        // exhaustive coverage is enforced separately by `representative_cases`
        // asserting its length equals the variant count.
        let stage = err.stage();
        assert!(
            matches!(
                stage,
                Stage::Config
                    | Stage::TcpSocketCreate
                    | Stage::SocketProtect
                    | Stage::TcpConnect
                    | Stage::TlsHandshake
                    | Stage::Auth
                    | Stage::Cancelled
            ),
            "variant {err:?} mapped to unknown stage {stage:?}"
        );
    }

    // Spot-check a few specific mappings that matter for log grouping.
    let peer: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    assert_eq!(ConnectError::Cancelled.stage(), Stage::Cancelled);
    assert_eq!(ConnectError::EmptyHostname.stage(), Stage::Config);
    assert_eq!(
        ConnectError::TcpSocketCreate {
            peer,
            source: io::Error::other("x")
        }
        .stage(),
        Stage::TcpSocketCreate
    );
    assert_eq!(ConnectError::AuthProtocolError.stage(), Stage::Auth);
    assert_eq!(ConnectError::AuthUnexpectedMessage.stage(), Stage::Auth);
    assert_eq!(
        ConnectError::Io(io::Error::other("x")).stage(),
        Stage::TcpConnect
    );
}
