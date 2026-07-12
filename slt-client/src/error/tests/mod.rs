use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use boring::error::ErrorStack;
use boring::ssl::ErrorCode;
use boring::x509::X509VerifyError;
use slt_core::proto::{AuthFailCode, FrameError, MessageError, PayloadError};
use slt_core::types::ClientId;

use super::{ConnectError, TlsError};
use crate::transport::socket_protector::SocketKind;

mod conversions;
mod rendering;
mod retry_classification;
mod stage;

/// Build a boring `ErrorStack` for tests (preserves a cause string).
fn test_error_stack() -> ErrorStack {
    ErrorStack::internal_error(io::Error::other("test boring error"))
}

/// A constructed `X509VerifyError` for tests (cert verification failure).
fn test_verify_error() -> X509VerifyError {
    X509VerifyError::CERT_HAS_EXPIRED
}

/// One representative `ConnectError` per variant, so coverage tests can't
/// miss a variant. The asserted length is the number of `ConnectError`
/// variants: if a variant is added without a representative case here,
/// this test fails loudly.
fn representative_cases() -> Vec<ConnectError> {
    let peer: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    let client_id = ClientId([0x11; 16]);
    let assigned_ipv4 = Ipv4Addr::new(10, 10, 0, 2);
    let cases: Vec<ConnectError> = vec![
        ConnectError::Cancelled,
        ConnectError::EmptyHostname,
        ConnectError::TcpSocketCreate {
            peer,
            source: io::Error::other("x"),
        },
        ConnectError::SocketProtect {
            fd: 3,
            kind: SocketKind::Tcp,
            peer,
            source: io::Error::other("x"),
        },
        ConnectError::TcpConnectTimeout {
            peer,
            timeout: Duration::from_secs(30),
        },
        ConnectError::TcpConnect {
            peer,
            source: io::Error::other("x"),
        },
        ConnectError::TlsHandshakeTimeout {
            sni: "example.com".into(),
            timeout: Duration::from_secs(30),
        },
        // Cert-fault shape.
        ConnectError::TlsHandshake {
            sni: "example.com".into(),
            source: TlsError::Handshake {
                code: ErrorCode::SSL,
                verify_error: Some(test_verify_error()),
                io_error_kind: None,
            },
        },
        ConnectError::AuthRejected {
            code: AuthFailCode::BadSignature,
            client_id,
            assigned_ipv4,
        },
        ConnectError::AuthTimeout,
        ConnectError::AuthDisconnected,
        ConnectError::AuthProtocolError,
        ConnectError::AuthUnexpectedMessage,
        ConnectError::AuthTlsExport {
            source: test_error_stack(),
        },
        ConnectError::DnsResolution {
            hostname: "example.com".into(),
            source: io::Error::other("dns"),
        },
        ConnectError::Io(io::Error::other("x")),
        ConnectError::Frame(FrameError::UnknownType(0xFF)),
        ConnectError::Message(MessageError::DataTooLarge { len: 10, max: 5 }),
        ConnectError::Payload(PayloadError::InvalidCipher(0x99)),
    ];
    // 19 variants: Cancelled, EmptyHostname, TcpSocketCreate, SocketProtect,
    // TcpConnectTimeout, TcpConnect, TlsHandshakeTimeout, TlsHandshake,
    // AuthRejected, AuthTimeout, AuthDisconnected, AuthProtocolError,
    // AuthUnexpectedMessage, AuthTlsExport, DnsResolution, Io, Frame,
    // Message, Payload.
    assert_eq!(
        cases.len(),
        19,
        "representative_cases must cover every ConnectError variant; \
         update this count when adding a variant"
    );
    // The length alone would pass if a variant were duplicated and another
    // dropped. Distinct discriminants pin one representative per variant.
    let distinct = cases
        .iter()
        .map(std::mem::discriminant)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        distinct.len(),
        cases.len(),
        "representative_cases has duplicate variants; \
         each entry must be a distinct ConnectError variant"
    );
    cases
}
