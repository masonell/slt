use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use boring::ssl::ErrorCode;
use slt_core::proto::{AuthFailCode, FrameError, MessageError, PayloadError};
use slt_core::types::ClientId;

use super::{test_error_stack, test_verify_error};
use crate::error::{ConnectError, TlsError};
use crate::transport::socket_protector::{SocketKind, SocketProtectionResult};

/// The TLS cert/transient-IO split must classify each `TlsError` shape
/// correctly. A captured X.509 verification error is always fatal (even when
/// accompanied by an I/O error); an I/O error or Boring transport-loss code
/// without a cert fault is transient; everything else (setup, bare SSL
/// protocol errors) is fatal.
#[test]
fn tls_error_is_transient_io_classifies_each_shape() {
    // Setup fault → fatal.
    assert!(!TlsError::Setup(test_error_stack()).is_transient_io());

    // Cert verification failure → fatal, regardless of I/O.
    assert!(
        !TlsError::Handshake {
            code: ErrorCode::SSL,
            verify_error: Some(test_verify_error()),
            io_error_kind: None,
        }
        .is_transient_io()
    );
    // Adversarial: cert fault AND an io error — cert wins, still fatal.
    assert!(
        !TlsError::Handshake {
            code: ErrorCode::SSL,
            verify_error: Some(test_verify_error()),
            io_error_kind: Some(io::ErrorKind::ConnectionReset),
        }
        .is_transient_io()
    );

    // Transient I/O, no cert fault → retriable.
    assert!(
        TlsError::Handshake {
            code: ErrorCode::SYSCALL,
            verify_error: None,
            io_error_kind: Some(io::ErrorKind::ConnectionReset),
        }
        .is_transient_io()
    );

    // Boring may report mobile-link transport loss without surfacing an
    // io::Error through tokio-boring.
    assert!(
        TlsError::Handshake {
            code: ErrorCode::SYSCALL,
            verify_error: None,
            io_error_kind: None,
        }
        .is_transient_io()
    );
    assert!(
        TlsError::Handshake {
            code: ErrorCode::ZERO_RETURN,
            verify_error: None,
            io_error_kind: None,
        }
        .is_transient_io()
    );

    // No cert fault, no I/O (bare SSL protocol error) → fatal (safe default).
    assert!(
        !TlsError::Handshake {
            code: ErrorCode::SSL,
            verify_error: None,
            io_error_kind: None,
        }
        .is_transient_io()
    );
}

/// The retry/fatal policy, pinned per variant and relevant source kind.
#[test]
fn is_retriable_matches_policy_table() {
    let peer: SocketAddr = "127.0.0.1:8443".parse().unwrap();

    // Fatal.
    assert!(!ConnectError::Cancelled.is_retriable());
    assert!(!ConnectError::EmptyHostname.is_retriable());
    assert!(
        !ConnectError::TcpSocketCreate {
            peer,
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        }
        .is_retriable()
    );
    assert!(
        !ConnectError::SocketProtect {
            fd: 3,
            kind: SocketKind::Tcp,
            peer,
            source: SocketProtectionResult::ProtectRejected
                .into_io_result(3, SocketKind::Tcp)
                .unwrap_err(),
        }
        .is_retriable()
    );
    assert!(
        !ConnectError::SocketProtect {
            fd: 3,
            kind: SocketKind::Tcp,
            peer,
            source: SocketProtectionResult::PlatformFailure
                .into_io_result(3, SocketKind::Tcp)
                .unwrap_err(),
        }
        .is_retriable()
    );
    assert!(
        !ConnectError::AuthRejected {
            code: AuthFailCode::BadSignature,
            client_id: ClientId([0; 16]),
            assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
        }
        .is_retriable()
    );
    assert!(!ConnectError::AuthProtocolError.is_retriable());
    assert!(!ConnectError::AuthUnexpectedMessage.is_retriable());
    assert!(
        !ConnectError::AuthTlsExport {
            source: test_error_stack(),
        }
        .is_retriable()
    );
    assert!(!ConnectError::Frame(FrameError::UnknownType(1)).is_retriable());
    assert!(!ConnectError::Message(MessageError::DataTooLarge { len: 10, max: 5 }).is_retriable());
    assert!(!ConnectError::Payload(PayloadError::InvalidCipher(0x99)).is_retriable());

    // TLS: cert/setup fault (fatal).
    assert!(
        !ConnectError::TlsHandshake {
            sni: "h".into(),
            source: TlsError::Setup(test_error_stack()),
        }
        .is_retriable()
    );
    assert!(
        !ConnectError::TlsHandshake {
            sni: "h".into(),
            source: TlsError::Handshake {
                code: ErrorCode::SSL,
                verify_error: Some(test_verify_error()),
                io_error_kind: None,
            },
        }
        .is_retriable()
    );
    // TLS: transient I/O (retriable).
    assert!(
        ConnectError::TlsHandshake {
            sni: "h".into(),
            source: TlsError::Handshake {
                code: ErrorCode::SYSCALL,
                verify_error: None,
                io_error_kind: Some(io::ErrorKind::ConnectionReset),
            },
        }
        .is_retriable()
    );
    assert!(
        ConnectError::TlsHandshake {
            sni: "h".into(),
            source: TlsError::Handshake {
                code: ErrorCode::SYSCALL,
                verify_error: None,
                io_error_kind: None,
            },
        }
        .is_retriable()
    );

    // Retry.
    assert!(
        ConnectError::SocketProtect {
            fd: 3,
            kind: SocketKind::Tcp,
            peer,
            source: SocketProtectionResult::NoUnderlyingNetwork
                .into_io_result(3, SocketKind::Tcp)
                .unwrap_err(),
        }
        .is_retriable()
    );
    assert!(
        ConnectError::SocketProtect {
            fd: 3,
            kind: SocketKind::Tcp,
            peer,
            source: SocketProtectionResult::BindFailed
                .into_io_result(3, SocketKind::Tcp)
                .unwrap_err(),
        }
        .is_retriable()
    );
    assert!(
        ConnectError::TcpConnectTimeout {
            peer,
            timeout: Duration::from_secs(30),
        }
        .is_retriable()
    );
    assert!(
        ConnectError::TcpConnect {
            peer,
            source: io::Error::from(io::ErrorKind::ConnectionRefused),
        }
        .is_retriable()
    );
    // PermissionDenied from connect(2) is a firewall/platform policy block
    // (non-transient) — fatal, not retried indefinitely.
    assert!(
        !ConnectError::TcpConnect {
            peer,
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        }
        .is_retriable()
    );
    assert!(ConnectError::AuthTimeout.is_retriable());
    assert!(ConnectError::AuthDisconnected.is_retriable());
    assert!(
        ConnectError::TlsHandshakeTimeout {
            sni: "h".into(),
            timeout: Duration::from_secs(30),
        }
        .is_retriable()
    );
    // DNS is retriable: the resolver cannot distinguish a permanent typo
    // from a transient failure.
    assert!(
        ConnectError::DnsResolution {
            hostname: "example.com".into(),
            source: io::Error::from(io::ErrorKind::NotFound),
        }
        .is_retriable()
    );
    assert!(ConnectError::Io(io::Error::other("x")).is_retriable());
    assert!(!ConnectError::Io(io::Error::from(io::ErrorKind::PermissionDenied)).is_retriable());
}
