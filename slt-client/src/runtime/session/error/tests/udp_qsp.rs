use std::io;

use boring::error::ErrorStack;
use slt_core::crypto::udp_qsp::{QspCryptoError, QspSessionError};
use slt_core::proto::{FrameError, MessageError, PayloadError};

use crate::runtime::session::{SessionError, SessionExit};
use crate::transport::udp_qsp::UdpQspError;

/// The typed UDP-QSP recoverable projection must classify each
/// `UdpQspError` shape correctly. Also pins
/// [`SessionError::is_udp_path_transport_error`] — the gate used at the UDP
/// write, flush, TUN-packet, and upgrade-probe call sites.
#[test]
fn udp_qsp_projections_classify_each_shape() {
    let recoverable: SessionError = UdpQspError::from(QspSessionError::Replay).into();
    assert!(recoverable.is_udp_qsp_recoverable());
    let too_old: SessionError = UdpQspError::from(QspSessionError::TooOld).into();
    assert!(too_old.is_udp_qsp_recoverable());
    let crypto: SessionError =
        UdpQspError::from(QspSessionError::Crypto(QspCryptoError::CryptoFail)).into();
    assert!(crypto.is_udp_qsp_recoverable());

    let overflow: SessionError = UdpQspError::from(QspSessionError::PacketNumberOverflow).into();
    assert!(!overflow.is_udp_qsp_recoverable());

    let send_io: SessionError = UdpQspError::SendIo {
        source: io::Error::from(io::ErrorKind::TimedOut),
    }
    .into();
    assert!(!send_io.is_udp_qsp_recoverable());
    assert!(send_io.is_udp_path_transport_error());

    let frame: SessionError = UdpQspError::from(FrameError::UnknownType(0xFF)).into();
    assert!(matches!(frame, SessionError::Frame(_)));
    assert_eq!(frame.exit(), SessionExit::ProtocolError);
    assert!(!frame.is_udp_path_transport_error());

    let message: SessionError =
        UdpQspError::from(MessageError::DataTooLarge { len: 10, max: 5 }).into();
    assert!(matches!(message, SessionError::Message(_)));
    assert_eq!(message.exit(), SessionExit::ProtocolError);
    assert!(!message.is_udp_path_transport_error());

    let incomplete: SessionError = UdpQspError::IncompleteMessage.into();
    assert!(matches!(incomplete, SessionError::ProtocolViolation { .. }));
    assert_eq!(incomplete.exit(), SessionExit::ProtocolError);
    assert!(!incomplete.is_udp_path_transport_error());

    let proto = SessionError::Payload(PayloadError::InvalidCipher(0x99));
    assert!(!proto.is_udp_qsp_recoverable());

    assert!(recoverable.is_udp_path_transport_error());
    assert!(overflow.is_udp_path_transport_error());
    assert!(
        SessionError::from(io::Error::other("udp flush socket I/O")).is_udp_path_transport_error()
    );
    assert!(!proto.is_udp_path_transport_error());
    assert!(!SessionError::ProtocolViolation { detail: "x".into() }.is_udp_path_transport_error());
    assert!(
        !SessionError::Crypto(ErrorStack::internal_error(io::Error::other("rand")))
            .is_udp_path_transport_error()
    );
    assert!(!SessionError::UdpQspKeys(QspCryptoError::CryptoFail).is_udp_path_transport_error());
    assert!(!SessionError::Frame(FrameError::UnknownType(0x01)).is_udp_path_transport_error());
}

/// Packet-number overflow is a non-recoverable UDP-path transport error that
/// falls back to TCP when available and otherwise closes the session.
#[test]
fn overflow_routes_to_fatal_transport_path() {
    let overflow: SessionError = UdpQspError::from(QspSessionError::PacketNumberOverflow).into();

    assert!(
        overflow.is_udp_path_transport_error(),
        "overflow must be a UDP-path transport error"
    );
    assert!(
        !overflow.is_udp_qsp_recoverable(),
        "overflow must NOT be recoverable (would silently drop packets)"
    );
    assert_eq!(overflow.exit(), SessionExit::ConnectionError);
}
