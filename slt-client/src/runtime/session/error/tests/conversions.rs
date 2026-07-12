use std::io;

use slt_core::crypto::udp_qsp::QspCryptoError;
use slt_core::proto::FrameError;
use slt_core::transport::tcp::TcpWriteError;

use crate::runtime::session::{SessionError, SessionExit};

/// Pins both arms of `From<TcpWriteError>` so the routing cannot silently
/// regress.
#[test]
fn from_tcp_write_error_routes_frame_fatal_and_io_reconnect() {
    let frame: SessionError = TcpWriteError::Frame(FrameError::UnknownType(1)).into();
    assert!(
        matches!(frame, SessionError::Frame(_)),
        "Frame arm must route to SessionError::Frame, got {frame:?}"
    );
    assert_eq!(
        frame.exit(),
        SessionExit::ProtocolError,
        "SessionError::Frame from TcpWriteError must be fatal (ProtocolError)"
    );

    let io: SessionError =
        TcpWriteError::Io(io::Error::from(io::ErrorKind::ConnectionReset)).into();
    assert!(
        matches!(io, SessionError::Io(_)),
        "Io arm must route to SessionError::Io, got {io:?}"
    );
    assert_eq!(
        io.exit(),
        SessionExit::ConnectionError,
        "SessionError::Io from TcpWriteError must reconnect (ConnectionError)"
    );
}

/// `QspCryptoError` from `UdpQspKeys::new` (the construction-time key
/// derivation in `prepare_udp_qsp_registration`) routes to
/// [`SessionError::UdpQspKeys`]; its `Display` survives to the terminal
/// `{:#}` render, and the variant is fatal.
#[test]
fn udp_qsp_keys_error_preserves_qsp_crypto_error() {
    for err in [
        QspCryptoError::UnsupportedCipher,
        QspCryptoError::CryptoFail,
        QspCryptoError::InvalidHeader,
    ] {
        let rendered_err: SessionError = err.into();
        assert!(
            matches!(rendered_err, SessionError::UdpQspKeys(_)),
            "QspCryptoError must route to UdpQspKeys, got {rendered_err:?}"
        );
        assert_eq!(
            rendered_err.exit(),
            SessionExit::ProtocolError,
            "UdpQspKeys must be fatal"
        );
        let rendered = format!("{rendered_err:#}");
        let cause = format!("{err}");
        assert!(
            rendered.contains(&cause),
            "QspCryptoError cause missing from render: {rendered:?}"
        );
        assert!(
            rendered.contains("udp-qsp key derivation failed"),
            "missing stage framing: {rendered:?}"
        );
    }
}
