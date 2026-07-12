use std::io;

use slt_core::proto::{FrameError, MessageError, PayloadError};

use crate::runtime::session::SessionError;

/// The proto decode sources flow to the terminal `{:#}` render with their
/// structured payload detail intact.
#[test]
fn proto_sources_are_preserved_in_display() {
    let frame = SessionError::Frame(FrameError::UnknownType(0xAB));
    let rendered = format!("{frame:#}");
    assert!(
        rendered.contains("unknown frame type"),
        "frame: {rendered:?}"
    );
    assert!(rendered.contains("0xab"), "frame: {rendered:?}");

    let msg = SessionError::Message(MessageError::DataTooLarge {
        len: 9999,
        max: 1500,
    });
    let rendered = format!("{msg:#}");
    assert!(
        rendered.contains("data payload length"),
        "msg: {rendered:?}"
    );
    assert!(rendered.contains("9999"), "msg: {rendered:?}");
    assert!(rendered.contains("1500"), "msg: {rendered:?}");

    let payload = SessionError::Payload(PayloadError::InvalidCipher(0x99));
    let rendered = format!("{payload:#}");
    assert!(
        rendered.contains("unknown cipher suite"),
        "payload: {rendered:?}"
    );
    assert!(rendered.contains("0x99"), "payload: {rendered:?}");
}

/// The terminal renders useful, stage-specific detail (peer-relevant values,
/// the offending byte, etc.).
#[test]
fn terminal_renders_useful_detail() {
    let err = SessionError::Connection {
        source: io::Error::other("connection reset by peer"),
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("session connection error"),
        "connection detail missing stage: {rendered:?}"
    );
    assert!(
        rendered.contains("connection reset"),
        "connection detail missing source: {rendered:?}"
    );

    let err = SessionError::PermissionDenied {
        source: io::Error::other("protectSocket returned false"),
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("denied"),
        "permission detail missing stage: {rendered:?}"
    );
    assert!(
        rendered.contains("protectSocket"),
        "permission detail missing source: {rendered:?}"
    );
}
