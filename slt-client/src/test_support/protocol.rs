//! Protocol message helpers for testing.
//!
//! Provides convenient functions for encoding common message types.

use slt_core::proto::{CloseCode, ClosePayload, Message, PingPayload, encode_message};

/// Create a framed PING message with the given nonce.
///
/// Returns the complete framed message (TYPE + LEN + PAYLOAD).
#[must_use]
pub fn encode_ping(nonce: u64) -> Vec<u8> {
    let payload = PingPayload { nonce };
    let mut buf = Vec::new();
    payload.encode(&mut buf);
    let mut frame = Vec::new();
    encode_message(Message::Ping { payload: &buf }, &mut frame).expect("ping encoding succeeds");
    frame
}

/// Create a framed PONG message with the given nonce.
///
/// Returns the complete framed message (TYPE + LEN + PAYLOAD).
#[must_use]
pub fn encode_pong(nonce: u64) -> Vec<u8> {
    let wire = nonce.to_be_bytes();
    let mut frame = Vec::new();
    encode_message(Message::Pong { payload: &wire }, &mut frame).expect("pong encoding succeeds");
    frame
}

/// Create a framed DATA message with the given packet bytes.
///
/// Returns the complete framed message (TYPE + LEN + PAYLOAD).
#[must_use]
pub fn encode_data(packet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    encode_message(Message::Data { packet }, &mut frame).expect("data encoding succeeds");
    frame
}

/// Create a framed CLOSE message with the given code.
///
/// Returns the complete framed message (TYPE + LEN + PAYLOAD).
#[must_use]
pub fn encode_close(code: CloseCode) -> Vec<u8> {
    let payload = ClosePayload { code };
    let mut buf = Vec::new();
    payload.encode(&mut buf);
    let mut frame = Vec::new();
    encode_message(Message::Close { payload: &buf }, &mut frame).expect("close encoding succeeds");
    frame
}
