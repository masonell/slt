//! Framed VPN message channel over an established TLS stream.

use std::io;
use std::num::NonZeroU64;

use boring::error::ErrorStack;
use boring::ssl::SslRef;
use foreign_types::ForeignTypeRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_boring::SslStream;

use crate::proto::{
    FrameError, Message, MessageError, MessageLimits, MessageType, OwnedMessageBuf, decode_frame,
    encode_message,
};

/// Hook invoked by `TcpChannel` before each outbound application message.
pub trait KeyUpdater {
    /// Optionally request TLS key update before writing the next message.
    ///
    /// Implementations can use `ssl` to trigger `KeyUpdate` or keep per-channel
    /// counters and return without action.
    ///
    /// # Errors
    ///
    /// Return an error to fail the current write.
    fn maybe_request_key_update(&mut self, _ssl: &mut SslRef) -> io::Result<()> {
        Ok(())
    }
}

/// Default key-updater that never triggers TLS key updates.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopKeyUpdater;

impl KeyUpdater for NoopKeyUpdater {}

/// Key-updater that requests TLS `KeyUpdate` every N outbound messages.
#[derive(Debug, Clone, Copy)]
pub struct IntervalKeyUpdater {
    interval: NonZeroU64,
    until_update: u64,
    request_peer_update: bool,
}

impl IntervalKeyUpdater {
    /// Create an updater that requests key update every `interval` messages.
    #[must_use]
    pub const fn new(interval: NonZeroU64) -> Self {
        let initial = interval.get();
        Self {
            interval,
            until_update: initial,
            request_peer_update: false,
        }
    }

    /// Configure whether peer should also update its sending keys.
    ///
    /// When true, requests `SSL_KEY_UPDATE_REQUESTED`; otherwise uses
    /// `SSL_KEY_UPDATE_NOT_REQUESTED`.
    #[must_use]
    pub const fn with_peer_response_requested(mut self, request_peer_update: bool) -> Self {
        self.request_peer_update = request_peer_update;
        self
    }

    /// Return how many outbound messages remain before the next key update.
    #[must_use]
    pub const fn messages_until_update(&self) -> u64 {
        self.until_update
    }

    /// Return whether peer key update is requested on key-update frames.
    #[must_use]
    pub const fn requests_peer_update(&self) -> bool {
        self.request_peer_update
    }

    /// Simulate a message tick without triggering actual TLS key update.
    ///
    /// Returns `true` when the countdown reaches zero (an update would be triggered).
    /// This is primarily for testing the countdown logic.
    #[cfg(test)]
    #[must_use]
    pub const fn tick(&mut self) -> bool {
        if self.until_update > 1 {
            self.until_update -= 1;
            false
        } else {
            self.until_update = self.interval.get();
            true
        }
    }

    /// Reset the countdown to the initial interval.
    #[cfg(test)]
    pub const fn reset(&mut self) {
        self.until_update = self.interval.get();
    }
}

impl KeyUpdater for IntervalKeyUpdater {
    fn maybe_request_key_update(&mut self, ssl: &mut SslRef) -> io::Result<()> {
        if self.until_update > 1 {
            self.until_update -= 1;
            return Ok(());
        }

        request_tls_key_update(ssl, self.request_peer_update)?;
        self.until_update = self.interval.get();
        Ok(())
    }
}

/// Default number of outbound TCP messages per TLS key update.
///
/// Uses the same cadence scale as UDP-QSP key updates.
pub const TCP_TLS_KEY_UPDATE_INTERVAL_MESSAGES: u64 = 1 << 21;
/// Whether TCP TLS key updates should request peer key updates immediately.
pub const TCP_TLS_KEY_UPDATE_REQUEST_PEER_RESPONSE: bool = false;
const TCP_TLS_KEY_UPDATE_INTERVAL_NONZERO: NonZeroU64 =
    NonZeroU64::new(TCP_TLS_KEY_UPDATE_INTERVAL_MESSAGES).unwrap();

/// Build the default TCP TLS interval key updater used by client and server.
#[must_use]
pub const fn default_interval_key_updater() -> IntervalKeyUpdater {
    IntervalKeyUpdater::new(TCP_TLS_KEY_UPDATE_INTERVAL_NONZERO)
        .with_peer_response_requested(TCP_TLS_KEY_UPDATE_REQUEST_PEER_RESPONSE)
}

/// TCP framed channel over an established `SslStream`.
#[derive(Debug)]
pub struct TcpChannel<S, K = NoopKeyUpdater> {
    stream: SslStream<S>,
    key_updater: K,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl<S> TcpChannel<S, NoopKeyUpdater> {
    /// Create a new channel with an empty read buffer and no key updates.
    #[must_use]
    pub const fn new(stream: SslStream<S>) -> Self {
        Self {
            stream,
            key_updater: NoopKeyUpdater,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        }
    }

    /// Create a new channel with pre-buffered plaintext input.
    #[must_use]
    pub const fn with_read_buffer(stream: SslStream<S>, read_buf: Vec<u8>) -> Self {
        Self {
            stream,
            key_updater: NoopKeyUpdater,
            read_buf,
            write_buf: Vec::new(),
        }
    }
}

impl<S, K: KeyUpdater> TcpChannel<S, K> {
    /// Create a new channel with a custom key updater.
    #[must_use]
    pub const fn with_key_updater(stream: SslStream<S>, key_updater: K) -> Self {
        Self {
            stream,
            key_updater,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        }
    }

    /// Create a channel with custom key updater and pre-buffered input.
    #[must_use]
    pub const fn with_state(stream: SslStream<S>, key_updater: K, read_buf: Vec<u8>) -> Self {
        Self {
            stream,
            key_updater,
            read_buf,
            write_buf: Vec::new(),
        }
    }

    /// Returns true if there are buffered plaintext bytes ready for parsing.
    #[must_use]
    pub const fn has_buffered_input(&self) -> bool {
        !self.read_buf.is_empty()
    }

    /// Returns the TLS session handle.
    #[must_use]
    pub fn ssl(&self) -> &SslRef {
        self.stream.ssl()
    }

    /// Returns a mutable TLS session handle.
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        self.stream.ssl_mut()
    }

    /// Returns an immutable reference to the key updater.
    #[must_use]
    pub const fn key_updater(&self) -> &K {
        &self.key_updater
    }

    /// Returns a mutable reference to the key updater.
    #[must_use]
    pub const fn key_updater_mut(&mut self) -> &mut K {
        &mut self.key_updater
    }

    /// Consume the channel and return the underlying `SslStream`.
    #[must_use]
    pub fn into_inner(self) -> SslStream<S> {
        self.stream
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin, K: KeyUpdater> TcpChannel<S, K> {
    /// Read more plaintext bytes from TLS into the internal buffer.
    ///
    /// `read_buf` has no cap here: an oversized frame header is rejected by
    /// `decode_frame` on the next `try_pop_message`, before its payload can
    /// accumulate. Callers pair each `read_more` with a draining
    /// `try_pop_message` loop, so growth stays bounded by `max_frame_len`.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the underlying TLS stream fails.
    pub async fn read_more(&mut self) -> io::Result<usize> {
        self.stream.read_buf(&mut self.read_buf).await
    }

    /// Attempt to pop the next message from the internal read buffer.
    ///
    /// # Errors
    ///
    /// Returns a protocol error if the buffered bytes contain an invalid frame.
    pub fn try_pop_message(
        &mut self,
        limits: MessageLimits,
    ) -> Result<Option<OwnedMessageBuf>, MessageError> {
        pop_message_buf(&mut self.read_buf, limits)
    }

    /// Encode and write a protocol message on the TLS stream.
    ///
    /// # Errors
    ///
    /// Returns a [`TcpWriteError`], which preserves both failure sources
    /// unchanged: a frame-encode failure as [`TcpWriteError::Frame`] (the typed
    /// slt-core `FrameError`) and a TLS write failure as [`TcpWriteError::Io`]
    /// (the underlying `io::Error`). Neither is stringified into `io::Error`.
    pub async fn write_message(&mut self, message: Message<'_>) -> Result<(), TcpWriteError> {
        self.key_updater
            .maybe_request_key_update(self.stream.ssl_mut())?;
        self.write_buf.clear();
        encode_message(message, &mut self.write_buf)?;
        self.stream
            .write_all(&self.write_buf)
            .await
            .map_err(TcpWriteError::from)
    }
}

/// Typed failure from `TcpChannel::write_message`.
///
/// The encode failure surfaces as [`FrameError`]; the write failure as
/// [`io::Error`].
///
/// Note on the `Frame` arm's policy downstream: a `FrameError` here means
/// encoding a locally-constructed `Message` failed (an unknown message type, or
/// a payload oversized despite the TUN-layer pre-check) — a logic/config bug a
/// reconnect cannot fix. Consumers therefore route `Frame` to a fatal bucket
/// (e.g. `SessionError::Frame` / `ConnectError::Frame`); the `Io` arm stays
/// retryable/reconnect.
#[derive(Debug, thiserror::Error)]
pub enum TcpWriteError {
    /// Encode failure from `encode_message`.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// Write failure from the underlying TLS stream.
    #[error(transparent)]
    Io(#[from] io::Error),
}

fn pop_message_buf(
    read_buf: &mut Vec<u8>,
    limits: MessageLimits,
) -> Result<Option<OwnedMessageBuf>, MessageError> {
    let Some((frame, consumed)) = decode_frame(read_buf, limits.max_frame_len)? else {
        return Ok(None);
    };

    if frame.ty == MessageType::Data && frame.payload.len() > limits.max_data_len {
        return Err(MessageError::DataTooLarge {
            len: frame.payload.len(),
            max: limits.max_data_len,
        });
    }

    let ty = frame.ty;
    let rest = read_buf.split_off(consumed);
    let buf = std::mem::replace(read_buf, rest);
    Ok(Some(OwnedMessageBuf::new(ty, buf)))
}

fn request_tls_key_update(ssl: &mut SslRef, request_peer_update: bool) -> io::Result<()> {
    let request_type = if request_peer_update {
        boring_sys::SSL_KEY_UPDATE_REQUESTED
    } else {
        boring_sys::SSL_KEY_UPDATE_NOT_REQUESTED
    } as std::os::raw::c_int;
    let rc = unsafe { boring_sys::SSL_key_update(ssl.as_ptr(), request_type) };
    if rc == 1 {
        return Ok(());
    }
    let err = ErrorStack::get();
    // The `KeyUpdater` trait returns `io::Result<()>`, so the boring `ErrorStack`
    // cannot survive this boundary as a typed source. Log it before collapsing —
    // mirroring the `set_tls_configure_callback` pattern in `crypto/mod.rs` — so
    // the structured boring failure reaches the log rather than being stringified
    // and dropped.
    tracing::warn!(error = %err, "tls key update failed");
    Err(io::Error::other(format!("tls key update failed: {err:?}")))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use boring::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};
    use tokio::io::DuplexStream;

    use super::*;
    use crate::proto::{Message, MessageLimits, PingPayload, PongPayload};

    fn cert_paths() -> (PathBuf, PathBuf) {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        (
            root.join("../vendor/boring/test/cert.pem"),
            root.join("../vendor/boring/test/key.pem"),
        )
    }

    fn tls_acceptor() -> SslAcceptor {
        let (cert, key) = cert_paths();
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        builder.set_certificate_chain_file(cert).unwrap();
        builder.set_private_key_file(key, SslFiletype::PEM).unwrap();
        builder.check_private_key().unwrap();
        builder.build()
    }

    fn tls_connector() -> SslConnector {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        builder.build()
    }

    async fn tls_pair() -> (SslStream<DuplexStream>, SslStream<DuplexStream>) {
        let acceptor = tls_acceptor();
        let connector = tls_connector();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio_boring::accept(&acceptor, server_io);
        let client = tokio_boring::connect(connector.configure().unwrap(), "localhost", client_io);
        tokio::try_join!(server, client).unwrap()
    }

    #[tokio::test]
    async fn channel_reads_prebuffered_message() {
        let (server_stream, _client_stream) = tls_pair().await;
        let limits = MessageLimits::new(2048, 2048);

        let nonce = 0x1122_3344_5566_7788_u64;
        let mut frame = Vec::new();
        let payload = PingPayload { nonce };
        let mut payload_buf = Vec::new();
        payload.encode(&mut payload_buf);
        encode_message(
            Message::Ping {
                payload: &payload_buf,
            },
            &mut frame,
        )
        .unwrap();

        let mut channel = TcpChannel::with_read_buffer(server_stream, frame);
        assert!(channel.has_buffered_input());

        let msg = channel.try_pop_message(limits).unwrap().unwrap();
        let Message::Ping { payload } = msg.message() else {
            panic!("expected ping");
        };
        assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
        assert!(!channel.has_buffered_input());
    }

    #[tokio::test]
    async fn channel_roundtrips_framed_messages() {
        let (server_stream, client_stream) = tls_pair().await;
        let limits = MessageLimits::new(2048, 2048);
        let mut server = TcpChannel::new(server_stream);
        let mut client = TcpChannel::new(client_stream);

        let inbound_nonce = 0xA1A2_A3A4_A5A6_A7A8_u64;
        let mut inbound_payload = Vec::new();
        PingPayload {
            nonce: inbound_nonce,
        }
        .encode(&mut inbound_payload);
        client
            .write_message(Message::Ping {
                payload: &inbound_payload,
            })
            .await
            .unwrap();

        let read = server.read_more().await.unwrap();
        assert!(read > 0);
        let inbound_msg = server.try_pop_message(limits).unwrap().unwrap();
        let Message::Ping { payload } = inbound_msg.message() else {
            panic!("expected ping");
        };
        assert_eq!(PingPayload::decode(payload).unwrap().nonce, inbound_nonce);

        let outbound_nonce = 0xB1B2_B3B4_B5B6_B7B8_u64;
        let mut outbound_payload = Vec::new();
        PongPayload {
            nonce: outbound_nonce,
        }
        .encode(&mut outbound_payload);
        server
            .write_message(Message::Pong {
                payload: &outbound_payload,
            })
            .await
            .unwrap();

        let read = client.read_more().await.unwrap();
        assert!(read > 0);
        let outbound_msg = client.try_pop_message(limits).unwrap().unwrap();
        let Message::Pong { payload } = outbound_msg.message() else {
            panic!("expected pong");
        };
        assert_eq!(PongPayload::decode(payload).unwrap().nonce, outbound_nonce);
    }

    #[derive(Debug, Default)]
    struct CountingUpdater {
        calls: usize,
    }

    impl KeyUpdater for CountingUpdater {
        fn maybe_request_key_update(&mut self, _ssl: &mut SslRef) -> io::Result<()> {
            self.calls = self.calls.saturating_add(1);
            Ok(())
        }
    }

    #[tokio::test]
    async fn channel_invokes_key_updater_on_each_write() {
        let (_server_stream, client_stream) = tls_pair().await;
        let mut client = TcpChannel::with_key_updater(client_stream, CountingUpdater::default());

        let mut payload = Vec::new();
        PingPayload { nonce: 1 }.encode(&mut payload);
        client
            .write_message(Message::Ping { payload: &payload })
            .await
            .unwrap();
        client
            .write_message(Message::Ping { payload: &payload })
            .await
            .unwrap();

        assert_eq!(client.key_updater().calls, 2);
    }

    #[test]
    fn interval_key_updater_counts_down() {
        let mut updater = IntervalKeyUpdater::new(NonZeroU64::new(5).unwrap());
        assert_eq!(updater.messages_until_update(), 5);

        // Each tick decrements until_update when > 1
        assert!(!updater.tick()); // 5 -> 4
        assert_eq!(updater.messages_until_update(), 4);
        assert!(!updater.tick()); // 4 -> 3
        assert_eq!(updater.messages_until_update(), 3);
    }

    #[test]
    fn interval_key_updater_triggers_at_zero() {
        let mut updater = IntervalKeyUpdater::new(NonZeroU64::new(3).unwrap());
        assert_eq!(updater.messages_until_update(), 3);

        assert!(!updater.tick()); // 3 -> 2
        assert!(!updater.tick()); // 2 -> 1
        assert!(updater.tick()); // triggers update, resets to 3
        assert_eq!(updater.messages_until_update(), 3);
    }

    #[test]
    fn interval_key_updater_reset_restores_interval() {
        let mut updater = IntervalKeyUpdater::new(NonZeroU64::new(10).unwrap());
        assert_eq!(updater.messages_until_update(), 10);

        // Tick down a few times (ignore return value, we're testing reset)
        let _ = updater.tick();
        let _ = updater.tick();
        let _ = updater.tick();
        assert_eq!(updater.messages_until_update(), 7);

        // Reset should restore to initial interval
        updater.reset();
        assert_eq!(updater.messages_until_update(), 10);
    }

    #[test]
    fn interval_key_updater_peer_response_config() {
        let updater = IntervalKeyUpdater::new(NonZeroU64::new(100).unwrap());
        assert!(!updater.requests_peer_update());

        let updater_with_peer = IntervalKeyUpdater::new(NonZeroU64::new(100).unwrap())
            .with_peer_response_requested(true);
        assert!(updater_with_peer.requests_peer_update());
    }
}
