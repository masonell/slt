//! VPN protocol framing and message definitions.

/// Frame header length: 1 byte type + 4 bytes length.
pub const HEADER_LEN: usize = 5;
/// Maximum QUIC DCID length used by the protocol.
pub const MAX_DCID_LEN: usize = 20;
/// Length of the authentication challenge in bytes.
pub const AUTH_CHALLENGE_LEN: usize = 32;
/// Length of the Ed25519 signature in bytes.
pub const AUTH_SIGNATURE_LEN: usize = 64;
/// Length of the header protection key in bytes.
pub const HP_KEY_LEN: usize = 16;
/// Length of the AEAD key in bytes.
pub const AEAD_KEY_LEN: usize = 16;
/// Length of the AEAD IV in bytes.
pub const AEAD_IV_LEN: usize = 12;
/// Length of the AUTH payload in bytes.
pub const AUTH_PAYLOAD_LEN: usize = 16 + 4 + AUTH_CHALLENGE_LEN + AUTH_SIGNATURE_LEN;
/// Length of the PING/PONG payload in bytes.
pub const PING_PAYLOAD_LEN: usize = 8;
/// Length of the CLOSE payload in bytes.
pub const CLOSE_PAYLOAD_LEN: usize = 1;

/// Wire message types for the VPN protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Client authentication request.
    Auth = 0x01,
    /// Authentication accepted.
    AuthOk = 0x02,
    /// Authentication rejected.
    AuthFail = 0x03,
    /// Register a UDP-QSP CID and keys.
    RegisterCid = 0x04,
    /// CID registration accepted.
    RegisterOk = 0x05,
    /// CID registration rejected.
    RegisterFail = 0x06,
    /// Keepalive ping.
    Ping = 0x07,
    /// Keepalive pong.
    Pong = 0x08,
    /// Close the session.
    Close = 0x09,
    /// Tunnel data (raw IP packet).
    Data = 0x0a,
}

impl MessageType {
    /// Convert a wire byte into a MessageType, if known.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Auth),
            0x02 => Some(Self::AuthOk),
            0x03 => Some(Self::AuthFail),
            0x04 => Some(Self::RegisterCid),
            0x05 => Some(Self::RegisterOk),
            0x06 => Some(Self::RegisterFail),
            0x07 => Some(Self::Ping),
            0x08 => Some(Self::Pong),
            0x09 => Some(Self::Close),
            0x0a => Some(Self::Data),
            _ => None,
        }
    }

    /// Return the wire byte for this message type.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A decoded protocol frame referencing the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Frame message type.
    pub ty: MessageType,
    /// Frame payload bytes.
    pub payload: &'a [u8],
}

/// Cipher identifiers for UDP-QSP payload protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherSuite {
    /// AES-128-GCM.
    Aes128Gcm = 0x01,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305 = 0x02,
}

impl CipherSuite {
    /// Convert a wire byte into a cipher suite, if known.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Aes128Gcm),
            0x02 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Return the wire byte for this cipher suite.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Authentication failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthFailCode {
    /// Unspecified failure.
    Unknown = 0x00,
    /// Client is not in the allowlist.
    UnknownClient = 0x01,
    /// Client is disabled in the config.
    Disabled = 0x02,
    /// Signature verification failed.
    BadSignature = 0x03,
    /// Assigned IP does not match config.
    IpMismatch = 0x04,
    /// Challenge is expired or invalid.
    ChallengeInvalid = 0x05,
}

impl AuthFailCode {
    /// Convert a wire byte into an auth failure code.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Unknown),
            0x01 => Some(Self::UnknownClient),
            0x02 => Some(Self::Disabled),
            0x03 => Some(Self::BadSignature),
            0x04 => Some(Self::IpMismatch),
            0x05 => Some(Self::ChallengeInvalid),
            _ => None,
        }
    }

    /// Return the wire byte for this failure code.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Register-CID failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegisterFailCode {
    /// Unspecified failure.
    Unknown = 0x00,
    /// Client is not authenticated.
    NotAuthenticated = 0x01,
    /// Unsupported or invalid cipher suite.
    InvalidCipher = 0x02,
    /// Invalid CID length or format.
    InvalidCid = 0x03,
    /// Invalid key material.
    InvalidKeys = 0x04,
}

impl RegisterFailCode {
    /// Convert a wire byte into a register failure code.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Unknown),
            0x01 => Some(Self::NotAuthenticated),
            0x02 => Some(Self::InvalidCipher),
            0x03 => Some(Self::InvalidCid),
            0x04 => Some(Self::InvalidKeys),
            _ => None,
        }
    }

    /// Return the wire byte for this failure code.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Close reasons for terminating a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseCode {
    /// Normal shutdown.
    Normal = 0x00,
    /// Authentication timeout.
    AuthTimeout = 0x01,
    /// Idle timeout.
    IdleTimeout = 0x02,
    /// Protocol error.
    ProtocolError = 0x03,
    /// Server shutdown or restart.
    ServerRestart = 0x04,
}

impl CloseCode {
    /// Convert a wire byte into a close reason code.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Normal),
            0x01 => Some(Self::AuthTimeout),
            0x02 => Some(Self::IdleTimeout),
            0x03 => Some(Self::ProtocolError),
            0x04 => Some(Self::ServerRestart),
            _ => None,
        }
    }

    /// Return the wire byte for this close reason.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Authentication message payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthPayload {
    /// Client identifier.
    pub client_id: [u8; 16],
    /// Assigned IPv4 address.
    pub assigned_ipv4: std::net::Ipv4Addr,
    /// Server-provided challenge bytes.
    pub challenge: [u8; AUTH_CHALLENGE_LEN],
    /// Ed25519 signature over the challenge and context.
    pub signature: [u8; AUTH_SIGNATURE_LEN],
}

impl AuthPayload {
    /// Decode an AUTH payload.
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != AUTH_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: AUTH_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }

        let mut client_id = [0u8; 16];
        client_id.copy_from_slice(&payload[..16]);

        let assigned_ipv4 =
            std::net::Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);

        let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
        challenge.copy_from_slice(&payload[20..20 + AUTH_CHALLENGE_LEN]);

        let mut signature = [0u8; AUTH_SIGNATURE_LEN];
        signature.copy_from_slice(
            &payload[20 + AUTH_CHALLENGE_LEN..20 + AUTH_CHALLENGE_LEN + AUTH_SIGNATURE_LEN],
        );

        Ok(Self {
            client_id,
            assigned_ipv4,
            challenge,
            signature,
        })
    }

    /// Encode an AUTH payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(AUTH_PAYLOAD_LEN);
        out.extend_from_slice(&self.client_id);
        out.extend_from_slice(&self.assigned_ipv4.octets());
        out.extend_from_slice(&self.challenge);
        out.extend_from_slice(&self.signature);
    }
}

/// AUTH_OK payload (currently empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthOkPayload;

impl AuthOkPayload {
    /// Decode an AUTH_OK payload.
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if !payload.is_empty() {
            return Err(PayloadError::LengthMismatch {
                expected: 0,
                actual: payload.len(),
            });
        }
        Ok(Self)
    }

    /// Encode an AUTH_OK payload.
    pub fn encode(&self, _out: &mut Vec<u8>) {}
}

/// AUTH_FAIL payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthFailPayload {
    /// Failure reason code.
    pub code: AuthFailCode,
}

impl AuthFailPayload {
    /// Decode an AUTH_FAIL payload.
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != 1 {
            return Err(PayloadError::LengthMismatch {
                expected: 1,
                actual: payload.len(),
            });
        }
        let code = AuthFailCode::from_u8(payload[0])
            .ok_or(PayloadError::InvalidAuthFailCode(payload[0]))?;
        Ok(Self { code })
    }

    /// Encode an AUTH_FAIL payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.code.as_u8());
    }
}

/// REGISTER_CID payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterCidPayload<'a> {
    /// Destination connection ID to reuse.
    pub dcid: &'a [u8],
    /// Cipher suite for packet protection.
    pub cipher: CipherSuite,
    /// Header protection key (tx).
    pub hp_tx: [u8; HP_KEY_LEN],
    /// Header protection key (rx).
    pub hp_rx: [u8; HP_KEY_LEN],
    /// AEAD key (tx).
    pub aead_tx: [u8; AEAD_KEY_LEN],
    /// AEAD key (rx).
    pub aead_rx: [u8; AEAD_KEY_LEN],
    /// AEAD IV (tx).
    pub iv_tx: [u8; AEAD_IV_LEN],
    /// AEAD IV (rx).
    pub iv_rx: [u8; AEAD_IV_LEN],
    /// Initial packet number for the UDP-QSP flow.
    pub pn_start: u64,
    /// Initial key phase (false = 0, true = 1).
    pub key_phase: bool,
}

impl<'a> RegisterCidPayload<'a> {
    /// Decode a REGISTER_CID payload.
    pub fn decode(payload: &'a [u8]) -> Result<Self, PayloadError> {
        if payload.is_empty() {
            return Err(PayloadError::LengthTooShort {
                min: 1,
                actual: payload.len(),
            });
        }

        let dcid_len = payload[0] as usize;
        if dcid_len == 0 || dcid_len > MAX_DCID_LEN {
            return Err(PayloadError::InvalidDcidLen(dcid_len));
        }

        let expected_len =
            1 + dcid_len + 1 + (HP_KEY_LEN * 2) + (AEAD_KEY_LEN * 2) + (AEAD_IV_LEN * 2) + 8 + 1;

        if payload.len() != expected_len {
            return Err(PayloadError::LengthMismatch {
                expected: expected_len,
                actual: payload.len(),
            });
        }

        let mut offset = 1;
        let dcid = &payload[offset..offset + dcid_len];
        offset += dcid_len;

        let cipher = CipherSuite::from_u8(payload[offset])
            .ok_or(PayloadError::InvalidCipher(payload[offset]))?;
        offset += 1;

        let mut hp_tx = [0u8; HP_KEY_LEN];
        hp_tx.copy_from_slice(&payload[offset..offset + HP_KEY_LEN]);
        offset += HP_KEY_LEN;

        let mut hp_rx = [0u8; HP_KEY_LEN];
        hp_rx.copy_from_slice(&payload[offset..offset + HP_KEY_LEN]);
        offset += HP_KEY_LEN;

        let mut aead_tx = [0u8; AEAD_KEY_LEN];
        aead_tx.copy_from_slice(&payload[offset..offset + AEAD_KEY_LEN]);
        offset += AEAD_KEY_LEN;

        let mut aead_rx = [0u8; AEAD_KEY_LEN];
        aead_rx.copy_from_slice(&payload[offset..offset + AEAD_KEY_LEN]);
        offset += AEAD_KEY_LEN;

        let mut iv_tx = [0u8; AEAD_IV_LEN];
        iv_tx.copy_from_slice(&payload[offset..offset + AEAD_IV_LEN]);
        offset += AEAD_IV_LEN;

        let mut iv_rx = [0u8; AEAD_IV_LEN];
        iv_rx.copy_from_slice(&payload[offset..offset + AEAD_IV_LEN]);
        offset += AEAD_IV_LEN;

        let pn_start = u64::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
            payload[offset + 4],
            payload[offset + 5],
            payload[offset + 6],
            payload[offset + 7],
        ]);
        offset += 8;

        let key_phase = match payload[offset] {
            0 => false,
            1 => true,
            other => return Err(PayloadError::InvalidKeyPhase(other)),
        };

        Ok(Self {
            dcid,
            cipher,
            hp_tx,
            hp_rx,
            aead_tx,
            aead_rx,
            iv_tx,
            iv_rx,
            pn_start,
            key_phase,
        })
    }

    /// Encode a REGISTER_CID payload.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), PayloadError> {
        if self.dcid.is_empty() || self.dcid.len() > MAX_DCID_LEN {
            return Err(PayloadError::InvalidDcidLen(self.dcid.len()));
        }

        let expected_len = 1
            + self.dcid.len()
            + 1
            + (HP_KEY_LEN * 2)
            + (AEAD_KEY_LEN * 2)
            + (AEAD_IV_LEN * 2)
            + 8
            + 1;
        out.reserve(expected_len);
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(self.dcid);
        out.push(self.cipher.as_u8());
        out.extend_from_slice(&self.hp_tx);
        out.extend_from_slice(&self.hp_rx);
        out.extend_from_slice(&self.aead_tx);
        out.extend_from_slice(&self.aead_rx);
        out.extend_from_slice(&self.iv_tx);
        out.extend_from_slice(&self.iv_rx);
        out.extend_from_slice(&self.pn_start.to_be_bytes());
        out.push(u8::from(self.key_phase));
        Ok(())
    }
}

/// REGISTER_OK payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterOkPayload<'a> {
    /// The acknowledged CID.
    pub dcid: &'a [u8],
}

impl<'a> RegisterOkPayload<'a> {
    /// Decode a REGISTER_OK payload.
    pub fn decode(payload: &'a [u8]) -> Result<Self, PayloadError> {
        if payload.is_empty() {
            return Err(PayloadError::LengthTooShort {
                min: 1,
                actual: payload.len(),
            });
        }

        let dcid_len = payload[0] as usize;
        if dcid_len == 0 || dcid_len > MAX_DCID_LEN {
            return Err(PayloadError::InvalidDcidLen(dcid_len));
        }

        let expected_len = 1 + dcid_len;
        if payload.len() != expected_len {
            return Err(PayloadError::LengthMismatch {
                expected: expected_len,
                actual: payload.len(),
            });
        }

        Ok(Self {
            dcid: &payload[1..1 + dcid_len],
        })
    }

    /// Encode a REGISTER_OK payload.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), PayloadError> {
        if self.dcid.is_empty() || self.dcid.len() > MAX_DCID_LEN {
            return Err(PayloadError::InvalidDcidLen(self.dcid.len()));
        }
        out.reserve(1 + self.dcid.len());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(self.dcid);
        Ok(())
    }
}

/// REGISTER_FAIL payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterFailPayload {
    /// Failure reason code.
    pub code: RegisterFailCode,
}

impl RegisterFailPayload {
    /// Decode a REGISTER_FAIL payload.
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != 1 {
            return Err(PayloadError::LengthMismatch {
                expected: 1,
                actual: payload.len(),
            });
        }
        let code = RegisterFailCode::from_u8(payload[0])
            .ok_or(PayloadError::InvalidRegisterFailCode(payload[0]))?;
        Ok(Self { code })
    }

    /// Encode a REGISTER_FAIL payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.code.as_u8());
    }
}

/// PING payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingPayload {
    /// Ping nonce.
    pub nonce: u64,
}

impl PingPayload {
    /// Decode a PING payload.
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != PING_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: PING_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let nonce = u64::from_be_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        Ok(Self { nonce })
    }

    /// Encode a PING payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.nonce.to_be_bytes());
    }
}

/// PONG payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PongPayload {
    /// Pong nonce.
    pub nonce: u64,
}

impl PongPayload {
    /// Decode a PONG payload.
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != PING_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: PING_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let nonce = u64::from_be_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        Ok(Self { nonce })
    }

    /// Encode a PONG payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.nonce.to_be_bytes());
    }
}

/// CLOSE payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosePayload {
    /// Close reason code.
    pub code: CloseCode,
}

impl ClosePayload {
    /// Decode a CLOSE payload.
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != CLOSE_PAYLOAD_LEN {
            return Err(PayloadError::LengthMismatch {
                expected: CLOSE_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let code =
            CloseCode::from_u8(payload[0]).ok_or(PayloadError::InvalidCloseCode(payload[0]))?;
        Ok(Self { code })
    }

    /// Encode a CLOSE payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.code.as_u8());
    }
}

/// Application-layer message with a payload view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message<'a> {
    /// Client authentication request.
    Auth { payload: &'a [u8] },
    /// Authentication accepted.
    AuthOk { payload: &'a [u8] },
    /// Authentication rejected.
    AuthFail { payload: &'a [u8] },
    /// Register a UDP-QSP CID and keys.
    RegisterCid { payload: &'a [u8] },
    /// CID registration accepted.
    RegisterOk { payload: &'a [u8] },
    /// CID registration rejected.
    RegisterFail { payload: &'a [u8] },
    /// Keepalive ping.
    Ping { payload: &'a [u8] },
    /// Keepalive pong.
    Pong { payload: &'a [u8] },
    /// Close the session.
    Close { payload: &'a [u8] },
    /// Tunnel data (raw IP packet).
    Data { packet: &'a [u8] },
}

impl<'a> Message<'a> {
    /// Returns the message type.
    #[must_use]
    pub fn ty(&self) -> MessageType {
        match self {
            Message::Auth { .. } => MessageType::Auth,
            Message::AuthOk { .. } => MessageType::AuthOk,
            Message::AuthFail { .. } => MessageType::AuthFail,
            Message::RegisterCid { .. } => MessageType::RegisterCid,
            Message::RegisterOk { .. } => MessageType::RegisterOk,
            Message::RegisterFail { .. } => MessageType::RegisterFail,
            Message::Ping { .. } => MessageType::Ping,
            Message::Pong { .. } => MessageType::Pong,
            Message::Close { .. } => MessageType::Close,
            Message::Data { .. } => MessageType::Data,
        }
    }

    /// Returns the payload bytes (or packet bytes for DATA).
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        match self {
            Message::Data { packet } => packet,
            Message::Auth { payload }
            | Message::AuthOk { payload }
            | Message::AuthFail { payload }
            | Message::RegisterCid { payload }
            | Message::RegisterOk { payload }
            | Message::RegisterFail { payload }
            | Message::Ping { payload }
            | Message::Pong { payload }
            | Message::Close { payload } => payload,
        }
    }
}

impl<'a> From<Frame<'a>> for Message<'a> {
    fn from(frame: Frame<'a>) -> Self {
        match frame.ty {
            MessageType::Auth => Message::Auth {
                payload: frame.payload,
            },
            MessageType::AuthOk => Message::AuthOk {
                payload: frame.payload,
            },
            MessageType::AuthFail => Message::AuthFail {
                payload: frame.payload,
            },
            MessageType::RegisterCid => Message::RegisterCid {
                payload: frame.payload,
            },
            MessageType::RegisterOk => Message::RegisterOk {
                payload: frame.payload,
            },
            MessageType::RegisterFail => Message::RegisterFail {
                payload: frame.payload,
            },
            MessageType::Ping => Message::Ping {
                payload: frame.payload,
            },
            MessageType::Pong => Message::Pong {
                payload: frame.payload,
            },
            MessageType::Close => Message::Close {
                payload: frame.payload,
            },
            MessageType::Data => Message::Data {
                packet: frame.payload,
            },
        }
    }
}

impl<'a> From<Message<'a>> for Frame<'a> {
    fn from(message: Message<'a>) -> Self {
        Frame {
            ty: message.ty(),
            payload: message.payload(),
        }
    }
}

/// Bounds used when decoding protocol messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageLimits {
    /// Maximum frame payload length to accept.
    pub max_frame_len: usize,
    /// Maximum data payload length to accept for `DATA` messages.
    pub max_data_len: usize,
}

impl MessageLimits {
    /// Create message limits for a decoding context.
    #[must_use]
    pub fn new(max_frame_len: usize, max_data_len: usize) -> Self {
        Self {
            max_frame_len,
            max_data_len,
        }
    }
}

/// Framing errors for encode/decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The type byte is unknown.
    UnknownType(u8),
    /// Frame length exceeds the configured maximum.
    LengthTooLarge { len: usize, max: usize },
    /// Payload length does not fit in the u32 length field.
    LengthOverflow(usize),
}

/// Payload parsing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    /// Payload length does not match the expected length.
    LengthMismatch { expected: usize, actual: usize },
    /// Payload is shorter than the minimum required length.
    LengthTooShort { min: usize, actual: usize },
    /// DCID length is invalid.
    InvalidDcidLen(usize),
    /// Cipher identifier is unknown.
    InvalidCipher(u8),
    /// Auth failure code is unknown.
    InvalidAuthFailCode(u8),
    /// Register failure code is unknown.
    InvalidRegisterFailCode(u8),
    /// Close code is unknown.
    InvalidCloseCode(u8),
    /// Key phase is not 0 or 1.
    InvalidKeyPhase(u8),
}

/// Message-level errors for encode/decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// Framing error while decoding.
    Frame(FrameError),
    /// `DATA` payload length exceeds the allowed maximum.
    DataTooLarge { len: usize, max: usize },
}

impl From<FrameError> for MessageError {
    fn from(err: FrameError) -> Self {
        Self::Frame(err)
    }
}

/// Decode a single frame from the provided buffer.
///
/// Returns `Ok(None)` if the buffer does not yet contain a full frame.
pub fn decode_frame(
    buf: &'_ [u8],
    max_len: usize,
) -> Result<Option<(Frame<'_>, usize)>, FrameError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }

    let ty = MessageType::from_u8(buf[0]).ok_or(FrameError::UnknownType(buf[0]))?;
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > max_len {
        return Err(FrameError::LengthTooLarge { len, max: max_len });
    }

    let total_len = HEADER_LEN + len;
    if buf.len() < total_len {
        return Ok(None);
    }

    Ok(Some((
        Frame {
            ty,
            payload: &buf[HEADER_LEN..total_len],
        },
        total_len,
    )))
}

/// Encode a frame into the provided output buffer.
pub fn encode_frame(ty: MessageType, payload: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    let len = payload.len();
    if len > u32::MAX as usize {
        return Err(FrameError::LengthOverflow(len));
    }

    out.reserve(HEADER_LEN + len);
    out.push(ty.as_u8());
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Decode a single message from the provided buffer.
///
/// Returns `Ok(None)` if the buffer does not yet contain a full frame.
pub fn decode_message(
    buf: &'_ [u8],
    limits: MessageLimits,
) -> Result<Option<(Message<'_>, usize)>, MessageError> {
    let (frame, consumed) = match decode_frame(buf, limits.max_frame_len)? {
        Some(frame) => frame,
        None => return Ok(None),
    };

    if frame.ty == MessageType::Data && frame.payload.len() > limits.max_data_len {
        return Err(MessageError::DataTooLarge {
            len: frame.payload.len(),
            max: limits.max_data_len,
        });
    }

    Ok(Some((Message::from(frame), consumed)))
}

/// Encode a message into the provided output buffer.
pub fn encode_message(message: Message<'_>, out: &mut Vec<u8>) -> Result<(), FrameError> {
    encode_frame(message.ty(), message.payload(), out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_roundtrip_frame() {
        let payload = b"hello";
        let mut buf = Vec::new();
        encode_frame(MessageType::Ping, payload, &mut buf).unwrap();

        let (frame, consumed) = decode_frame(&buf, 1024).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(frame.ty, MessageType::Ping);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn decode_incomplete_header() {
        let buf = [MessageType::Auth.as_u8(), 0x00];
        assert!(decode_frame(&buf, 1024).unwrap().is_none());
    }

    #[test]
    fn decode_incomplete_payload() {
        let buf = [
            MessageType::Auth.as_u8(),
            0x00,
            0x00,
            0x00,
            0x05,
            0x01,
            0x02,
        ];
        assert!(decode_frame(&buf, 1024).unwrap().is_none());
    }

    #[test]
    fn decode_unknown_type() {
        let buf = [0xff, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode_frame(&buf, 1024), Err(FrameError::UnknownType(0xff)));
    }

    #[test]
    fn decode_length_too_large() {
        let buf = [MessageType::Auth.as_u8(), 0x00, 0x00, 0x10, 0x00];
        assert_eq!(
            decode_frame(&buf, 1024),
            Err(FrameError::LengthTooLarge {
                len: 4096,
                max: 1024
            })
        );
    }

    #[test]
    fn decode_roundtrip_message() {
        let payload = b"ping";
        let message = Message::Ping { payload };
        let mut buf = Vec::new();
        encode_message(message, &mut buf).unwrap();

        let limits = MessageLimits::new(1024, 1024);
        let (decoded, consumed) = decode_message(&buf, limits).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded, message);
    }

    #[test]
    fn decode_message_data_too_large() {
        let payload = [0u8; 16];
        let message = Message::Data { packet: &payload };
        let mut buf = Vec::new();
        encode_message(message, &mut buf).unwrap();

        let limits = MessageLimits::new(1024, 8);
        assert_eq!(
            decode_message(&buf, limits),
            Err(MessageError::DataTooLarge { len: 16, max: 8 })
        );
    }

    #[test]
    fn auth_payload_roundtrip() {
        let payload = AuthPayload {
            client_id: [0x11; 16],
            assigned_ipv4: std::net::Ipv4Addr::new(10, 10, 0, 2),
            challenge: [0x22; AUTH_CHALLENGE_LEN],
            signature: [0x33; AUTH_SIGNATURE_LEN],
        };

        let mut buf = Vec::new();
        payload.encode(&mut buf);
        let decoded = AuthPayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn auth_ok_requires_empty_payload() {
        let buf = [0x01];
        assert_eq!(
            AuthOkPayload::decode(&buf),
            Err(PayloadError::LengthMismatch {
                expected: 0,
                actual: 1
            })
        );
    }

    #[test]
    fn register_cid_roundtrip() {
        let dcid = [0x55u8; 8];
        let payload = RegisterCidPayload {
            dcid: &dcid,
            cipher: CipherSuite::Aes128Gcm,
            hp_tx: [0x01; HP_KEY_LEN],
            hp_rx: [0x02; HP_KEY_LEN],
            aead_tx: [0x03; AEAD_KEY_LEN],
            aead_rx: [0x04; AEAD_KEY_LEN],
            iv_tx: [0x05; AEAD_IV_LEN],
            iv_rx: [0x06; AEAD_IV_LEN],
            pn_start: 42,
            key_phase: true,
        };

        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();
        let decoded = RegisterCidPayload::decode(&buf).unwrap();
        assert_eq!(decoded.dcid, payload.dcid);
        assert_eq!(decoded.cipher, payload.cipher);
        assert_eq!(decoded.hp_tx, payload.hp_tx);
        assert_eq!(decoded.hp_rx, payload.hp_rx);
        assert_eq!(decoded.aead_tx, payload.aead_tx);
        assert_eq!(decoded.aead_rx, payload.aead_rx);
        assert_eq!(decoded.iv_tx, payload.iv_tx);
        assert_eq!(decoded.iv_rx, payload.iv_rx);
        assert_eq!(decoded.pn_start, payload.pn_start);
        assert_eq!(decoded.key_phase, payload.key_phase);
    }

    #[test]
    fn register_ok_roundtrip() {
        let dcid = [0xAAu8; 8];
        let payload = RegisterOkPayload { dcid: &dcid };
        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();
        let decoded = RegisterOkPayload::decode(&buf).unwrap();
        assert_eq!(decoded.dcid, payload.dcid);
    }

    #[test]
    fn ping_pong_roundtrip() {
        let ping = PingPayload {
            nonce: 0x1122334455667788,
        };
        let mut buf = Vec::new();
        ping.encode(&mut buf);
        let decoded_ping = PingPayload::decode(&buf).unwrap();
        assert_eq!(decoded_ping, ping);

        buf.clear();
        let pong = PongPayload {
            nonce: 0x1122334455667788,
        };
        pong.encode(&mut buf);
        let decoded_pong = PongPayload::decode(&buf).unwrap();
        assert_eq!(decoded_pong, pong);
    }

    #[test]
    fn close_payload_invalid_code() {
        let buf = [0xff];
        assert_eq!(
            ClosePayload::decode(&buf),
            Err(PayloadError::InvalidCloseCode(0xff))
        );
    }
}
