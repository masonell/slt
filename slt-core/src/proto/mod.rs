//! VPN protocol framing, message types, and payload schemas.

/// AUTH message construction (signature context + payload builder).
pub mod auth;
/// Frame encoding/decoding.
pub mod framing;
/// Message helpers built on top of frames.
pub mod message;
/// Application payload schemas and codes.
pub mod payloads;
/// Message type identifiers.
pub mod types;

/// AUTH message construction.
pub use auth::{AUTH_CHALLENGE_LABEL, auth_signature_context, build_auth_payload};
/// Frame encoding/decoding and frame types.
pub use framing::{Frame, FrameError, HEADER_LEN, OwnedMessageBuf, decode_frame, encode_frame};
/// Message-level helpers and limits.
pub use message::{Message, MessageError, MessageLimits, decode_message, encode_message};
/// Payload schemas, constants, and codes.
pub use payloads::{
    AEAD_IV_LEN, AEAD_KEY_LEN, AUTH_CHALLENGE_LEN, AUTH_PAYLOAD_LEN, AUTH_SIGNATURE_LEN,
    AuthFailCode, AuthFailPayload, AuthOkPayload, AuthPayload, CHACHA20_POLY1305_KEY_LEN,
    CLOSE_PAYLOAD_LEN, CipherSuite, CloseCode, ClosePayload, HP_KEY_LEN, MAX_AEAD_KEY_LEN,
    MAX_CONTROL_FRAME_LEN, MAX_HP_KEY_LEN, PING_PAYLOAD_LEN, PayloadError, PingPayload,
    PongPayload, RegisterCidPayload, RegisterFailCode, RegisterFailPayload, RegisterOkPayload,
    SwitchAckPayload, SwitchToUdpPayload, UPGRADE_ID_PAYLOAD_LEN, UPGRADE_PROBE_PAYLOAD_LEN,
    UdpReadyPayload, UpgradeProbeAckPayload, UpgradeProbePayload,
};
/// Message type identifiers.
pub use types::MessageType;

/// Maximum QUIC DCID length for UDP-QSP.
pub use crate::types::MAX_DCID_LEN;
/// QUIC DCID prefix length for UDP-QSP.
pub use crate::types::QUIC_DCID_PREFIX_LEN;
