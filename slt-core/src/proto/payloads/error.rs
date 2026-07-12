/// Payload parsing errors.
///
/// This is a real [`std::error::Error`] type (it derives [`thiserror::Error`])
/// so downstream layers can preserve it via `#[from]` rather than flattening it
/// into an `io::Error`. It stays `Copy` — callers rely on that, and `thiserror`
/// is compatible with `Copy` enums as long as every field is `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// Payload length does not match the expected length.
    #[error("payload length mismatch: expected {expected}, got {actual}")]
    LengthMismatch {
        /// Expected payload length for the message type.
        expected: usize,
        /// Actual payload length that was decoded.
        actual: usize,
    },
    /// Payload is shorter than the minimum required length.
    #[error("payload too short: need at least {min} bytes, got {actual}")]
    LengthTooShort {
        /// Minimum payload length required to continue parsing.
        min: usize,
        /// Actual payload length that was decoded.
        actual: usize,
    },
    /// Client-to-server CID length is invalid.
    #[error("invalid client-to-server cid length: {0}")]
    InvalidClientToServerCidLen(usize),
    /// Server-to-client CID length is invalid.
    #[error("invalid server-to-client cid length: {0}")]
    InvalidServerToClientCidLen(usize),
    /// Cipher identifier is unknown.
    #[error("unknown cipher suite identifier: {0:#02x}")]
    InvalidCipher(u8),
    /// Auth failure code is unknown.
    #[error("unknown auth failure code: {0:#02x}")]
    InvalidAuthFailCode(u8),
    /// Register failure code is unknown.
    #[error("unknown register failure code: {0:#02x}")]
    InvalidRegisterFailCode(u8),
    /// Close code is unknown.
    #[error("unknown close code: {0:#02x}")]
    InvalidCloseCode(u8),
    /// Key phase is not 0 or 1.
    #[error("invalid key phase: {0:#02x}")]
    InvalidKeyPhase(u8),
}
