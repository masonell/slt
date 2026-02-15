/// Maximum QUIC DCID length supported by the protocol.
pub const MAX_DCID_LEN: usize = 20;
/// Prefix length used to classify QUIC short headers.
pub const QUIC_DCID_PREFIX_LEN: usize = 8;

/// Fixed-length prefix used to classify QUIC short headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CidPrefix([u8; QUIC_DCID_PREFIX_LEN]);

/// QUIC destination connection ID used by UDP-QSP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cid {
    len: u8,
    bytes: [u8; MAX_DCID_LEN],
}

/// Errors returned when parsing a CID from bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CidError {
    /// The CID length does not match protocol bounds.
    #[error("invalid CID length {0}; expected {QUIC_DCID_PREFIX_LEN}..={MAX_DCID_LEN}")]
    InvalidLen(usize),
}

impl CidPrefix {
    /// Construct a CID prefix from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; QUIC_DCID_PREFIX_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw prefix bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; QUIC_DCID_PREFIX_LEN] {
        &self.0
    }

    /// Returns the prefix as a byte slice.
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; QUIC_DCID_PREFIX_LEN]> for CidPrefix {
    fn from(bytes: [u8; QUIC_DCID_PREFIX_LEN]) -> Self {
        Self::new(bytes)
    }
}

impl Cid {
    /// Construct a CID from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `CidError::InvalidLen` if the length is shorter than
    /// `QUIC_DCID_PREFIX_LEN` or longer than `MAX_DCID_LEN`.
    pub fn new(bytes: &[u8]) -> Result<Self, CidError> {
        if bytes.len() < QUIC_DCID_PREFIX_LEN || bytes.len() > MAX_DCID_LEN {
            return Err(CidError::InvalidLen(bytes.len()));
        }
        let mut out = [0u8; MAX_DCID_LEN];
        out[..bytes.len()].copy_from_slice(bytes);
        let len = u8::try_from(bytes.len()).map_err(|_| CidError::InvalidLen(bytes.len()))?;
        Ok(Self { len, bytes: out })
    }

    /// Returns the raw CID bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Returns the CID prefix used for classification.
    #[must_use]
    pub fn prefix(&self) -> CidPrefix {
        let mut bytes = [0u8; QUIC_DCID_PREFIX_LEN];
        bytes.copy_from_slice(&self.bytes[..QUIC_DCID_PREFIX_LEN]);
        CidPrefix::new(bytes)
    }

    /// Returns the CID length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns true if the CID is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl From<[u8; QUIC_DCID_PREFIX_LEN]> for Cid {
    fn from(bytes: [u8; QUIC_DCID_PREFIX_LEN]) -> Self {
        let mut out = [0u8; MAX_DCID_LEN];
        out[..QUIC_DCID_PREFIX_LEN].copy_from_slice(&bytes);
        let len = u8::try_from(QUIC_DCID_PREFIX_LEN).expect("prefix length fits in u8");
        Self { len, bytes: out }
    }
}

impl TryFrom<&[u8]> for Cid {
    type Error = CidError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_too_short_cid() {
        let short = &[0u8; 7];
        let result = Cid::new(short);
        assert!(matches!(result, Err(CidError::InvalidLen(7))));
    }

    #[test]
    fn rejects_too_long_cid() {
        let long = &[0xAA; 21];
        let result = Cid::new(long);
        assert!(matches!(result, Err(CidError::InvalidLen(21))));
    }

    #[test]
    fn accepts_minimum_length_cid() {
        let min = &[0xAA; 8];
        let cid = Cid::new(min).unwrap();
        assert_eq!(cid.len(), 8);
        assert_eq!(cid.as_slice(), min);
    }

    #[test]
    fn accepts_maximum_length_cid() {
        let max = &[0xBB; 20];
        let cid = Cid::new(max).unwrap();
        assert_eq!(cid.len(), 20);
        assert_eq!(cid.as_slice(), max);
    }

    #[test]
    fn cid_prefix_new_succeeds() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let prefix = CidPrefix::new(bytes);
        assert_eq!(prefix.as_bytes(), &bytes);
    }

    #[test]
    fn cid_prefix_as_bytes_returns_correct_slice() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let prefix = CidPrefix::new(bytes);
        assert_eq!(prefix.as_bytes(), &bytes);
        assert_eq!(prefix.as_slice(), &bytes[..]);
    }
}
