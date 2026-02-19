/// Maximum QUIC DCID length supported by the protocol.
pub const MAX_DCID_LEN: usize = 20;
/// Prefix length used to classify QUIC short headers.
pub const QUIC_DCID_PREFIX_LEN: usize = 20;

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
    #[error("invalid CID length {0}; expected 0..={MAX_DCID_LEN}")]
    InvalidLen(usize),
    /// The CID is too short to extract a prefix.
    #[error("CID length {0} is too short for prefix extraction (need {QUIC_DCID_PREFIX_LEN})")]
    TooShortForPrefix(usize),
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
    /// Returns `CidError::InvalidLen` if the length is longer than `MAX_DCID_LEN`.
    pub fn new(bytes: &[u8]) -> Result<Self, CidError> {
        if bytes.len() > MAX_DCID_LEN {
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
    ///
    /// # Errors
    ///
    /// Returns `CidError::TooShortForPrefix` if the CID length is less than
    /// `QUIC_DCID_PREFIX_LEN` (20 bytes).
    pub fn prefix(&self) -> Result<CidPrefix, CidError> {
        if self.len() < QUIC_DCID_PREFIX_LEN {
            return Err(CidError::TooShortForPrefix(self.len()));
        }
        let mut bytes = [0u8; QUIC_DCID_PREFIX_LEN];
        bytes.copy_from_slice(&self.bytes[..QUIC_DCID_PREFIX_LEN]);
        Ok(CidPrefix::new(bytes))
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

impl From<[u8; MAX_DCID_LEN]> for Cid {
    fn from(bytes: [u8; MAX_DCID_LEN]) -> Self {
        let mut out = [0u8; MAX_DCID_LEN];
        out.copy_from_slice(&bytes);
        let len = u8::try_from(MAX_DCID_LEN).expect("MAX_DCID_LEN fits in u8");
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
    fn accepts_empty_cid() {
        let empty = &[];
        let cid = Cid::new(empty).unwrap();
        assert_eq!(cid.len(), 0);
        assert_eq!(cid.as_slice(), empty);
    }

    #[test]
    fn rejects_too_long_cid() {
        let long = &[0xAA; 21];
        let result = Cid::new(long);
        assert!(matches!(result, Err(CidError::InvalidLen(21))));
    }

    #[test]
    fn accepts_various_lengths() {
        for len in [0, 1, 8, 10, 20] {
            let bytes = vec![0xAA; len];
            let cid = Cid::new(&bytes).unwrap();
            assert_eq!(cid.len(), len);
            assert_eq!(cid.as_slice(), bytes.as_slice());
        }
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
        let bytes = [0x01; 20];
        let prefix = CidPrefix::new(bytes);
        assert_eq!(prefix.as_bytes(), &bytes);
    }

    #[test]
    fn cid_prefix_as_bytes_returns_correct_slice() {
        let bytes = [0xDE; 20];
        let prefix = CidPrefix::new(bytes);
        assert_eq!(prefix.as_bytes(), &bytes);
        assert_eq!(prefix.as_slice(), &bytes[..]);
    }

    #[test]
    fn prefix_succeeds_for_max_len_cid() {
        let bytes = [0xAB; 20];
        let cid = Cid::from(bytes);
        let prefix = cid.prefix().unwrap();
        assert_eq!(prefix.as_bytes(), &bytes);
    }

    #[test]
    fn prefix_fails_for_short_cid() {
        let short = &[0xAA; 10];
        let cid = Cid::new(short).unwrap();
        let result = cid.prefix();
        assert!(matches!(result, Err(CidError::TooShortForPrefix(10))));
    }

    #[test]
    fn prefix_fails_for_empty_cid() {
        let empty = &[];
        let cid = Cid::new(empty).unwrap();
        let result = cid.prefix();
        assert!(matches!(result, Err(CidError::TooShortForPrefix(0))));
    }
}
