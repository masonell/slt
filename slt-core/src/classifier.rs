use boring::hash::hmac_sha256;
use boring::memcmp;

use crate::crypto::client_hello::{
    EXT_KEY_SHARE, GROUP_X25519, HANDSHAKE_TYPE_CLIENT_HELLO, LEGACY_SESSION_ID_LEN, PART_LEN,
    RANDOM_PREFIX_LEN,
};
use crate::types::{CidPrefix, QUIC_DCID_PREFIX_LEN, SharedSecret};

/// Classification result for a parsed `ClientHello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// `ClientHello` matches the expected `session_id` scheme.
    Claim,
    /// `ClientHello` does not match and should be passed on.
    Pass,
    /// `ClientHello` is invalid and should be dropped.
    Drop,
    /// Not enough data to decide yet.
    Incomplete,
}

/// Result of classifying a QUIC datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicVerdict {
    /// Datagram is not QUIC and should be dropped.
    Drop,
    /// QUIC long-header packet should be passed through.
    Pass,
    /// QUIC short-header packet with extracted DCID prefix.
    Short { dcid_prefix: CidPrefix },
}

const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;

/// Classify a UDP datagram and extract the DCID from a QUIC short header.
///
/// This uses QUIC invariants (fixed bit set) to recognize QUIC packets. Long
/// headers are passed through. For short headers, the DCID length is assumed
/// to be `QUIC_DCID_PREFIX_LEN`.
#[must_use]
pub fn classify_quic_datagram(input: &[u8]) -> QuicVerdict {
    if input.is_empty() {
        return QuicVerdict::Drop;
    }

    let first = input[0];
    let header_form_long = (first & 0x80) != 0;
    let fixed_bit = (first & 0x40) != 0;

    if !fixed_bit {
        return QuicVerdict::Drop;
    }

    if header_form_long {
        return QuicVerdict::Pass;
    }

    if input.len() < 1 + QUIC_DCID_PREFIX_LEN {
        return QuicVerdict::Drop;
    }

    let mut dcid_bytes = [0u8; QUIC_DCID_PREFIX_LEN];
    dcid_bytes.copy_from_slice(&input[1..=QUIC_DCID_PREFIX_LEN]);
    QuicVerdict::Short {
        dcid_prefix: CidPrefix::from(dcid_bytes),
    }
}

/// Classify a TCP stream buffer that starts with TLS records.
///
/// The classifier reads the first `ClientHello` from the stream and validates
/// the `legacy_session_id` using `shared_secret`.
#[must_use]
pub fn classify_tcp_client_hello(input: &[u8], shared_secret: &SharedSecret) -> Verdict {
    let mut record = RecordReader::new(input);

    let hs_type = match record.read_u8() {
        Ok(v) => v,
        Err(v) => return v,
    };

    if hs_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Verdict::Pass;
    }

    let hs_len = match record.read_u24() {
        Ok(v) => v,
        Err(v) => return v,
    };

    let mut hs = HandshakeReader::new(record, hs_len);

    if let Err(v) = hs.skip(2) {
        return v;
    }

    let mut random = [0u8; 32];
    if let Err(v) = hs.read_exact(&mut random) {
        return v;
    }

    let session_id_len = match hs.read_u8() {
        Ok(v) => v as usize,
        Err(v) => return v,
    };

    if session_id_len != LEGACY_SESSION_ID_LEN {
        return Verdict::Pass;
    }

    let mut session_id = [0u8; LEGACY_SESSION_ID_LEN];
    if let Err(v) = hs.read_exact(&mut session_id) {
        return v;
    }

    let Ok(part1) = hmac_sha256(shared_secret.as_bytes(), &random[..RANDOM_PREFIX_LEN]) else {
        return Verdict::Pass;
    };

    if !memcmp::eq(&session_id[..PART_LEN], &part1[..PART_LEN]) {
        return Verdict::Pass;
    }

    let cipher_suites_len = match hs.read_u16() {
        Ok(v) => v as usize,
        Err(v) => return v,
    };

    if let Err(v) = hs.skip(cipher_suites_len) {
        return v;
    }

    let compression_len = match hs.read_u8() {
        Ok(v) => v as usize,
        Err(v) => return v,
    };

    if let Err(v) = hs.skip(compression_len) {
        return v;
    }

    let extensions_len = match hs.read_u16() {
        Ok(v) => v as usize,
        Err(v) => return v,
    };

    let mut exts_remaining = extensions_len;
    while exts_remaining >= 4 {
        let ext_type = match hs.read_u16() {
            Ok(v) => v,
            Err(v) => return v,
        };
        let ext_len = match hs.read_u16() {
            Ok(v) => v as usize,
            Err(v) => return v,
        };

        exts_remaining = exts_remaining.saturating_sub(4);

        if ext_len > exts_remaining {
            return Verdict::Pass;
        }

        if ext_type == EXT_KEY_SHARE {
            let key_share = match parse_key_share(&mut hs, ext_len) {
                Ok(v) => v,
                Err(v) => return v,
            };

            if let Some(key_share) = key_share {
                let Ok(part2) = hmac_sha256(shared_secret.as_bytes(), &key_share) else {
                    return Verdict::Pass;
                };

                return if memcmp::eq(&session_id[PART_LEN..], &part2[..PART_LEN]) {
                    Verdict::Claim
                } else {
                    Verdict::Pass
                };
            }

            exts_remaining -= ext_len;
            continue;
        }

        if let Err(v) = hs.skip(ext_len) {
            return v;
        }

        exts_remaining -= ext_len;
    }

    Verdict::Pass
}

fn parse_key_share(hs: &mut HandshakeReader, ext_len: usize) -> Result<Option<[u8; 32]>, Verdict> {
    if ext_len < 2 {
        hs.skip(ext_len)?;
        return Ok(None);
    }

    let list_len = hs.read_u16()? as usize;
    let mut remaining = ext_len - 2;

    if list_len > remaining {
        hs.skip(remaining)?;
        return Ok(None);
    }

    let mut list_remaining = list_len;

    while list_remaining >= 4 {
        let group = hs.read_u16()?;
        let ks_len = hs.read_u16()? as usize;
        list_remaining -= 4;
        remaining -= 4;

        if ks_len > list_remaining {
            hs.skip(list_remaining)?;
            remaining -= list_remaining;
            list_remaining = 0;
            break;
        }

        if group == GROUP_X25519 && ks_len == 32 {
            let mut key_share = [0u8; 32];
            hs.read_exact(&mut key_share)?;
            list_remaining -= 32;
            remaining -= 32;

            if list_remaining > 0 {
                hs.skip(list_remaining)?;
                remaining -= list_remaining;
            }

            if remaining > 0 {
                hs.skip(remaining)?;
            }

            return Ok(Some(key_share));
        }

        hs.skip(ks_len)?;
        list_remaining -= ks_len;
        remaining -= ks_len;
    }

    if list_remaining > 0 {
        hs.skip(list_remaining)?;
        remaining -= list_remaining;
    }

    if remaining > 0 {
        hs.skip(remaining)?;
    }

    Ok(None)
}

struct RecordReader<'a> {
    buf: &'a [u8],
    pos: usize,
    record_remaining: usize,
}

impl<'a> RecordReader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            record_remaining: 0,
        }
    }

    fn read_u8(&mut self) -> Result<u8, Verdict> {
        let mut out = [0u8; 1];
        self.read_exact(&mut out)?;
        Ok(out[0])
    }

    fn read_u24(&mut self) -> Result<usize, Verdict> {
        let mut out = [0u8; 3];
        self.read_exact(&mut out)?;
        Ok(((out[0] as usize) << 16) | ((out[1] as usize) << 8) | out[2] as usize)
    }

    fn read_exact(&mut self, out: &mut [u8]) -> Result<(), Verdict> {
        let mut filled = 0usize;

        while filled < out.len() {
            if self.record_remaining == 0 {
                self.next_record()?;
            }

            let take = core::cmp::min(self.record_remaining, out.len() - filled);
            let end = self.pos + take;

            out[filled..filled + take].copy_from_slice(&self.buf[self.pos..end]);
            self.pos = end;
            self.record_remaining -= take;
            filled += take;
        }

        Ok(())
    }

    fn discard(&mut self, mut len: usize) -> Result<(), Verdict> {
        let mut scratch = [0u8; 256];
        while len > 0 {
            let take = core::cmp::min(len, scratch.len());
            self.read_exact(&mut scratch[..take])?;
            len -= take;
        }
        Ok(())
    }

    fn next_record(&mut self) -> Result<(), Verdict> {
        if self.pos + 5 > self.buf.len() {
            return Err(Verdict::Incomplete);
        }

        let content_type = self.buf[self.pos];
        if content_type != TLS_HANDSHAKE_CONTENT_TYPE {
            return Err(Verdict::Pass);
        }

        let len = u16::from_be_bytes([self.buf[self.pos + 3], self.buf[self.pos + 4]]) as usize;

        self.pos += 5;

        if self.pos + len > self.buf.len() {
            return Err(Verdict::Incomplete);
        }

        self.record_remaining = len;
        Ok(())
    }
}

struct HandshakeReader<'a> {
    record: RecordReader<'a>,
    remaining: usize,
}

impl<'a> HandshakeReader<'a> {
    const fn new(record: RecordReader<'a>, remaining: usize) -> Self {
        Self { record, remaining }
    }

    fn read_exact(&mut self, out: &mut [u8]) -> Result<(), Verdict> {
        if out.len() > self.remaining {
            return Err(Verdict::Pass);
        }
        self.record.read_exact(out)?;
        self.remaining -= out.len();
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, Verdict> {
        let mut out = [0u8; 1];
        self.read_exact(&mut out)?;
        Ok(out[0])
    }

    fn read_u16(&mut self) -> Result<u16, Verdict> {
        let mut out = [0u8; 2];
        self.read_exact(&mut out)?;
        Ok(u16::from_be_bytes(out))
    }

    fn skip(&mut self, len: usize) -> Result<(), Verdict> {
        if len > self.remaining {
            return Err(Verdict::Pass);
        }
        self.record.discard(len)?;
        self.remaining -= len;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::client_hello::client_hello_session_id_callback;
    use boring::ssl::{HandshakeError, Ssl, SslContextBuilder, SslMethod, SslVerifyMode};
    use quiche::Header;
    use std::io::{self, Read, Write};

    #[derive(Default, Debug)]
    struct CaptureStream {
        written: Vec<u8>,
    }

    impl Read for CaptureStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl Write for CaptureStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn generate_client_hello(secret: SharedSecret) -> Vec<u8> {
        let mut ctx = SslContextBuilder::new(SslMethod::tls()).unwrap();
        ctx.set_verify(SslVerifyMode::NONE);
        ctx.set_curves_list("X25519").unwrap();
        ctx.set_client_hello_session_id_callback(client_hello_session_id_callback(secret));

        let ctx = ctx.build();
        let mut ssl = Ssl::new(&ctx).unwrap();
        ssl.set_hostname("example.com").unwrap();

        let mid = ssl.setup_connect(CaptureStream::default());
        let mid = match mid.handshake() {
            Err(HandshakeError::WouldBlock(mid)) => mid,
            Err(err) => panic!("handshake failed: {err:?}"),
            Ok(_) => panic!("handshake unexpectedly completed"),
        };

        mid.into_source_stream().written
    }

    #[test]
    fn classifier_claims_boring_client_hello() {
        let secret = SharedSecret([0x42u8; 32]);
        let client_hello = generate_client_hello(secret);

        assert_eq!(
            classify_tcp_client_hello(&client_hello, &secret),
            Verdict::Claim
        );
    }

    #[test]
    fn classifier_rejects_wrong_secret() {
        let secret = SharedSecret([0x11u8; 32]);
        let client_hello = generate_client_hello(secret);
        let wrong_secret = SharedSecret([0x22u8; 32]);

        assert_eq!(
            classify_tcp_client_hello(&client_hello, &wrong_secret),
            Verdict::Pass
        );
    }

    #[test]
    fn quic_classifier_drops_non_quic() {
        let buf = [0u8; 1];
        assert_eq!(classify_quic_datagram(&buf), QuicVerdict::Drop);
    }

    #[test]
    fn quic_classifier_passes_long_header() {
        let mut buf = Vec::new();
        buf.push(0xC0); // long header + fixed bit + Initial type
        buf.extend_from_slice(&quiche::PROTOCOL_VERSION.to_be_bytes());
        #[allow(clippy::cast_possible_truncation)]
        let dcid_len = QUIC_DCID_PREFIX_LEN as u8; // QUIC_DCID_PREFIX_LEN = 8, fits in u8
        buf.push(dcid_len);
        buf.extend_from_slice(&[0x11; QUIC_DCID_PREFIX_LEN]);
        buf.push(dcid_len);
        buf.extend_from_slice(&[0x22; QUIC_DCID_PREFIX_LEN]);
        buf.push(0x00); // token length = 0

        let header = Header::from_slice(&mut buf, 0).unwrap();
        assert_eq!(header.ty, quiche::Type::Initial);

        assert_eq!(classify_quic_datagram(&buf), QuicVerdict::Pass);
    }

    #[test]
    fn quic_classifier_extracts_short_dcid() {
        let mut buf = Vec::new();
        buf.push(0x40); // short header + fixed bit
        buf.extend_from_slice(&[0xAB; QUIC_DCID_PREFIX_LEN]);

        let header = Header::from_slice(&mut buf, QUIC_DCID_PREFIX_LEN).unwrap();
        assert_eq!(header.ty, quiche::Type::Short);

        match classify_quic_datagram(&buf) {
            QuicVerdict::Short { dcid_prefix } => {
                let mut header_dcid = [0u8; QUIC_DCID_PREFIX_LEN];
                header_dcid.copy_from_slice(header.dcid.iter().as_slice());
                assert_eq!(dcid_prefix, CidPrefix::from(header_dcid));
            }
            other => panic!("expected Short, got {other:?}"),
        }
    }

    #[test]
    fn quic_classifier_drops_short_too_small() {
        let mut buf = vec![0x40];
        buf.extend_from_slice(&[0xAB; QUIC_DCID_PREFIX_LEN - 1]);

        assert_eq!(classify_quic_datagram(&buf), QuicVerdict::Drop);
    }
}
