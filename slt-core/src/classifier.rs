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
///
/// Selection contract: applies the same `X25519` `key_share` selection rule as
/// the client-side [`crate::crypto::client_hello::parse_client_hello`], so the
/// session id it validates matches the one the client derived.
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

            let available = self.buf.len().saturating_sub(self.pos);
            if available == 0 {
                return Err(Verdict::Incomplete);
            }

            let take = core::cmp::min(
                core::cmp::min(self.record_remaining, out.len() - filled),
                available,
            );
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
    use quiche::Header;

    use super::*;
    use crate::crypto::client_hello::{fill_legacy_session_id, parse_client_hello};
    use crate::test_support::generate_client_hello_tls_record;

    #[test]
    fn classifier_claims_boring_client_hello() {
        let secret = SharedSecret([0x42u8; 32]);
        let client_hello = generate_client_hello_tls_record(secret);

        assert_eq!(
            classify_tcp_client_hello(&client_hello, &secret),
            Verdict::Claim
        );
    }

    #[test]
    fn classifier_rejects_wrong_secret() {
        let secret = SharedSecret([0x11u8; 32]);
        let client_hello = generate_client_hello_tls_record(secret);
        let wrong_secret = SharedSecret([0x22u8; 32]);

        assert_eq!(
            classify_tcp_client_hello(&client_hello, &wrong_secret),
            Verdict::Pass
        );
    }

    #[test]
    fn classifier_passes_early_when_session_id_hmac_mismatches() {
        let secret = SharedSecret([0x11u8; 32]);
        let client_hello = generate_client_hello_tls_record(SharedSecret([0x22u8; 32]));
        let through_session_id = 5 + 4 + 2 + 32 + 1 + LEGACY_SESSION_ID_LEN;

        assert_eq!(
            classify_tcp_client_hello(&client_hello[..through_session_id], &secret),
            Verdict::Pass
        );
    }

    #[test]
    fn classifier_waits_for_key_share_when_session_id_hmac_matches() {
        let secret = SharedSecret([0x11u8; 32]);
        let client_hello = generate_client_hello_tls_record(secret);
        let through_session_id = 5 + 4 + 2 + 32 + 1 + LEGACY_SESSION_ID_LEN;

        assert_eq!(
            classify_tcp_client_hello(&client_hello[..through_session_id], &secret),
            Verdict::Incomplete
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
        let dcid_len = QUIC_DCID_PREFIX_LEN as u8; // QUIC_DCID_PREFIX_LEN = 20, fits in u8
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

    /// Build a `ClientHello` handshake message (4-byte handshake header included).
    fn build_client_hello_handshake(
        random: &[u8; 32],
        session_id: &[u8],
        extensions: &[u8],
    ) -> Vec<u8> {
        let cipher_suites: &[u8] = &[0x00, 0x02, 0x13, 0x01]; // len=2 + TLS_AES_128_GCM_SHA256
        let compression: &[u8] = &[0x01, 0x00]; // len=1 + null

        let body_len = 2 // legacy_version
            + 32 // random
            + 1 + session_id.len()
            + cipher_suites.len()
            + compression.len()
            + 2 + extensions.len();

        let mut buf = Vec::with_capacity(4 + body_len);
        buf.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        buf.extend_from_slice(&(body_len as u32).to_be_bytes()[1..]); // u24 length
        buf.extend_from_slice(&[0x03, 0x03]); // legacy_version
        buf.extend_from_slice(random);
        buf.push(session_id.len() as u8);
        buf.extend_from_slice(session_id);
        buf.extend_from_slice(cipher_suites);
        buf.extend_from_slice(compression);
        buf.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        buf.extend_from_slice(extensions);
        buf
    }

    /// Build a `key_share` extension (type + length + list) from ordered entries.
    fn build_key_share_extension(entries: &[(u16, &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (group, key) in entries {
            list.extend_from_slice(&group.to_be_bytes());
            list.extend_from_slice(&(key.len() as u16).to_be_bytes());
            list.extend_from_slice(key);
        }

        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        ext.extend_from_slice(&((2 + list.len()) as u16).to_be_bytes()); // ext_len = list_len field + list
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes()); // list_len
        ext.extend_from_slice(&list);
        ext
    }

    /// Wrap a handshake message in a single TLS handshake record.
    fn wrap_in_tls_record(handshake: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(5 + handshake.len());
        record.push(0x16); // content_type = handshake
        record.extend_from_slice(&[0x03, 0x03]); // legacy_record_version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(handshake);
        record
    }

    #[test]
    fn both_parsers_select_x25519_among_multiple_key_share_entries() {
        // The key_share extension lists a non-X25519 group both before and after
        // the X25519 entry, exercising the selection rule (first X25519 with a
        // 32-byte key) that the client-side extractor and the streaming
        // classifier must apply identically for the session id to round-trip.
        const SECP256R1: u16 = 0x0017;

        let secret = SharedSecret([0x42u8; 32]);
        let random = [0xABu8; 32];
        let x25519_key = [0x55u8; 32];
        let leading_key = [0x11u8; 65]; // secp256r1 point length; must be ignored
        let trailing_key = [0x77u8; 65];

        let entries: &[(u16, &[u8])] = &[
            (SECP256R1, &leading_key),
            (GROUP_X25519, &x25519_key),
            (SECP256R1, &trailing_key),
        ];
        let extensions = build_key_share_extension(entries);

        // Derive the authoritative session id via the client-side path
        // (parse_client_hello + fill_legacy_session_id), then bake it in.
        let placeholder = build_client_hello_handshake(&random, &[0u8; 32], &extensions);
        let mut session_id = [0u8; 32];
        fill_legacy_session_id(&placeholder, &mut session_id, &secret).unwrap();
        let handshake = build_client_hello_handshake(&random, &session_id, &extensions);

        // Parser 1 (random access, client side) selects the X25519 entry.
        assert_eq!(
            parse_client_hello(&handshake),
            Some((random, x25519_key)),
            "parse_client_hello must select the X25519 entry, not a neighboring group"
        );

        // Parser 2 (streaming, server side) derives the same inputs and accepts.
        let record = wrap_in_tls_record(&handshake);
        assert_eq!(
            classify_tcp_client_hello(&record, &secret),
            Verdict::Claim,
            "classifier must agree with parse_client_hello on the selected key share"
        );
    }
}
