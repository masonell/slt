use boring::memcmp;

use crate::crypto::client_hello::{
    HANDSHAKE_TYPE_CLIENT_HELLO, LEGACY_SESSION_ID_LEN, MAX_TCP_CLIENT_HELLO_WIRE_LEN,
    TOKEN_PART_LEN, candidate_session_id_tag, verify_legacy_session_id,
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
const TLS_RECORD_HEADER_LEN: usize = 5;

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
/// The classifier verifies the candidate half of `legacy_session_id` as soon
/// as the random and session ID are available. A matching candidate remains
/// incomplete until the complete first `ClientHello` verifies its full-message
/// claim tag, so no mutable suffix can reach the VPN TLS acceptor unchecked. A
/// `ClientHello` that ends beyond [`MAX_TCP_CLIENT_HELLO_WIRE_LEN`] is passed as
/// ordinary HTTPS traffic.
#[must_use]
pub fn classify_tcp_client_hello(input: &[u8], shared_secret: &SharedSecret) -> Verdict {
    let verdict = classify_tcp_client_hello_within_limit(input, shared_secret);
    if verdict == Verdict::Incomplete && input.len() >= MAX_TCP_CLIENT_HELLO_WIRE_LEN {
        Verdict::Pass
    } else {
        verdict
    }
}

fn classify_tcp_client_hello_within_limit(input: &[u8], shared_secret: &SharedSecret) -> Verdict {
    let mut record = RecordReader::new(input);

    let mut handshake_header = [0u8; 4];
    if let Err(v) = record.read_exact(&mut handshake_header) {
        return v;
    }

    if handshake_header[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Verdict::Pass;
    }

    let hs_len = ((handshake_header[1] as usize) << 16)
        | ((handshake_header[2] as usize) << 8)
        | handshake_header[3] as usize;
    let minimum_wire_len = TLS_RECORD_HEADER_LEN + handshake_header.len() + hs_len;
    if minimum_wire_len > MAX_TCP_CLIENT_HELLO_WIRE_LEN {
        return Verdict::Pass;
    }
    let mut hs = HandshakeReader::new(record, hs_len);

    let mut legacy_version = [0u8; 2];
    if let Err(v) = hs.read_exact(&mut legacy_version) {
        return v;
    }

    let mut random = [0u8; 32];
    if let Err(v) = hs.read_exact(&mut random) {
        return v;
    }

    let mut session_id_len = [0u8; 1];
    if let Err(v) = hs.read_exact(&mut session_id_len) {
        return v;
    }

    if usize::from(session_id_len[0]) != LEGACY_SESSION_ID_LEN {
        return Verdict::Pass;
    }

    let mut session_id = [0u8; LEGACY_SESSION_ID_LEN];
    if let Err(v) = hs.read_exact(&mut session_id) {
        return v;
    }

    let Ok(candidate) = candidate_session_id_tag(&random, shared_secret) else {
        return Verdict::Pass;
    };

    if !memcmp::eq(&session_id[..TOKEN_PART_LEN], &candidate) {
        return Verdict::Pass;
    }

    let mut client_hello = Vec::with_capacity(input.len().min(4usize.saturating_add(hs_len)));
    client_hello.extend_from_slice(&handshake_header);
    client_hello.extend_from_slice(&legacy_version);
    client_hello.extend_from_slice(&random);
    client_hello.extend_from_slice(&session_id_len);
    client_hello.extend_from_slice(&session_id);
    if let Err(v) = hs.read_remaining_into(&mut client_hello) {
        return v;
    }
    if hs.wire_bytes_read() > MAX_TCP_CLIENT_HELLO_WIRE_LEN {
        return Verdict::Pass;
    }

    match verify_legacy_session_id(&client_hello, shared_secret) {
        Ok(true) => Verdict::Claim,
        Ok(false) | Err(_) => Verdict::Pass,
    }
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

    fn read_remaining_into(&mut self, output: &mut Vec<u8>) -> Result<(), Verdict> {
        let mut chunk = [0u8; 256];
        while self.remaining > 0 {
            let len = self.remaining.min(chunk.len());
            self.read_exact(&mut chunk[..len])?;
            output.extend_from_slice(&chunk[..len]);
        }
        Ok(())
    }

    const fn wire_bytes_read(&self) -> usize {
        self.record.pos
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use quiche::Header;

    use super::*;
    use crate::test_support::{
        fragment_client_hello_tls_record, generate_client_hello_tls_record,
        generate_sized_client_hello_tls_record,
    };

    const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

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
    fn classifier_waits_for_complete_boring_client_hello() {
        let secret = SharedSecret([0x42u8; 32]);
        let client_hello = generate_client_hello_tls_record(secret);
        let first_claim_len = (0..=client_hello.len())
            .find(|&len| classify_tcp_client_hello(&client_hello[..len], &secret) == Verdict::Claim)
            .expect("complete ClientHello should be claimed");

        for prefix_len in 0..first_claim_len {
            assert_eq!(
                classify_tcp_client_hello(&client_hello[..prefix_len], &secret),
                Verdict::Incomplete,
                "valid ClientHello prefix of {prefix_len} bytes must remain incomplete"
            );
        }

        for prefix_len in first_claim_len..=client_hello.len() {
            assert_eq!(
                classify_tcp_client_hello(&client_hello[..prefix_len], &secret),
                Verdict::Claim,
                "ClientHello prefix of {prefix_len} bytes contains the complete claim token input"
            );
        }
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
    fn classifier_waits_for_full_claim_tag_when_candidate_matches() {
        let secret = SharedSecret([0x11u8; 32]);
        let client_hello = generate_client_hello_tls_record(secret);
        let through_session_id = 5 + 4 + 2 + 32 + 1 + LEGACY_SESSION_ID_LEN;

        assert_eq!(
            classify_tcp_client_hello(&client_hello[..through_session_id], &secret),
            Verdict::Incomplete
        );
    }

    #[test]
    fn classifier_passes_supported_versions_downgrade_after_full_verification() {
        let secret = SharedSecret([0x42u8; 32]);
        let mut client_hello = generate_client_hello_tls_record(secret);
        let version_range = supported_versions_range(&client_hello);
        let versions = &mut client_hello[version_range];

        let mut replaced = false;
        for version in versions[1..].chunks_exact_mut(2) {
            if version == [0x03, 0x04] {
                version.copy_from_slice(&[0x03, 0x03]);
                replaced = true;
            }
        }
        assert!(replaced, "generated ClientHello must offer TLS 1.3");

        assert_eq!(
            classify_tcp_client_hello(&client_hello, &secret),
            Verdict::Pass
        );
    }

    #[test]
    fn classifier_claims_client_hello_spanning_tls_records() {
        let secret = SharedSecret([0x42u8; 32]);
        let client_hello = generate_client_hello_tls_record(secret);
        let handshake = &client_hello[TLS_RECORD_HEADER_LEN..];
        let split = handshake.len() / 2;
        let mut fragmented = Vec::with_capacity(client_hello.len() + TLS_RECORD_HEADER_LEN);

        append_tls_record(&mut fragmented, &handshake[..split]);
        append_tls_record(&mut fragmented, &handshake[split..]);

        assert_eq!(
            classify_tcp_client_hello(&fragmented, &secret),
            Verdict::Claim
        );
    }

    #[test]
    fn classifier_claims_client_hello_ending_at_wire_ceiling() {
        let secret = SharedSecret([0x42u8; 32]);
        let client_hello =
            generate_sized_client_hello_tls_record(secret, MAX_TCP_CLIENT_HELLO_WIRE_LEN);

        assert_eq!(client_hello.len(), MAX_TCP_CLIENT_HELLO_WIRE_LEN);
        assert_eq!(
            classify_tcp_client_hello(&client_hello, &secret),
            Verdict::Claim
        );
    }

    #[test]
    fn classifier_passes_client_hello_message_beyond_wire_ceiling() {
        let secret = SharedSecret([0x42u8; 32]);
        let client_hello =
            generate_sized_client_hello_tls_record(secret, MAX_TCP_CLIENT_HELLO_WIRE_LEN + 1);

        assert_eq!(
            classify_tcp_client_hello(&client_hello, &secret),
            Verdict::Pass
        );
    }

    #[test]
    fn classifier_counts_tls_record_headers_toward_wire_ceiling() {
        let secret = SharedSecret([0x42u8; 32]);
        let client_hello = generate_sized_client_hello_tls_record(
            secret,
            MAX_TCP_CLIENT_HELLO_WIRE_LEN - TLS_RECORD_HEADER_LEN,
        );
        let at_ceiling = fragment_client_hello_tls_record(&client_hello, 2);
        let beyond_ceiling = fragment_client_hello_tls_record(&client_hello, 3);

        assert_eq!(at_ceiling.len(), MAX_TCP_CLIENT_HELLO_WIRE_LEN);
        assert_eq!(
            classify_tcp_client_hello(&at_ceiling, &secret),
            Verdict::Claim
        );
        assert!(beyond_ceiling.len() > MAX_TCP_CLIENT_HELLO_WIRE_LEN);
        assert_eq!(
            classify_tcp_client_hello(&beyond_ceiling, &secret),
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

    fn append_tls_record(output: &mut Vec<u8>, payload: &[u8]) {
        output.push(TLS_HANDSHAKE_CONTENT_TYPE);
        output.extend_from_slice(&[0x03, 0x03]);
        output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        output.extend_from_slice(payload);
    }

    fn supported_versions_range(client_hello: &[u8]) -> Range<usize> {
        let handshake = &client_hello[TLS_RECORD_HEADER_LEN..];
        assert_eq!(handshake[0], HANDSHAKE_TYPE_CLIENT_HELLO);

        let mut pos = 4 + 2 + 32;
        let session_id_len = handshake[pos] as usize;
        pos += 1 + session_id_len;

        let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;

        let compression_methods_len = handshake[pos] as usize;
        pos += 1 + compression_methods_len;

        let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
        pos += 2;
        let extensions_end = pos + extensions_len;

        while pos < extensions_end {
            let extension_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
            let extension_len =
                u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
            let value_start = pos + 4;
            let value_end = value_start + extension_len;
            assert!(value_end <= extensions_end);

            if extension_type == EXT_SUPPORTED_VERSIONS {
                return (TLS_RECORD_HEADER_LEN + value_start)..(TLS_RECORD_HEADER_LEN + value_end);
            }
            pos = value_end;
        }

        panic!("generated ClientHello must contain supported_versions");
    }
}
