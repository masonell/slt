use boring::error::ErrorStack;
use boring::hash::hmac_sha256;
use boring::ssl::SslRef;

/// TLS `HandshakeType` value for `ClientHello`.
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// Expected `legacy_session_id` length used by the classifier.
pub const LEGACY_SESSION_ID_LEN: usize = 32;
/// Truncated HMAC length per part.
pub const PART_LEN: usize = 16;
/// Prefix length of `ClientHello` random used for the first HMAC.
pub const RANDOM_PREFIX_LEN: usize = 16;
/// Extension type for `key_share`.
pub const EXT_KEY_SHARE: u16 = 0x0033;
/// `NamedGroup` for `X25519`.
pub const GROUP_X25519: u16 = 0x001d;

/// Parse a serialized `ClientHello` (including handshake header) and extract
/// the legacy random and `X25519` `key_share`.
///
/// Returns `None` if the buffer is malformed or does not contain an `X25519`
/// `key_share`.
pub fn parse_client_hello(client_hello: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if client_hello.len() < 4 {
        return None;
    }

    if client_hello[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }

    let hs_len = ((client_hello[1] as usize) << 16)
        | ((client_hello[2] as usize) << 8)
        | (client_hello[3] as usize);
    if client_hello.len() < 4 + hs_len {
        return None;
    }

    let mut pos = 4;
    if pos + 2 + 32 + 1 > 4 + hs_len {
        return None;
    }

    pos += 2; // legacy_version

    let mut random = [0u8; 32];
    random.copy_from_slice(&client_hello[pos..pos + 32]);
    pos += 32;

    let session_id_len = client_hello[pos] as usize;
    pos += 1;
    if pos + session_id_len > 4 + hs_len {
        return None;
    }
    pos += session_id_len;

    if pos + 2 > 4 + hs_len {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_suites_len > 4 + hs_len {
        return None;
    }
    pos += cipher_suites_len;

    if pos + 1 > 4 + hs_len {
        return None;
    }
    let compression_len = client_hello[pos] as usize;
    pos += 1;
    if pos + compression_len > 4 + hs_len {
        return None;
    }
    pos += compression_len;

    if pos + 2 > 4 + hs_len {
        return None;
    }
    let extensions_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
    pos += 2;
    if pos + extensions_len > 4 + hs_len {
        return None;
    }

    let mut ext_pos = pos;
    let ext_end = pos + extensions_len;
    while ext_pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([client_hello[ext_pos], client_hello[ext_pos + 1]]);
        let ext_len =
            u16::from_be_bytes([client_hello[ext_pos + 2], client_hello[ext_pos + 3]]) as usize;
        ext_pos += 4;
        if ext_pos + ext_len > ext_end {
            return None;
        }

        if ext_type == EXT_KEY_SHARE {
            if ext_len < 2 {
                return None;
            }
            let list_len =
                u16::from_be_bytes([client_hello[ext_pos], client_hello[ext_pos + 1]]) as usize;
            let mut list_pos = ext_pos + 2;
            let list_end = ext_pos + 2 + list_len;
            if list_end > ext_pos + ext_len {
                return None;
            }

            while list_pos + 4 <= list_end {
                let group =
                    u16::from_be_bytes([client_hello[list_pos], client_hello[list_pos + 1]]);
                let ks_len =
                    u16::from_be_bytes([client_hello[list_pos + 2], client_hello[list_pos + 3]])
                        as usize;
                list_pos += 4;
                if list_pos + ks_len > list_end {
                    return None;
                }

                if group == GROUP_X25519 && ks_len == 32 {
                    let mut key_share = [0u8; 32];
                    key_share.copy_from_slice(&client_hello[list_pos..list_pos + 32]);
                    return Some((random, key_share));
                }

                list_pos += ks_len;
            }
        }

        ext_pos += ext_len;
    }

    None
}

/// Fill the `legacy_session_id` based on `ClientHello` random and `key_share`.
///
/// This computes two truncated HMAC-SHA256 parts and writes them into the
/// provided `session_id` buffer.
pub fn fill_legacy_session_id(
    client_hello: &[u8],
    session_id: &mut [u8],
    secret: &[u8],
) -> Result<(), ErrorStack> {
    if session_id.len() != LEGACY_SESSION_ID_LEN {
        return Err(ErrorStack::get());
    }

    let (random, key_share) = match parse_client_hello(client_hello) {
        Some(v) => v,
        None => return Err(ErrorStack::get()),
    };

    let part1 = hmac_sha256(secret, &random[..RANDOM_PREFIX_LEN])?;
    let part2 = hmac_sha256(secret, &key_share)?;

    session_id[..PART_LEN].copy_from_slice(&part1[..PART_LEN]);
    session_id[PART_LEN..].copy_from_slice(&part2[..PART_LEN]);

    Ok(())
}

/// Helper to build a `BoringSSL` callback that overwrites `legacy_session_id`.
///
/// The callback uses `secret` to fill the `session_id` based on `ClientHello`
/// random and `X25519` `key_share`.
pub fn client_hello_session_id_callback(
    secret: [u8; 32],
) -> impl Fn(&mut SslRef, &[u8], &mut [u8]) -> Result<(), ErrorStack> + Sync + Send + 'static {
    move |_ssl, client_hello, session_id| fill_legacy_session_id(client_hello, session_id, &secret)
}
