# UDP-QSP Packet Protection

UDP-QSP (QUIC-Shaped Packet protection) provides encrypted UDP transport for VPN data
using QUIC short-header wire format. It is **not** actual QUIC -- there is no QUIC
handshake, congestion control, or stream multiplexing. Only the packet protection
scheme and short-header layout are borrowed from QUIC to make VPN traffic indistinguishable
from legitimate QUIC traffic on the wire.

## 1. Overview

UDP-QSP is activated after a client completes TCP authentication and registers a
connection ID (CID) via `REGISTER_CID`. Once active:

- All VPN data frames travel over UDP with QUIC short headers
- Keys are provisioned during registration (HP, AEAD, IV for each direction)
- Packet numbers are monotonically increasing u64 values (no wraparound allowed)
- Key updates happen in-band via the key phase bit

## 2. Short Header Layout

```
 +--------+------------------+------------------+-------------------+
 | 1 byte |    DCID (var)    |   PN (1-4 bytes) | Ciphertext || Tag |
 +--------+------------------+------------------+-------------------+
```

### First Byte Structure

```
Bit 7: Header Form (MUST be 0 for short header)
Bit 6: Fixed Bit (MUST be 1)
Bit 5: Spin Bit (unused, SHOULD be 0, receiver ignores)
Bits 4-3: Reserved (MUST be 0 on transmit and on receive after HP removal)
Bit 2: Key Phase (0 or 1)
Bits 1-0: Packet Number Length minus 1 (00=1 byte, 01=2 bytes, 10=3 bytes, 11=4 bytes)
```

**Constant**: `FIXED_BIT = 0x40`

### DCID Field

The Destination Connection ID (DCID) identifies the receiving endpoint. For UDP-QSP:

- Maximum length: 20 bytes (`MAX_DCID_LEN`)
- The first `QUIC_DCID_PREFIX_LEN` (20) bytes are used for server-side classification
- DCID length is negotiated during `REGISTER_CID`

### Packet Number Field

- Encoded as 1-4 bytes in big-endian order
- Sender MUST use the minimum length required to encode the PN
- Full PN space is u64; wrapping is not allowed
- Length selection (from `packet_number_len`):

| PN Range | Bytes on Wire |
|----------|---------------|
| 0x00 - 0xFF | 1 |
| 0x100 - 0xFFFF | 2 |
| 0x10000 - 0xFFFFFF | 3 |
| 0x1000000+ | 4 |

## 3. Header Protection (HP)

Header protection obscures the first byte (except the fixed bit's position) and the
packet number bytes. The mask algorithm follows the cipher suite selected in
`REGISTER_CID`:

- AES-128-GCM uses AES-128-ECB mask derivation (QUIC's AES HP).
- ChaCha20-Poly1305 uses a single-block ChaCha20 mask derivation (QUIC's ChaCha HP).

### Constants

| Constant | Value | Source |
|----------|-------|--------|
| `HP_SAMPLE_LEN` | 16 bytes | `slt-core/src/crypto/udp_qsp/mod.rs` |
| `HP_MASK_LEN` | 5 bytes | `slt-core/src/crypto/udp_qsp/mod.rs` |
| `HP_KEY_LEN` | 16 bytes (AES-128-GCM) | `slt-core/src/proto/mod.rs` |
| `CHACHA20_POLY1305_KEY_LEN` | 32 bytes (ChaCha20-Poly1305) | `slt-core/src/proto/mod.rs` |

### Sample Location

The HP sample is taken from the ciphertext portion of the packet:

```
sample_offset = 1 + dcid_len + 4
sample_range = sample_offset .. (sample_offset + 16)
```

The sample starts 4 bytes after the PN field begins, ensuring sufficient ciphertext
is available for the mask derivation.

### Mask Derivation

**AES-128-GCM**

```
mask = AES-128-ECB-encrypt(hp_key, sample)[0..5]
```

The 16-byte sample is encrypted with AES-128-ECB using the 16-byte HP key. The first
5 bytes of the output form the mask.

**ChaCha20-Poly1305**

```
counter = u32::from_le_bytes(sample[0..4])
nonce   = sample[4..16]
mask    = CRYPTO_chacha_20(hp_key, nonce, counter, zeros[0..5])
```

The 16-byte sample is split into a 4-byte little-endian counter and a 12-byte nonce.
`CRYPTO_chacha_20` encrypts five zero bytes to produce the 5-byte mask. This matches
QUIC's ChaCha20 header protection.

### Applying the Mask

```rust
first_byte ^= mask[0] & 0x1f;  // Protect bits 0-4 (preserves bits 5-7)
for i in 0..pn_len {
    pn_byte[i] ^= mask[1 + i];  // Protect each PN byte
}
```

The first byte mask preserves:
- Bit 7 (header form) -- already known to be 0
- Bit 6 (fixed bit) -- already known to be 1
- Bit 5 (spin bit) -- unprotected, but receiver ignores

## 4. AEAD Payload Protection

The payload (VPN frame) is encrypted using AEAD with the packet number as the nonce
counter.

### Constants

| Constant | Value | Source |
|----------|-------|--------|
| `AEAD_TAG_LEN` | 16 bytes (both suites) | `slt-core/src/crypto/udp_qsp/mod.rs` |
| `AEAD_KEY_LEN` | 16 bytes (AES-128-GCM) | `slt-core/src/proto/mod.rs` |
| `CHACHA20_POLY1305_KEY_LEN` | 32 bytes (ChaCha20-Poly1305) | `slt-core/src/proto/mod.rs` |
| `AEAD_IV_LEN` | 12 bytes (both suites) | `slt-core/src/proto/mod.rs` |

### Cipher Suites

| Cipher constant | `cipher` | AEAD | Key | Tag |
|-----------------|----------|------|----:|----:|
| `CipherSuite::Aes128Gcm` | 0x01 | AES-128-GCM (BoringSSL `EVP_aead_aes_128_gcm`) | 16 | 16 |
| `CipherSuite::ChaCha20Poly1305` | 0x02 | ChaCha20-Poly1305 (BoringSSL `EVP_aead_chacha20_poly1305`) | 32 | 16 |

Both suites use a 96-bit nonce and a 128-bit authentication tag. The cipher is chosen
by the client in `REGISTER_CID` and accepted by the server subject to its
`allowed_ciphers` policy.

### Nonce Construction

The 12-byte nonce is constructed by XORing the IV with the packet number:

```rust
fn make_nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn_bytes = pn.to_be_bytes();  // 8 bytes, big-endian
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];  // XOR into last 8 bytes
    }
    nonce
}
```

### Associated Data (AD)

The AD is the **unprotected** header:

```
AD = first_byte || dcid || pn_bytes
```

The key phase bit and PN length in the AD reflect the values **before** header
protection is applied.

### Encryption Output

```
ciphertext || tag = AEAD-Seal(key, nonce, ad, plaintext)
```

`AEAD-Seal` is AES-128-GCM or ChaCha20-Poly1305 per the negotiated suite.

## 5. Padding Requirements

To ensure sufficient data for the HP sample, the packet must satisfy:

```
ciphertext_len >= sample_offset + HP_SAMPLE_LEN - header_len
```

Or equivalently, the padded plaintext must satisfy:

```
min_cipher_len = (1 + dcid_len + 4 + 16) - (1 + dcid_len + pn_len)
               = 20 - pn_len
pad_len = max(0, min_cipher_len - plaintext_len - AEAD_TAG_LEN)
```

**Implementation** (`protect_into` in `keys.rs`):
1. Calculate required padding to ensure `ciphertext_len >= min_cipher_len`
2. Append zero bytes to plaintext before encryption
3. Receivers ignore trailing zeros after decoding the framed message

## 6. Packet Number Reconstruction

Since PNs are transmitted with only 1-4 bytes, receivers must reconstruct the full
u64 value using the expected next packet number.

### Definitions

Per CID, per direction:
- `largest_pn`: highest PN successfully accepted
- `expected = largest_pn + 1` (or initial expected PN if no packets received)
- `pn_nbits = pn_len * 8`
- `pn_win = 1 << pn_nbits`
- `pn_hwin = pn_win / 2`
- `pn_mask = pn_win - 1`

### Reconstruction Algorithm

From `reconstruct_packet_number` in `pn.rs`:

```rust
fn reconstruct_packet_number(truncated_pn: u64, expected_pn: u64, pn_len: usize) -> u64 {
    let pn_window = 1u64 << (pn_len * 8);
    let pn_half_window = pn_window / 2;
    let pn_mask = pn_window - 1;

    // Start with the expected PN's high bits
    let mut candidate = (expected_pn & !pn_mask) | truncated_pn;

    // If candidate is too far behind expected, advance by one window
    if candidate.saturating_add(pn_half_window) <= expected_pn {
        candidate = candidate.saturating_add(pn_window);
    }

    // If candidate is too far ahead of expected, retreat by one window
    if candidate > expected_pn.saturating_add(pn_half_window) && candidate >= pn_window {
        candidate -= pn_window;
    }

    candidate
}
```

### Example

With `expected = 0x00AB_CDEF` and receiving `truncated = 0x1234` (2-byte PN):

```
pn_window = 0x10000
pn_mask = 0xFFFF
candidate = (0x00AB_CDEF & !0xFFFF) | 0x1234 = 0x00AB_0000 | 0x1234 = 0x00AB_1234
```

Since `0x00AB_1234 + 0x8000 < 0x00AB_CDEF`, the forward-window adjustment is applied.
Result: `0x00AC_1234`

## 7. Replay Protection

Each CID maintains a replay window to accept reordered packets while rejecting
duplicates and very old packets.

### Constants

| Constant | Value | Source |
|----------|-------|--------|
| `PN_REPLAY_WINDOW` | 1024 | `slt-core/src/crypto/udp_qsp/session.rs` |

### Window Structure

The replay window uses a 1024-bit bitmap (16 x u64 words) stored as a ring buffer:

```rust
const WINDOW_WORD_BITS: usize = 64;
const WINDOW_WORDS: usize = PN_REPLAY_WINDOW / WINDOW_WORD_BITS; // 16
```

### Accept/Reject Rules

From `ReplayWindow::check_and_update`:

1. **First packet**: Accept and set as `largest_pn`
2. **PN > largest_pn**:
   - Accept
   - Slide window forward
   - Update `largest_pn`
3. **PN <= largest_pn**:
   - Calculate `delta = largest_pn - pn`
   - If `delta >= PN_REPLAY_WINDOW`: **Reject (TooOld)**
   - If bit `delta` is already set: **Reject (Replay)**
   - Otherwise: Set bit and **Accept**

### Ring Buffer Implementation

```rust
fn bit_position(pn: u64) -> (usize, u64) {
    let idx = (pn % PN_REPLAY_WINDOW as u64) as usize;
    let word = idx / WINDOW_WORD_BITS;  // Which u64 word
    let bit = idx % WINDOW_WORD_BITS;   // Which bit in that word
    (word, 1u64 << bit)
}
```

This avoids shifting the entire bitmap on each packet.

## 8. Key Update (Key Phase)

Key updates rotate all directional keys (HP, AEAD key, IV) in-band without
re-transmitting `REGISTER_CID`.

### Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `KEY_UPDATE_INTERVAL` | 2^21 (2097152) | Packets per key phase |
| `KEY_UPDATE_LATE_MARGIN` | 8192 | Margin for accepting old keys |

### Sender Behavior

1. When `next_pn` crosses a multiple of `KEY_UPDATE_INTERVAL`:
   - Derive new TX keys via HKDF from the current traffic secret
   - Flip `tx_key_phase`
   - Continue sending with new keys

### Receiver Behavior

The receiver maintains up to three key states:
- `current`: Active decryption keys
- `previous`: Keys from prior phase (valid within grace window)
- `candidate`: Ephemeral keys derived for rekey detection

On packet receipt:
1. Try `current` keys first; accept if key phase matches
2. If within grace window and key phase differs, try `previous` keys
3. If near expected rekey threshold, derive and try `candidate` keys
4. On `candidate` success: promote (`previous = current`, `current = candidate`)
5. Drop packets that fail authentication without changing channel-liveness state

### Key Derivation

Initial packet material is derived from the directional traffic secrets carried
in `REGISTER_CID`. Key updates use the RFC 9001/TLS 1.3 label schedule:

```rust
hp_key   = HKDF-Expand-Label(secret, "quic hp",  "", hp_len)
aead_key = HKDF-Expand-Label(secret, "quic key", "", aead_len)
iv       = HKDF-Expand-Label(secret, "quic iv",  "", 12)

next_secret = HKDF-Expand-Label(secret, "quic ku", "", 32)
```

Header-protection keys are derived from the initial directional secret and remain
stable across key updates. AEAD keys and IVs are re-derived from each updated
traffic secret. See [key-update.md](key-update.md) for the full derivation.

## 9. UDP-QSP Payload Format

Each UDP datagram carries exactly one framed VPN message using the same format as TCP:

```
TYPE: u8
LEN:  u32 (big-endian)
PAYLOAD: LEN bytes
```

### Allowed Message Types

| Type | Code | Direction |
|------|------|-----------|
| DATA | 0x0a | Both |
| PING | 0x07 | Both |
| PONG | 0x08 | Both |
| CLOSE | 0x09 | Both |
| UPGRADE_PROBE | 0x0b | Client -> Server |
| UPGRADE_PROBE_ACK | 0x0c | Server -> Client |

TCP-only messages (AUTH, REGISTER_*, UDP_READY, SWITCH_*, etc.) are never sent on UDP-QSP.

## 10. Error Handling

Packets with any of the following conditions MUST be silently dropped:

- Invalid first byte (missing fixed bit or long header bit set)
- Reserved bits non-zero after HP removal
- Packet too short for HP sample
- Packet too short for PN + AEAD tag
- AEAD authentication failure
- Replay detected
- Packet older than replay window

An authenticated packet whose plaintext does not contain one complete framed VPN
message is a protocol violation. The endpoint terminates the session with
`ProtocolError`.

The implementation returns structured errors via `QspCryptoError` and `QspSessionError`.

## 11. Server Peer Address Migration

The server learns the client's UDP reply address from authenticated client-to-server
packets. It maintains a peer-selection watermark containing the highest reconstructed
packet number that selected the current address.

After AEAD authentication and replay acceptance:

- The first accepted packet establishes the reply address and watermark.
- A packet with a number strictly greater than the watermark updates both the reply
  address and watermark, even when the address itself is unchanged.
- An unseen out-of-order packet at or below the watermark is processed normally but
  MUST NOT change the reply address.
- A successful `REGISTER_CID` starts a new UDP-QSP packet-number space and resets the
  peer-selection watermark.

Protected packets buffered for send but not submitted to the UDP socket use the current
reply address when flushed. A peer update therefore retargets those buffered packets.
Datagrams already submitted to the socket cannot be redirected and may still arrive on
the prior path.
