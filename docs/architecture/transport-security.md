# Transport Security Model

This document describes the security properties of SLT's two transport modes:
TCP with TLS, and UDP-QSP (QUIC-shaped packet protection).

## 1. Overview

SLT uses two transport modes with distinct security properties:

| Property | TCP | UDP-QSP |
|----------|-----|---------|
| Protocol | TLS 1.3 | Custom (QUIC wire format) |
| Termination | VPN handler | N/A (already encrypted) |
| Key Exchange | TLS handshake | Via TCP control channel |
| Libraries | BoringSSL (patched) | BoringSSL (AES-128-GCM) |
| Use Case | Control plane + fallback | High-performance data plane |

The client starts on TCP, authenticates, and may later upgrade to UDP-QSP for
data traffic. TCP remains available as a fallback if UDP-QSP fails.

## 2. TCP Security (TLS with BoringSSL)

### 2.1 Why BoringSSL

SLT uses BoringSSL (via the `boring` and `boring-sys` crates) instead of
rustls or OpenSSL for a specific reason: the VPN traffic classifier needs to
embed a cryptographic token in the TLS ClientHello `legacy_session_id` field.

This requires a custom TLS hook that:

1. Fires after the `random` and `key_share` values are generated
2. Fires before the ClientHello transcript hash is computed
3. Allows overwriting the `legacy_session_id` with a computed value

BoringSSL provides the necessary low-level hooks to implement this callback.
See `slt-core/src/crypto/client_hello.rs` for the implementation.

### 2.2 ClientHello Token Construction

The classifier token allows the server to identify VPN clients without
terminating TLS for unknown traffic. The token is constructed as:

```
session_id = part1 || part2

part1 = HMAC-SHA256(random[0:16] || server_secret)[:16]
part2 = HMAC-SHA256(key_share || server_secret)[:16]
```

Where:

- `random` is the ClientHello's 32-byte random field (first 16 bytes used)
- `key_share` is the X25519 key share (32 bytes)
- Both HMAC outputs are truncated to 16 bytes
- Total `legacy_session_id` length is exactly 32 bytes

### 2.3 TLS Termination

**VPN connections**: The VPN handler terminates TLS and runs the VPN protocol
over the decrypted stream. This is where authentication (AUTH/AUTH_OK) occurs.

**Unknown connections**: Connections that fail the classifier check are passed
through to nginx without TLS termination. The wrapper pipes bytes
bidirectionally between the client and nginx's TLS endpoint on `127.0.0.1:8443`.
This ensures real HTTPS and HTTP/3 traffic reaches nginx unchanged.

## 3. UDP-QSP Security (QUIC-shaped, Custom)

UDP-QSP uses QUIC short-header wire format for packet protection, but it is
**not** QUIC. There is no QUIC handshake on the VPN path; all QUIC long-header
traffic is forwarded to nginx.

### 3.1 Wire Format

UDP-QSP packets use QUIC short headers:

```
first_byte | dcid | pn | ciphertext || tag
```

First byte bits:

- Bit 7: Header form (MUST be 0 for short header)
- Bit 6: Fixed bit (MUST be 1)
- Bit 5: Spin bit (unused, SHOULD be 0)
- Bits 4-3: Reserved (MUST be 0)
- Bit 2: Key phase
- Bits 1-0: Packet number length minus 1 (0-3 for lengths 1-4)

Constants:

- `HP_MASK_LEN = 5` bytes
- `HP_SAMPLE_LEN = 16` bytes
- `AEAD_TAG_LEN = 16` bytes

### 3.2 Key Negotiation

Keys are **not** derived from a QUIC handshake. Instead:

1. Client establishes a real QUIC connection to nginx (for wire-shape cover)
2. Client sends `REGISTER_CID` over the **TCP control channel** with:
   - DCID to use for UDP-QSP
   - UDP-QSP keys (HP + AEAD, both directions)
   - Initial packet numbers and key phase
3. Server validates, stores keys in `cid_map`, replies `REGISTER_OK`
4. Client may now send UDP-QSP packets with that DCID

### 3.3 Header Protection (HP)

Header protection masks the packet number length, key phase, and reserved bits
in the first byte, plus the packet number bytes themselves.

**Algorithm**: AES-128-ECB on a 16-byte sample

```
sample_offset = 1 + dcid_len + 4
sample = packet[sample_offset .. sample_offset + 16]
mask = AES-128-ECB(hp_key, sample)

first_byte ^= mask[0] & 0x1f
pn[i] ^= mask[1 + i]  for i in 0..pn_len
```

The sample is taken from the ciphertext portion, after the header. Senders
MUST pad packets that would be too short to provide a 16-byte sample.

### 3.4 AEAD Payload Protection

**Cipher**: AES-128-GCM (tag length 16 bytes)

**Nonce construction**:

```
nonce = iv XOR pn
```

Where `pn` is the full 64-bit packet number, XORed into the last 8 bytes of
the 12-byte IV.

**Associated data (AD)**: The unprotected header (first_byte + dcid + pn)

**Encryption**:

```
ciphertext || tag = AES-128-GCM-Seal(key, nonce, ad, plaintext)
```

### 3.5 Key Directionality

UDP-QSP uses separate keys for each direction:

| Key | Client Uses For | Server Uses For |
|-----|-----------------|-----------------|
| `hp_tx` | Sending packets | Sending packets |
| `hp_rx` | Receiving packets | Receiving packets |
| `aead_tx` | Encrypting outbound | Encrypting outbound |
| `aead_rx` | Decrypting inbound | Decrypting inbound |
| `iv_tx` | Outbound nonces | Outbound nonces |
| `iv_rx` | Inbound nonces | Inbound nonces |

In `REGISTER_CID`, the client sends keys from its perspective. The server
uses `*_tx` to send to the client and `*_rx` to open packets from the client.

## 4. Key Management

### 4.1 Initial Keys via REGISTER_CID

The `REGISTER_CID` payload includes:

```
offset size field
0      1    client_to_server_cid_len (must be 20)
1      N    client_to_server_cid
1+N    1    server_to_client_cid_len (0-20)
2+N    M    server_to_client_cid
...    1    cipher (0x01 = AES-128-GCM)
...    16   hp_tx
...    16   hp_rx
...    16   aead_tx
...    16   aead_rx
...    12   iv_tx
...    12   iv_rx
...    8    pn_start (server->client initial PN)
...    8    pn_start_rx (expected from client)
...    1    key_phase (0 or 1)
```

### 4.2 Key Phase Updates (In-Band)

UDP-QSP key updates are signaled in-band via the key phase bit. There is no
explicit rekey message.

**Update interval**: Recommended `2^21` packets per direction (much larger than
the replay window of 1024).

**Sender behavior**:

1. When TX packet number crosses the rekey threshold
2. Derive next directional keys via HKDF
3. Flip `key_phase` bit on outgoing packets
4. Continue sending with new keys

**Receiver behavior**:

1. Maintain RX key states: `current` and `previous`
2. Try `current` keys first
3. Try `previous` keys within grace window
4. Derive candidate keys and try them near expected rekey threshold
5. If candidate succeeds, promote: `previous = current`, `current = candidate`

**Dead channel detection**: After too many consecutive decrypt failures (64
by default), the channel is considered dead and the session reconnects.

### 4.3 HKDF Key Derivation

Next-generation keys are derived using HKDF-SHA256:

```
ikm = hp_key || aead_key || iv

extract_input = "slt-udp-qsp/key-update-v1" || ikm
prk = HKDF-Extract(iv, extract_input)

next_hp = HKDF-Expand(prk, "slt-udp-qsp/key-update-v1/hp", 16)
next_aead = HKDF-Expand(prk, "slt-udp-qsp/key-update-v1/aead", 16)
next_iv = HKDF-Expand(prk, "slt-udp-qsp/key-update-v1/iv", 12)
```

## 5. Security Properties

### 5.1 What UDP-QSP Provides

- **Confidentiality**: AES-128-GCM encrypts all payload data. Only parties
  with the shared keys can decrypt.

- **Integrity**: The 16-byte AEAD tag authenticates both the ciphertext and
  the associated data (header). Any tampering is detected.

- **Replay protection**: A 1024-packet sliding window tracks received packet
  numbers. Duplicates and packets older than the window are rejected.

- **Header obfuscation**: The packet number length and key phase are masked
  to prevent traffic analysis of these fields.

### 5.2 What UDP-QSP Does NOT Provide

- **Forward secrecy from compromised server_secret**: The initial UDP-QSP
  keys are generated by the client and sent over TCP. An attacker who
  compromises the server's `server_secret` can:
  1. Forge valid ClientHello tokens
  2. Impersonate the server to clients
  3. Decrypt captured VPN traffic if they also captured the REGISTER_CID
     message

  However, forward secrecy **is** maintained for key phase updates: an
  attacker who compromises current keys cannot decrypt past traffic from
  earlier key phases.

- **QUIC interoperability**: UDP-QSP uses QUIC wire format but is not
  compatible with standard QUIC stacks. It cannot be used with generic
  QUIC libraries.

- **DDoS mitigation**: UDP-QSP does not address amplification or flooding
  attacks. The wrapper's UDP classification logic (DCID lookup) provides
  basic filtering but is not a complete DDoS solution.

### 5.3 Replay Protection Details

The replay window (`PN_REPLAY_WINDOW = 1024`) uses a ring-buffer bitmap:

- If `pn > largest_pn`: Accept, advance `largest_pn`, slide window
- If `pn <= largest_pn`:
  - `delta = largest_pn - pn`
  - If `delta >= 1024`: Drop (too old)
  - If bit `delta` is set: Drop (replay)
  - Else: Set bit `delta` and accept

This allows out-of-order delivery within the window while rejecting
duplicates and old packets.

## 6. Implementation References

- `slt-core/src/crypto/client_hello.rs`: TLS ClientHello token generation
- `slt-core/src/crypto/udp_qsp/keys.rs`: Key management and packet protection
- `slt-core/src/crypto/udp_qsp/packet.rs`: Header parsing and protection
- `slt-core/src/crypto/udp_qsp/session.rs`: Session state and replay window
- `protocol.md`: Authoritative wire protocol specification (Section 4)
- `spec.txt`: Comprehensive design reference (Section 5)
