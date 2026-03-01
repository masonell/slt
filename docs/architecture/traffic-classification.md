# Traffic Classification

## 1. Overview

The SLT server multiplexes VPN traffic and standard web traffic on the same public
ports (80/443 TCP, 443 UDP). Traffic classification determines whether an incoming
connection or datagram should be:

- **CLAIM**: Route to the VPN handler for authentication and tunnel processing.
- **PASS**: Forward to nginx (the internal web service) unmodified.
- **DROP**: Silently discard the packet.

This design ensures that VPN traffic is indistinguishable from regular HTTPS/QUIC
traffic to outside observers. Failed VPN claim attempts simply route to nginx like
any other web traffic, providing plausible deniability.

### Design Goals

1. **Stealth**: VPN traffic must be indistinguishable from normal TLS/QUIC traffic.
2. **Bounded Resources**: Classification must have predictable CPU and memory usage.
3. **No Side Effects**: The classifier must not emit network packets.

## 2. TCP Classification (ClientHello Token)

TCP connections are classified by inspecting the TLS ClientHello message. The client
embeds a 32-byte authentication token in the `legacy_session_id` field.

### 2.1 Token Structure

The `legacy_session_id` field contains exactly 32 bytes:

```
session_id = part1 || part2
```

Where:
- `part1` = 16 bytes
- `part2` = 16 bytes

### 2.2 Token Computation

#### Part 1: Random-based HMAC

```
part1 = HMAC-SHA256(server_secret, random[0:16])[:16]
```

- `server_secret`: 32-byte shared secret configured on both client and server.
- `random`: The 32-byte random field from the ClientHello.
- Only the first 16 bytes of the random field are used.
- The HMAC output is truncated to 16 bytes.

#### Part 2: Key Share-based HMAC

```
part2 = HMAC-SHA256(server_secret, key_share)[:16]
```

- `key_share`: The 32-byte X25519 public key from the `key_share` extension.
- The HMAC output is truncated to 16 bytes.

**Note**: Only X25519 key shares are supported. If the ClientHello contains a
different key exchange group, the token cannot be validated.

### 2.3 Classification Algorithm

The classifier processes the TLS record layer and handshake message step by step:

```
1. Read TLS record header (content type, version, length)
   - If content type != 0x16 (handshake) -> PASS
   - If incomplete -> INCOMPLETE (need more data)

2. Read handshake message header (type, length)
   - If type != 0x01 (ClientHello) -> PASS
   - If incomplete -> INCOMPLETE

3. Parse ClientHello body:
   a. Skip legacy_version (2 bytes)
   b. Read random (32 bytes)
   c. Read session_id_len (1 byte)
   d. If session_id_len != 32 -> PASS

4. Read session_id (32 bytes)

5. Compute expected_part1 = HMAC-SHA256(secret, random[0:16])[:16]
   - Compare with session_id[0:16] using constant-time comparison
   - If mismatch -> PASS

6. Skip cipher_suites (variable length)
7. Skip compression_methods (variable length)

8. Parse extensions:
   - Find key_share extension (type 0x0033)
   - Extract X25519 key share (group 0x001d, 32 bytes)
   - If no X25519 key share found -> PASS

9. Compute expected_part2 = HMAC-SHA256(secret, key_share)[:16]
   - Compare with session_id[16:32] using constant-time comparison
   - If mismatch -> PASS

10. Both parts valid -> CLAIM
```

### 2.4 Implementation Notes

The implementation in `slt-core/src/classifier.rs` uses a streaming parser that:

- Handles multiple TLS records (a ClientHello may span records).
- Uses a fixed-size scratch buffer (256 bytes) for skipping data.
- Performs constant-time HMAC comparisons using `boring::memcmp::eq`.
- Returns early on any parse error with `PASS` verdict.

**Constants** (from `slt-core/src/crypto/client_hello.rs`):
- `LEGACY_SESSION_ID_LEN = 32`
- `PART_LEN = 16`
- `RANDOM_PREFIX_LEN = 16`
- `EXT_KEY_SHARE = 0x0033`
- `GROUP_X25519 = 0x001d`

### 2.5 Verification Against Code

The algorithm description above matches the implementation in `classify_tcp_client_hello()`:

| Step | Spec | Code |
|------|------|------|
| Record type check | content_type == 0x16 | `TLS_HANDSHAKE_CONTENT_TYPE` constant, checked in `next_record()` |
| Handshake type check | type == 0x01 | `HANDSHAKE_TYPE_CLIENT_HELLO` constant, line 83 |
| Session ID length | == 32 | `LEGACY_SESSION_ID_LEN` constant, line 108 |
| Part 1 verification | HMAC(random[:16]) | `hmac_sha256(secret, &random[..RANDOM_PREFIX_LEN])` at line 117 |
| Part 2 verification | HMAC(key_share) | `hmac_sha256(secret, &key_share)` at line 172 |
| Constant-time compare | Required | `memcmp::eq()` used at lines 121, 176 |

**No discrepancies found.**

## 3. UDP Classification (QUIC-shaped)

UDP datagrams are classified based on QUIC wire format detection. The classifier
uses QUIC invariants to distinguish packet types.

### 3.1 QUIC Format Detection

QUIC packets are identified by the **fixed bit** (bit 6 of the first byte), which
must always be set to 1 in valid QUIC packets.

```
first_byte bits:
  bit 7: header form (0 = short, 1 = long)
  bit 6: fixed bit (must be 1)
  bits 5-0: packet-type specific
```

Classification rule:
- If `fixed_bit == 0` -> **DROP** (not QUIC format)

### 3.2 Long Header Packets

Long header packets (bit 7 = 1) are QUIC handshake packets (Initial, Handshake, Retry, 0-RTT).

```
Classification:
  If header_form == long -> PASS (forward to nginx)
```

Rationale: The VPN does not intercept real QUIC handshakes. Extracting TLS key
shares from QUIC Initial packets would require CRYPTO frame reassembly and deeper
parsing, which violates the bounded-resource requirement.

### 3.3 Short Header Packets

Short header packets (bit 7 = 0) are 1-RTT encrypted packets.

```
Classification:
  If header_form == short:
    - Extract DCID (Destination Connection ID) from bytes [1..=20]
    - Lookup DCID prefix in cid_map
    - If found -> CLAIM
    - If not found -> PASS
```

The DCID prefix length is 20 bytes (`QUIC_DCID_PREFIX_LEN`). This prefix is used
as the lookup key in the server's connection ID map.

### 3.4 Classification Algorithm

```
1. If datagram is empty -> DROP

2. Read first byte:
   - header_form = (first_byte & 0x80) != 0
   - fixed_bit = (first_byte & 0x40) != 0

3. If fixed_bit == 0 -> DROP (not QUIC)

4. If header_form == long -> PASS

5. If header_form == short:
   a. If datagram length < 1 + 20 -> DROP (too short for DCID)
   b. Extract dcid_prefix = datagram[1..=20]
   c. Return Short { dcid_prefix }
   d. Caller performs cid_map lookup to determine CLAIM vs PASS
```

### 3.5 4-tuple NAT for Non-VPN Traffic

Non-VPN UDP traffic (long headers and unknown short headers) is forwarded to nginx
via a 4-tuple NAT mechanism:

- **NAT Map**: `client_ip:client_port -> local_socket`
- Each unique source address gets a dedicated local socket to `127.0.0.1:8443/udp`.
- **Resource Limits**:
  - Bounded table size (configurable, typically 100-1000 entries).
  - LRU eviction when limit is reached.
  - Idle timeout for stale entries.

This allows real QUIC connections to nginx to function normally while the VPN
uses short-header packets with registered DCIDs.

### 3.6 Verification Against Code

The algorithm description above matches the implementation in `classify_quic_datagram()`:

| Step | Spec | Code |
|------|------|------|
| Empty check | -> DROP | Line 43-44 |
| Fixed bit check | (first & 0x40) | Line 49 |
| Non-QUIC -> DROP | If !fixed_bit | Line 51-52 |
| Long header -> PASS | If (first & 0x80) | Line 55-56 |
| Short header DCID extraction | bytes [1..=20] | Line 59-64 |
| Prefix length | 20 bytes | `QUIC_DCID_PREFIX_LEN` constant |

**No discrepancies found.**

## 4. Security Requirements

The classifier operates on untrusted network input and must meet strict security
constraints.

### 4.1 Bounded CPU Per Packet

- **No unbounded loops**: All parsing loops have fixed upper bounds based on
  declared lengths from the packet itself.
- **Early termination**: Any malformed or oversized field causes immediate return.
- **Fixed scratch buffer**: The TCP classifier uses a 256-byte scratch buffer
  for skipping data, never allocating based on attacker input.
- **Single pass**: Each byte is read at most once.

### 4.2 Bounded Memory

- **No heap allocations**: The classifier uses only stack-allocated buffers.
- **Fixed-size structures**: All intermediate buffers have compile-time known sizes.
- **No data accumulation**: The classifier does not buffer packets; it processes
  each one independently.

Memory usage summary:
- TCP classifier: ~400 bytes stack (readers + scratch + HMAC outputs)
- UDP classifier: ~24 bytes stack (DCID prefix buffer)

### 4.3 No Network Emission

The classifier is a pure function that:
- Takes a byte slice as input.
- Returns a verdict (no I/O).
- Never sends packets or opens connections.

This ensures that:
- Classification cannot be used for amplification attacks.
- No information leaks through timing side channels based on network state.
- The classifier is safe to call from any context.

### 4.4 Constant-Time Comparisons

HMAC comparisons use constant-time equality (`boring::memcmp::eq`) to prevent
timing attacks that could reveal information about valid tokens.

### 4.5 Defense in Depth

- **PASS on error**: Any parse error or malformed input results in PASS, not DROP.
  This ensures that broken but innocent traffic still reaches nginx.
- **No secret-dependent control flow**: The only secret-dependent operation is
  the HMAC comparison, which is constant-time.
- **Separation of concerns**: Classification and authentication are separate.
  Classification only identifies potential VPN traffic; authentication happens
  later over the TLS channel.

## 5. Implementation Reference

- **TCP Classifier**: `slt-core/src/classifier.rs` - `classify_tcp_client_hello()`
- **UDP Classifier**: `slt-core/src/classifier.rs` - `classify_quic_datagram()`
- **Token Generation**: `slt-core/src/crypto/client_hello.rs` - `fill_legacy_session_id()`
- **Constants**: `slt-core/src/crypto/client_hello.rs` and `slt-core/src/types/cid.rs`
- **Protocol Spec**: `protocol.md` section 2 (front door classification)
- **Design Spec**: `spec.txt` section 3.2 (classification)
