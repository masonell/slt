# VPN Message Payload Schemas

This document specifies the binary payload layouts for all VPN protocol message types.
All multi-byte integers are encoded in big-endian (network) byte order.

## Frame Format

All VPN messages are framed as:

```
+--------+--------+--------+--------+--------+---------------------+
| TYPE   | LEN (u32, big-endian)             | PAYLOAD (LEN bytes) |
+--------+--------+--------+--------+--------+---------------------+
   1 byte              4 bytes                LEN bytes
```

- `TYPE`: Message type identifier (1 byte)
- `LEN`: Payload length, not including the 5-byte header (4 bytes, big-endian)
- `PAYLOAD`: Message-specific data (`LEN` bytes)

## Message Types Summary

| Type              | ID    | Direction       | Payload Size | Description                           |
|-------------------|-------|-----------------|--------------|---------------------------------------|
| AUTH              | 0x01  | Client -> Server| 118 bytes    | Client authentication request         |
| AUTH_OK           | 0x02  | Server -> Client| 0 bytes      | Authentication accepted               |
| AUTH_FAIL         | 0x03  | Server -> Client| 1 byte       | Authentication rejected               |
| REGISTER_CID      | 0x04  | Client -> Server| Variable     | Register UDP-QSP CID and traffic secrets |
| REGISTER_OK       | 0x05  | Server -> Client| 21 bytes     | CID registration accepted             |
| REGISTER_FAIL     | 0x06  | Server -> Client| 1 byte       | CID registration rejected             |
| PING              | 0x07  | Bidirectional   | 8 bytes      | Keepalive ping                        |
| PONG              | 0x08  | Bidirectional   | 8 bytes      | Keepalive pong                        |
| CLOSE             | 0x09  | Bidirectional   | 1 byte       | Session termination                   |
| DATA              | 0x0a  | Bidirectional   | Variable     | Raw IP packet                         |
| UPGRADE_PROBE     | 0x0b  | Client -> Server| 16 bytes     | UDP path validation probe             |
| UPGRADE_PROBE_ACK | 0x0c  | Server -> Client| 16 bytes     | UDP path validation acknowledgment    |
| UDP_READY         | 0x0d  | Client -> Server| 8 bytes      | Client signals UDP path validated     |
| SWITCH_TO_UDP     | 0x0e  | Server -> Client| 8 bytes      | Server requests transport switch      |
| SWITCH_ACK        | 0x0f  | Client -> Server| 8 bytes      | Client accepts the switch request     |
| FALLBACK_TO_TCP   | 0x10  | Bidirectional   | 8 bytes      | Request TCP as the preferred transport |
| FALLBACK_OK       | 0x11  | Bidirectional   | 8 bytes      | Acknowledge TCP fallback               |
| SWITCH_OK         | 0x12  | Server -> Client| 8 bytes      | Confirm UDP switch acknowledgement    |

---

## Authentication Messages

### AUTH (0x01)

**Direction:** Client -> Server
**Payload Size:** 118 bytes

Client authentication request sent after TLS handshake completion.

#### Binary Layout

| Offset | Size | Field          | Description                              |
|--------|------|----------------|------------------------------------------|
| 0      | 16   | client_id      | Client identifier (16-byte UUID)         |
| 16     | 4    | assigned_ipv4  | Assigned IPv4 address (network order)    |
| 20     | 2    | tun_mtu        | Client TUN MTU (big-endian)              |
| 22     | 32   | challenge      | TLS exporter challenge                   |
| 54     | 64   | signature      | Ed25519 signature                        |

#### Field Descriptions

- **client_id** (16 bytes): Unique client identifier. Must exist in server configuration.
- **assigned_ipv4** (4 bytes): The IPv4 address assigned to this client. Must match server configuration for this client.
- **tun_mtu** (2 bytes): Client TUN MTU. Must exactly match the server TUN MTU.
- **challenge** (32 bytes): Challenge bytes derived from TLS handshake:
  ```
  challenge = TLS-Exporter("slt-auth-challenge", "", 32)
  ```
  Computed after TLS handshake completes.
- **signature** (64 bytes): Ed25519 signature over the authentication context:
  ```
  context = b"slt-auth-v2" || client_id || assigned_ipv4 || tun_mtu_be || challenge
  signature = Ed25519.sign(client_private_key, context)
  ```

#### Validation Rules

1. `client_id` must exist in server's client configuration
2. `assigned_ipv4` must match the configured IP for this `client_id`
3. `tun_mtu` must equal the server's configured TUN MTU
4. `challenge` must equal the TLS exporter output from the current session
5. `signature` must verify under the public key configured for this `client_id`

---

### AUTH_OK (0x02)

**Direction:** Server -> Client
**Payload Size:** 0 bytes

Indicates successful authentication. After receiving this message, the session is authenticated and TCP data transfer is permitted.

#### Binary Layout

Empty payload (LEN = 0).

---

### AUTH_FAIL (0x03)

**Direction:** Server -> Client
**Payload Size:** 1 byte

Indicates authentication failure.

#### Binary Layout

| Offset | Size | Field | Description       |
|--------|------|-------|-------------------|
| 0      | 1    | code  | Failure reason    |

#### Error Codes

| Code | Name              | Description                                    |
|------|-------------------|------------------------------------------------|
| 0x00 | Unknown           | Unspecified or unknown failure                 |
| 0x01 | UnknownClient     | Client ID not found in server configuration    |
| 0x02 | Disabled          | Client is disabled in configuration            |
| 0x03 | BadSignature      | Ed25519 signature verification failed          |
| 0x04 | IpMismatch        | Assigned IPv4 does not match configuration     |
| 0x05 | ChallengeInvalid  | Challenge is expired or invalid                |
| 0x06 | MtuMismatch       | Client and server TUN MTUs do not match        |

---

## Registration Messages

### REGISTER_CID (0x04)

**Direction:** Client -> Server
**Payload Size:** Variable; traffic secrets are fixed at 32 bytes each

Registers a UDP-QSP connection ID and associated directional traffic secrets for the session.

Packet-protection keys are derived locally from the traffic secrets using the
RFC 9001/TLS 1.3 labels described in [key-update.md](key-update.md).

#### Per-Cipher Key Sizes

Key-material field widths are fixed per cipher and defined by the cipher, not by
configuration:

| Suite | `cipher` | Traffic secret | Derived HP key | Derived AEAD key | Derived IV | Tag |
|-------|----------|---------------:|---------------:|-----------------:|-----------:|----:|
| AES-128-GCM        | 0x01 | 32 | 16 | 16 | 12 | 16 |
| ChaCha20-Poly1305  | 0x02 | 32 | 32 | 32 | 12 | 16 |

#### Binary Layout

| Offset         | Size              | Field                   | Description                           |
|----------------|-------------------|-------------------------|---------------------------------------|
| 0              | 1                 | client_to_server_cid_len| Length of client->server CID (must be 20) |
| 1              | N                 | client_to_server_cid    | CID for client->server packets        |
| 1+N            | 1                 | server_to_client_cid_len| Length of server->client CID (0-20)   |
| 2+N            | M                 | server_to_client_cid    | CID for server->client packets        |
| 2+N+M          | 1                 | cipher                  | Cipher suite identifier               |
| 3+N+M          | 32                | secret_tx               | Traffic secret for server->client packets |
| 35+N+M         | 32                | secret_rx               | Traffic secret for client->server packets |
| 67+N+M         | 8                 | pn_start                | Initial packet number (TX, server->client) |
| 75+N+M         | 8                 | pn_start_rx             | Initial packet number (RX, client->server) |
| 83+N+M         | 1                 | key_phase               | Initial key phase (0 or 1)            |

Where:
- N = client_to_server_cid_len (must be 20)
- M = server_to_client_cid_len (0 to 20)

Total length: `84 + N + M` bytes (104-124 bytes with N=20).

#### Field Descriptions

- **client_to_server_cid** (N bytes): Destination CID for packets from client to server. Must be exactly 20 bytes.
- **server_to_client_cid** (M bytes): Destination CID for packets from server to client. May be 0-20 bytes (Chrome uses 0).
- **cipher** (1 byte): Cipher suite for packet protection.
- **secret_tx/secret_rx** (32 bytes each): Directional traffic secrets. The server uses `secret_tx` for server->client packets and `secret_rx` for client->server packets. The client uses the opposite directions.
- **pn_start** (8 bytes): Initial packet number for server->client traffic.
- **pn_start_rx** (8 bytes): Initial packet number expected from client->server traffic.
- **key_phase** (1 byte): Initial key phase (0 = phase 0, 1 = phase 1).

#### Key Direction Semantics

From the server's perspective:
- `secret_tx` is used by the server to **send** packets to the client
- `secret_rx` is used by the server to **receive** packets from the client

The client uses the opposite directions.

#### Cipher Suites

| Code | Name                | Description                          |
|------|---------------------|--------------------------------------|
| 0x01 | AES-128-GCM         | Supported                            |
| 0x02 | ChaCha20-Poly1305   | Supported                            |

The client selects the suite (see `cipher` under `[transport.udp_qsp]`); the server
accepts the suite if it is both supported and permitted by the server's
`allowed_ciphers` policy, otherwise rejecting with `RegisterFailCode::InvalidCipher`.

#### Validation Rules

1. `client_to_server_cid_len` MUST be exactly 20 bytes
2. `server_to_client_cid_len` MUST be 0-20 bytes
3. `cipher` MUST be a supported suite (0x01 or 0x02) and permitted by server policy
4. `secret_tx` and `secret_rx` MUST each be exactly 32 bytes, and the overall
   payload length MUST match the expected total
5. `key_phase` MUST be 0 or 1
6. The 20-byte prefix of `client_to_server_cid` MUST NOT conflict with any other active connection

A `cipher` value that is supported but disallowed by policy is rejected as
`InvalidCipher`; payloads that do not fit the expected layout are rejected as
`InvalidKeys`.

---

### REGISTER_OK (0x05)

**Direction:** Server -> Client
**Payload Size:** 21 bytes

Confirms successful CID registration.

#### Binary Layout

| Offset | Size | Field                   | Description                           |
|--------|------|-------------------------|---------------------------------------|
| 0      | 1    | client_to_server_cid_len| Length of confirmed CID (must be 20)  |
| 1      | 20   | client_to_server_cid    | Echo of the registered CID            |

#### Validation Rules

1. `client_to_server_cid_len` MUST be exactly 20
2. `client_to_server_cid` MUST match the value sent in REGISTER_CID

---

### REGISTER_FAIL (0x06)

**Direction:** Server -> Client
**Payload Size:** 1 byte

Indicates CID registration failure.

#### Binary Layout

| Offset | Size | Field | Description       |
|--------|------|-------|-------------------|
| 0      | 1    | code  | Failure reason    |

#### Error Codes

| Code | Name              | Description                                    |
|------|-------------------|------------------------------------------------|
| 0x00 | Unknown           | Unspecified or unknown failure                 |
| 0x01 | NotAuthenticated  | Client has not completed AUTH                  |
| 0x02 | InvalidCipher     | Unsupported or invalid cipher suite            |
| 0x03 | InvalidCid        | Invalid CID length or format                   |
| 0x04 | InvalidKeys       | Invalid key material                           |

---

## Keepalive Messages

### PING (0x07)

**Direction:** Bidirectional
**Payload Size:** 8 bytes

Keepalive ping. Sent on the preferred transport.

#### Binary Layout

| Offset | Size | Field | Description              |
|--------|------|-------|--------------------------|
| 0      | 8    | nonce | Random nonce (big-endian)|

#### Semantics

- The responder MUST echo the nonce in PONG
- During UDP path refresh, the client requires the PONG nonce to match the
  current refresh PING before marking the path refreshed
- During periodic keepalive, endpoints do not track outstanding PING nonces;
  PONGs count as inbound activity like any other valid message

---

### PONG (0x08)

**Direction:** Bidirectional
**Payload Size:** 8 bytes

Keepalive pong response to PING.

#### Binary Layout

| Offset | Size | Field | Description              |
|--------|------|-------|--------------------------|
| 0      | 8    | nonce | Echo of PING nonce       |

#### Validation Rules

1. `nonce` MUST echo the value from the corresponding PING message
2. A stale or non-matching PONG does not complete UDP path refresh

---

## Session Control Messages

### CLOSE (0x09)

**Direction:** Bidirectional
**Payload Size:** 1 byte

Terminates the VPN session.

#### Binary Layout

| Offset | Size | Field | Description       |
|--------|------|-------|-------------------|
| 0      | 1    | code  | Close reason      |

#### Error Codes

| Code | Name           | Description                              |
|------|----------------|------------------------------------------|
| 0x00 | Normal         | Graceful shutdown                        |
| 0x01 | AuthTimeout    | Authentication timeout exceeded          |
| 0x02 | IdleTimeout    | No inbound traffic within timeout        |
| 0x03 | ProtocolError  | Protocol violation detected              |
| 0x04 | ServerRestart  | Server is shutting down or restarting    |

#### Notes

- CLOSE on UDP-QSP is best-effort; if dropped, idle timeout closes the session

---

## Data Messages

### DATA (0x0a)

**Direction:** Bidirectional
**Payload Size:** Variable (up to max_data_len)

Transports a raw IP packet through the VPN tunnel.

#### Binary Layout

| Offset | Size      | Field   | Description              |
|--------|-----------|---------|--------------------------|
| 0      | Variable  | packet  | Raw IP packet            |

#### Field Descriptions

- **packet**: A complete IP packet (currently IPv4 only). The packet includes the full IP header.

#### Validation Rules

1. Payload length MUST NOT exceed `max_data_len` (derived from TUN MTU)
2. For client-originated DATA, `src_ip` in the IP header MUST equal the client's `assigned_ipv4`
3. `tun_mtu` MUST be in range 1-1406

SLT validates message framing, the size limit, enough of the IPv4 header to
read addresses, and the identity-bound source-address rule. It intentionally
delegates full IPv4 validation—including total length, header checksum, and
fragmentation handling—to the receiving platform IP stack when the packet is
delivered through TUN. Malformed inner packets are handled with the platform
stack's normal per-packet semantics.

#### MTU Constraints

Maximum `tun_mtu` is 1406 bytes, derived from:
- Ethernet/IP MTU: 1500 bytes
- Outer overhead (worst case): IPv6 header (40) + UDP header (8) = 48 bytes
- UDP-QSP + VPN framing: short header (1 + 20 + 4) + AEAD tag (16) + VPN frame (5) = 46 bytes
- Budget: 1500 - 48 - 46 = 1406 bytes

---

## UDP Upgrade Messages

### UPGRADE_PROBE (0x0b)

**Direction:** Client -> Server (UDP)
**Payload Size:** 16 bytes

UDP path validation probe sent during the upgrade sequence.

#### Binary Layout

| Offset | Size | Field       | Description                    |
|--------|------|-------------|--------------------------------|
| 0      | 8    | upgrade_id  | Unique upgrade attempt ID      |
| 8      | 8    | nonce       | Random probe nonce             |

#### Field Descriptions

- **upgrade_id**: Unique identifier for this upgrade attempt
- **nonce**: Random value generated once per upgrade attempt, reused by probe retransmissions, and echoed in the acknowledgment

---

### UPGRADE_PROBE_ACK (0x0c)

**Direction:** Server -> Client (UDP)
**Payload Size:** 16 bytes

Acknowledgment of UDP path validation probe.

#### Binary Layout

| Offset | Size | Field       | Description                    |
|--------|------|-------------|--------------------------------|
| 0      | 8    | upgrade_id  | Echo of probe upgrade_id       |
| 8      | 8    | nonce       | Echo of probe nonce            |

#### Validation Rules

1. Both `upgrade_id` and `nonce` MUST exactly match the active upgrade attempt

---

### UDP_READY (0x0d)

**Direction:** Client -> Server (TCP)
**Payload Size:** 8 bytes

Client signals that the UDP path has been validated and is ready for use.

#### Binary Layout

| Offset | Size | Field       | Description                    |
|--------|------|-------------|--------------------------------|
| 0      | 8    | upgrade_id  | ID of validated upgrade        |

#### Semantics

- Sent after receiving UPGRADE_PROBE_ACK
- Correlates with the successful UDP probe via `upgrade_id`

---

### SWITCH_TO_UDP (0x0e)

**Direction:** Server -> Client (TCP)
**Payload Size:** 8 bytes

Server asks the client to begin the UDP-QSP switch commit.

#### Binary Layout

| Offset | Size | Field       | Description                    |
|--------|------|-------------|--------------------------------|
| 0      | 8    | upgrade_id  | ID of upgrade being committed  |

#### Semantics

- Sent only after both conditions are met:
  1. A valid UDP probe (UPGRADE_PROBE) was observed
  2. A matching UDP_READY was received on TCP

---

### SWITCH_ACK (0x0f)

**Direction:** Client -> Server (TCP)
**Payload Size:** 8 bytes

Client accepts the server's switch request.

#### Binary Layout

| Offset | Size | Field       | Description                    |
|--------|------|-------------|--------------------------------|
| 0      | 8    | upgrade_id  | ID of acknowledged upgrade     |

#### Semantics

- Client keeps TCP as its preferred outbound transport after sending SWITCH_ACK
- Server makes UDP-QSP its preferred outbound transport after receiving SWITCH_ACK
- Server sends SWITCH_OK after processing the matching SWITCH_ACK
- Authenticated DATA remains valid on TCP and UDP-QSP while both transports are live

---

### SWITCH_OK (0x12)

**Direction:** Server -> Client (TCP)
**Payload Size:** 8 bytes

Confirms that the server processed the client's UDP switch acknowledgement.

#### Binary Layout

| Offset | Size | Field       | Description                         |
|--------|------|-------------|-------------------------------------|
| 0      | 8    | upgrade_id  | ID of the committed upgrade         |

#### Semantics

- Sent after the server commits UDP-QSP as its preferred outbound transport
- Client makes UDP-QSP its preferred outbound transport only after receiving a matching SWITCH_OK
- If TCP closes before SWITCH_OK, the client reconnects instead of assuming the server committed

---

### FALLBACK_TO_TCP (0x10)

**Direction:** Bidirectional (TCP)
**Payload Size:** 8 bytes

Requests that the peer use TCP as its preferred outbound transport.

#### Binary Layout

| Offset | Size | Field        | Description                         |
|--------|------|--------------|-------------------------------------|
| 0      | 8    | fallback_id  | Identifier echoed in FALLBACK_OK    |

#### Semantics

- The receiver switches its preferred outbound transport to TCP before processing later frames
- The request is idempotent; duplicate requests receive another FALLBACK_OK
- The sender may place DATA after the request on the same TCP stream because stream ordering guarantees the receiver processes the fallback first
- Protected UDP packets still buffered for send are discarded rather than flushed or replayed on TCP
- A live prior UDP transport remains receive-capable until replacement UDP registration completes

---

### FALLBACK_OK (0x11)

**Direction:** Bidirectional (TCP)
**Payload Size:** 8 bytes

Acknowledges a TCP fallback request.

#### Binary Layout

| Offset | Size | Field        | Description                              |
|--------|------|--------------|------------------------------------------|
| 0      | 8    | fallback_id  | Identifier copied from FALLBACK_TO_TCP   |

#### Semantics

- Confirms that the peer now prefers TCP for outbound traffic
- Stale or duplicate acknowledgements do not change transport state

---

## Constants Reference

| Constant               | Value | Description                              |
|------------------------|-------|------------------------------------------|
| MAX_DCID_LEN           | 20    | Maximum QUIC DCID length                 |
| QUIC_DCID_PREFIX_LEN   | 20    | Prefix length for UDP-QSP classification |
| AUTH_CHALLENGE_LEN     | 32    | Length of authentication challenge       |
| AUTH_SIGNATURE_LEN     | 64    | Length of Ed25519 signature              |
| HP_KEY_LEN             | 16    | Header protection key length (AES-128-GCM) |
| CHACHA20_POLY1305_KEY_LEN | 32 | HP/AEAD key length (ChaCha20-Poly1305)  |
| AEAD_KEY_LEN           | 16    | AEAD key length (AES-128-GCM)           |
| AEAD_IV_LEN            | 12    | Length of AEAD IV (both suites)         |
| FALLBACK_ID_PAYLOAD_LEN | 8   | TCP fallback identifier length           |
| MAX_TUN_MTU            | 1406  | Maximum TUN MTU                          |
| PN_REPLAY_WINDOW       | 1024  | Replay protection window size (packets)  |

---

## Transport Restrictions

| Message Type        | TCP | UDP-QSP |
|---------------------|-----|---------|
| AUTH                | Yes | No      |
| AUTH_OK             | Yes | No      |
| AUTH_FAIL           | Yes | No      |
| REGISTER_CID        | Yes | No      |
| REGISTER_OK         | Yes | No      |
| REGISTER_FAIL       | Yes | No      |
| PING                | Yes | Yes     |
| PONG                | Yes | Yes     |
| CLOSE               | Yes | Yes     |
| DATA                | Yes | Yes     |
| UPGRADE_PROBE       | No  | Yes     |
| UPGRADE_PROBE_ACK   | No  | Yes     |
| UDP_READY           | Yes | No      |
| SWITCH_TO_UDP       | Yes | No      |
| SWITCH_ACK          | Yes | No      |
| SWITCH_OK           | Yes | No      |
| FALLBACK_TO_TCP     | Yes | No      |
| FALLBACK_OK         | Yes | No      |
