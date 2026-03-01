# VPN Message Payload Schemas

This document specifies the binary payload layouts for all VPN protocol message types.
All multi-byte integers are encoded in big-endian (network) byte order.

## Frame Format

All VPN messages are framed as:

```
+--------+--------+--------+--------+--------+------------------+
| TYPE   | LEN (u32, big-endian)      | PAYLOAD (LEN bytes)    |
+--------+--------+--------+--------+--------+------------------+
   1 byte              4 bytes                LEN bytes
```

- `TYPE`: Message type identifier (1 byte)
- `LEN`: Payload length, not including the 5-byte header (4 bytes, big-endian)
- `PAYLOAD`: Message-specific data (`LEN` bytes)

## Message Types Summary

| Type              | ID    | Direction       | Payload Size | Description                           |
|-------------------|-------|-----------------|--------------|---------------------------------------|
| AUTH              | 0x01  | Client -> Server| 116 bytes    | Client authentication request         |
| AUTH_OK           | 0x02  | Server -> Client| 0 bytes      | Authentication accepted               |
| AUTH_FAIL         | 0x03  | Server -> Client| 1 byte       | Authentication rejected               |
| REGISTER_CID      | 0x04  | Client -> Server| Variable     | Register UDP-QSP CID and keys         |
| REGISTER_OK       | 0x05  | Server -> Client| 21 bytes     | CID registration accepted             |
| REGISTER_FAIL     | 0x06  | Server -> Client| 1 byte       | CID registration rejected             |
| PING              | 0x07  | Bidirectional   | 8 bytes      | Keepalive ping                        |
| PONG              | 0x08  | Bidirectional   | 8 bytes      | Keepalive pong                        |
| CLOSE             | 0x09  | Bidirectional   | 1 byte       | Session termination                   |
| DATA              | 0x0a  | Bidirectional   | Variable     | Raw IP packet                         |
| UPGRADE_PROBE     | 0x0b  | Client -> Server| 16 bytes     | UDP path validation probe             |
| UPGRADE_PROBE_ACK | 0x0c  | Server -> Client| 16 bytes     | UDP path validation acknowledgment    |
| UDP_READY         | 0x0d  | Client -> Server| 8 bytes      | Client signals UDP path validated     |
| SWITCH_TO_UDP     | 0x0e  | Server -> Client| 8 bytes      | Server commits transport switch       |
| SWITCH_ACK        | 0x0f  | Client -> Server| 8 bytes      | Client acknowledges switch commit     |

---

## Authentication Messages

### AUTH (0x01)

**Direction:** Client -> Server
**Payload Size:** 116 bytes

Client authentication request sent after TLS handshake completion.

#### Binary Layout

| Offset | Size | Field          | Description                              |
|--------|------|----------------|------------------------------------------|
| 0      | 16   | client_id      | Client identifier (16-byte UUID)         |
| 16     | 4    | assigned_ipv4  | Assigned IPv4 address (network order)    |
| 20     | 32   | challenge      | TLS exporter challenge                   |
| 52     | 64   | signature      | Ed25519 signature                        |

#### Field Descriptions

- **client_id** (16 bytes): Unique client identifier. Must exist in server configuration.
- **assigned_ipv4** (4 bytes): The IPv4 address assigned to this client. Must match server configuration for this client.
- **challenge** (32 bytes): Challenge bytes derived from TLS handshake:
  ```
  challenge = TLS-Exporter("slt-auth-challenge", "", 32)
  ```
  Computed after TLS handshake completes.
- **signature** (64 bytes): Ed25519 signature over the authentication context:
  ```
  context = b"slt-auth-v1" || client_id || assigned_ipv4 || challenge
  signature = Ed25519.sign(client_private_key, context)
  ```

#### Validation Rules

1. `client_id` must exist in server's client configuration
2. `assigned_ipv4` must match the configured IP for this `client_id`
3. `challenge` must equal the TLS exporter output from the current session
4. `signature` must verify under the public key configured for this `client_id`

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

---

## Registration Messages

### REGISTER_CID (0x04)

**Direction:** Client -> Server
**Payload Size:** Variable (109 + client_to_server_cid_len + server_to_client_cid_len bytes)

Registers a UDP-QSP connection ID and associated cryptographic keys for the session.

#### Binary Layout

| Offset         | Size              | Field                   | Description                           |
|----------------|-------------------|-------------------------|---------------------------------------|
| 0              | 1                 | client_to_server_cid_len| Length of client->server CID (must be 20) |
| 1              | N                 | client_to_server_cid    | CID for client->server packets        |
| 1+N            | 1                 | server_to_client_cid_len| Length of server->client CID (0-20)   |
| 2+N            | M                 | server_to_client_cid    | CID for server->client packets        |
| 2+N+M          | 1                 | cipher                  | Cipher suite identifier               |
| 3+N+M          | 16                | hp_tx                   | Header protection key (TX)            |
| 19+N+M         | 16                | hp_rx                   | Header protection key (RX)            |
| 35+N+M         | 16                | aead_tx                 | AEAD encryption key (TX)              |
| 51+N+M         | 16                | aead_rx                 | AEAD decryption key (RX)              |
| 67+N+M         | 12                | iv_tx                   | AEAD IV (TX)                          |
| 79+N+M         | 12                | iv_rx                   | AEAD IV (RX)                          |
| 91+N+M         | 8                 | pn_start                | Initial packet number (TX, server->client) |
| 99+N+M         | 8                 | pn_start_rx             | Initial packet number (RX, client->server) |
| 107+N+M        | 1                 | key_phase               | Initial key phase (0 or 1)            |

Where:
- N = client_to_server_cid_len (must be 20)
- M = server_to_client_cid_len (0 to 20)

Total length: `109 + N + M` bytes

#### Field Descriptions

- **client_to_server_cid** (N bytes): Destination CID for packets from client to server. Must be exactly 20 bytes.
- **server_to_client_cid** (M bytes): Destination CID for packets from server to client. May be 0-20 bytes (Chrome uses 0).
- **cipher** (1 byte): Cipher suite for packet protection.
- **hp_tx/hp_rx** (16 bytes each): AES-128-ECB keys for header protection.
- **aead_tx/aead_rx** (16 bytes each): AES-128-GCM keys for payload protection.
- **iv_tx/iv_rx** (12 bytes each): AEAD initialization vectors.
- **pn_start** (8 bytes): Initial packet number for server->client traffic.
- **pn_start_rx** (8 bytes): Initial packet number expected from client->server traffic.
- **key_phase** (1 byte): Initial key phase (0 = phase 0, 1 = phase 1).

#### Key Direction Semantics

From the server's perspective:
- `*_tx` keys are used by the server to **send** packets to the client
- `*_rx` keys are used by the server to **receive** (decrypt) packets from the client

The client uses the opposite directions.

#### Cipher Suites

| Code | Name                | Description                    |
|------|---------------------|--------------------------------|
| 0x01 | AES-128-GCM         | Required, currently supported  |
| 0x02 | ChaCha20-Poly1305   | Reserved, not yet supported    |

#### Validation Rules

1. `client_to_server_cid_len` MUST be exactly 20 bytes
2. `server_to_client_cid_len` MUST be 0-20 bytes
3. `cipher` MUST be 0x01 (AES-128-GCM)
4. `key_phase` MUST be 0 or 1
5. The 20-byte prefix of `client_to_server_cid` MUST NOT conflict with any other active connection

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

Keepalive ping. Sent only on the active transport.

#### Binary Layout

| Offset | Size | Field | Description              |
|--------|------|-------|--------------------------|
| 0      | 8    | nonce | Random nonce (big-endian)|

#### Semantics

- The nonce need not be validated for ordinary keepalive traffic
- When used as a switch-commit barrier, the receiver MUST validate the nonce before committing to UDP-QSP

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
2. `src_ip` in the IP header MUST equal the client's `assigned_ipv4`
3. `tun_mtu` MUST be in range 1-1406

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
- **nonce**: Random value to be echoed in the acknowledgment

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

1. Both `upgrade_id` and `nonce` MUST exactly match the values from UPGRADE_PROBE

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

Server commits to switching the active transport to UDP-QSP.

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

Client acknowledges the server's switch commit.

#### Binary Layout

| Offset | Size | Field       | Description                    |
|--------|------|-------------|--------------------------------|
| 0      | 8    | upgrade_id  | ID of acknowledged upgrade     |

#### Semantics

- After sending SWITCH_ACK, client sends a TCP PING with a barrier nonce
- Client commits to UDP-QSP only after receiving the matching barrier PONG
- During the transition window, either side MAY drop DATA on the inactive transport

---

## Constants Reference

| Constant               | Value | Description                              |
|------------------------|-------|------------------------------------------|
| MAX_DCID_LEN           | 20    | Maximum QUIC DCID length                 |
| QUIC_DCID_PREFIX_LEN   | 20    | Prefix length for UDP-QSP classification |
| AUTH_CHALLENGE_LEN     | 32    | Length of authentication challenge       |
| AUTH_SIGNATURE_LEN     | 64    | Length of Ed25519 signature              |
| HP_KEY_LEN             | 16    | Length of header protection key          |
| AEAD_KEY_LEN           | 16    | Length of AEAD key                       |
| AEAD_IV_LEN            | 12    | Length of AEAD IV                        |
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
