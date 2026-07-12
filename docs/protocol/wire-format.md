# Wire Format

This document describes the VPN protocol frame format, message types, and transport rules.

## 1. Frame Format

All VPN messages use a simple length-prefixed framing:

```
+------+------+------+------+------+------+------...---+
| TYPE | LEN (4 bytes, big-endian) |    PAYLOAD        |
+------+------+------+------+------+------+------...---+
  u8              u32                      LEN bytes
```

- **TYPE** (1 byte): Message type identifier (see [Message Types](#2-message-types))
- **LEN** (4 bytes, big-endian): Payload length in bytes
- **PAYLOAD** (LEN bytes): Message-specific payload

### Constraints

- `LEN` is the payload length only (not including the 5-byte header)
- `LEN` MUST be <= `max_frame_len` (configurable)
- `DATA` payload length MUST be <= `max_data_len` (configurable)
- `tun_mtu` MUST be in `1..=1406`
- The client `tun_mtu` carried in `AUTH` MUST equal the server `tun_mtu`

### MTU Rationale

Maximum `tun_mtu` of 1406 is derived from:

- Target outer transport envelope: Ethernet IP MTU `1500`
- Outer overhead budget (worst case): IPv6 header `40` + UDP header `8`
- UDP-QSP + VPN framing overhead (worst case):
  - Short-header fields: `1 + 20 + 4`
  - AEAD tag: `16`
  - VPN frame header: `5`
  - Total overhead: `46`
- Budget: `1500 - 48 - 46 = 1406`

## 2. Message Types

| Type             | ID    | Direction         | Description                                    |
|------------------|-------|-------------------|------------------------------------------------|
| AUTH             | 0x01  | Client -> Server  | Client authentication request                  |
| AUTH_OK          | 0x02  | Server -> Client  | Authentication accepted                        |
| AUTH_FAIL        | 0x03  | Server -> Client  | Authentication rejected                        |
| REGISTER_CID     | 0x04  | Client -> Server  | Register UDP-QSP connection ID and traffic secrets |
| REGISTER_OK      | 0x05  | Server -> Client  | CID registration accepted                      |
| REGISTER_FAIL    | 0x06  | Server -> Client  | CID registration rejected                      |
| PING             | 0x07  | Both              | Keepalive ping                                 |
| PONG             | 0x08  | Both              | Keepalive pong (echoes PING nonce)             |
| CLOSE            | 0x09  | Both              | Close the session                              |
| DATA             | 0x0a  | Both              | Tunnel data (raw IP packet)                    |
| UPGRADE_PROBE    | 0x0b  | Client -> Server  | UDP path validation probe during upgrade       |
| UPGRADE_PROBE_ACK| 0x0c  | Server -> Client  | UDP path validation probe acknowledgement      |
| UDP_READY        | 0x0d  | Client -> Server  | Client indicates UDP path is validated         |
| SWITCH_TO_UDP    | 0x0e  | Server -> Client  | Server requests transport switch to UDP         |
| SWITCH_ACK       | 0x0f  | Client -> Server  | Client accepts the UDP switch request           |
| FALLBACK_TO_TCP  | 0x10  | Both              | Request TCP as the preferred transport          |
| FALLBACK_OK      | 0x11  | Both              | Acknowledge TCP fallback                        |
| SWITCH_OK        | 0x12  | Server -> Client  | Confirm the UDP switch acknowledgement          |

## 3. State Rules

### Before Authentication

Before `AUTH_OK` is received:

- **Valid from client**: `AUTH`, `PING`, `PONG`, `CLOSE`
- **Valid from server**: `AUTH_OK`, `AUTH_FAIL`, `PING`, `PONG`, `CLOSE`
- **Invalid**: `DATA`, `REGISTER_CID`, and all other messages
- Any `DATA` or `REGISTER_CID` received before `AUTH_OK` MUST be rejected as protocol error

### After Authentication

After `AUTH_OK`:

- Authenticated `DATA` is accepted on either live transport
- `REGISTER_CID` may be sent to enable UDP-QSP
- UDP upgrade commit control messages become valid:
  - `UDP_READY` (client -> server)
  - `SWITCH_TO_UDP` (server -> client)
  - `SWITCH_ACK` (client -> server)
  - `SWITCH_OK` (server -> client)
- `FALLBACK_TO_TCP` and `FALLBACK_OK` are valid bidirectional TCP control messages

### Session Lifecycle

1. Client connects and completes TLS 1.3 handshake
2. Client sends `AUTH`
3. Server replies `AUTH_OK` or `AUTH_FAIL`
4. On success, TCP data transfer is permitted
5. Client may register UDP-QSP CID for data plane upgrade
6. Preferred transport switches from TCP to UDP-QSP after switch commit

## 4. Transport Mapping

### TCP-Only Messages

These messages are only sent on the TCP control channel:

| Message          | Notes                                           |
|------------------|-------------------------------------------------|
| AUTH             | Authentication requires TLS channel binding     |
| AUTH_OK          | Authentication response                         |
| AUTH_FAIL        | Authentication response                         |
| REGISTER_CID     | Registers UDP traffic secrets over TCP          |
| REGISTER_OK      | Registration response                           |
| REGISTER_FAIL    | Registration response                           |
| UDP_READY        | UDP upgrade commit (control plane)              |
| SWITCH_TO_UDP    | UDP upgrade commit (control plane)              |
| SWITCH_ACK       | UDP upgrade commit (control plane)              |
| SWITCH_OK        | UDP upgrade commit confirmation (control plane) |
| FALLBACK_TO_TCP  | Requests TCP as the preferred data path         |
| FALLBACK_OK      | Confirms TCP fallback                           |

### UDP-QSP-Only Messages

These messages are only sent on the UDP-QSP data plane:

| Message           | Notes                                        |
|-------------------|----------------------------------------------|
| UPGRADE_PROBE     | UDP path validation probe                    |
| UPGRADE_PROBE_ACK | UDP path validation response                 |

### Bidirectional Messages

These messages can be sent on either transport:

| Message | TCP | UDP-QSP | Notes                                |
|---------|-----|---------|--------------------------------------|
| DATA    | Yes | Yes     | Raw IP packet tunneling              |
| PING    | Yes | Yes     | Keepalive (sent on preferred transport) |
| PONG    | Yes | Yes     | Keepalive response                   |
| CLOSE   | Yes | Yes     | Session termination                  |

### Preferred Transport Rules

- New DATA and PING messages are sent on the preferred transport
- Authenticated DATA received on either live transport is accepted
- Registration, switch-commit, and fallback control remain on TCP
- Cross-transport packet reordering is permitted
- `CLOSE` on UDP-QSP is best-effort; if dropped, idle timeout closes the session
- Either peer may request TCP fallback with `FALLBACK_TO_TCP`

## 5. Implementation Notes

### Frame Encoding

```rust
// Header length: 1 byte type + 4 bytes length
const HEADER_LEN: usize = 5;

// Encode: TYPE || LEN_BE32 || PAYLOAD
fn encode_frame(ty: MessageType, payload: &[u8], out: &mut Vec<u8>) {
    out.push(u8::from(ty));
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
}
```

### Frame Decoding

```rust
fn decode_frame(buf: &[u8], max_len: usize) -> Option<(Frame, usize)> {
    if buf.len() < HEADER_LEN {
        return None;
    }

    let ty = MessageType::try_from(buf[0])?;
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

    if len > max_len {
        return Err(FrameError::LengthTooLarge { len, max: max_len });
    }

    let total_len = HEADER_LEN + len;
    if buf.len() < total_len {
        return None;
    }

    Some((Frame { ty, payload: &buf[HEADER_LEN..total_len] }, total_len))
}
```

### UDP-QSP Payload Format

Each UDP datagram carries exactly one framed message using the same `TYPE + LEN + PAYLOAD` format as TCP. The frame is encrypted with the negotiated UDP-QSP cipher suite using QUIC short-header packet protection; see the [UDP-QSP cipher suites](udp-qsp.md#cipher-suites) table.
