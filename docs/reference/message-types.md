# Message Types Quick Reference

## Message Types

| Type ID | Name            | Direction | Payload Size | Description                              |
|---------|-----------------|-----------|--------------|------------------------------------------|
| `0x01`  | AUTH            | C->S      | 116 bytes    | Client authentication request            |
| `0x02`  | AUTH_OK         | S->C      | 0 bytes      | Authentication accepted                  |
| `0x03`  | AUTH_FAIL       | S->C      | 1 byte       | Authentication rejected                  |
| `0x04`  | REGISTER_CID    | C->S      | 128-148 bytes | Register UDP-QSP CID and keys            |
| `0x05`  | REGISTER_OK     | S->C      | 21 bytes     | CID registration accepted                |
| `0x06`  | REGISTER_FAIL   | S->C      | 1 byte       | CID registration rejected                |
| `0x07`  | PING            | Both      | 8 bytes      | Keepalive ping                           |
| `0x08`  | PONG            | Both      | 8 bytes      | Keepalive pong                           |
| `0x09`  | CLOSE           | Both      | 1 byte       | Close the session                        |
| `0x0a`  | DATA            | Both      | Variable     | Tunnel data (raw IP packet)              |
| `0x0b`  | UPGRADE_PROBE   | C->S      | 16 bytes     | UDP path validation probe                |
| `0x0c`  | UPGRADE_PROBE_ACK | S->C    | 16 bytes     | UDP path validation acknowledgement      |
| `0x0d`  | UDP_READY       | C->S      | 8 bytes      | Client signals UDP path validated        |
| `0x0e`  | SWITCH_TO_UDP   | S->C      | 8 bytes      | Server commits transport switch to UDP   |
| `0x0f`  | SWITCH_ACK      | C->S      | 8 bytes      | Client acknowledges switch commit        |

## Error Codes

### AuthFailCode (`AUTH_FAIL` payload)

| Code   | Name            | Description                        |
|--------|-----------------|------------------------------------|
| `0x00` | Unknown         | Unspecified failure                |
| `0x01` | UnknownClient   | Client is not in the allowlist     |
| `0x02` | Disabled        | Client is disabled in the config   |
| `0x03` | BadSignature    | Signature verification failed      |
| `0x04` | IpMismatch      | Assigned IP does not match config  |
| `0x05` | ChallengeInvalid| Challenge is expired or invalid    |

### RegisterFailCode (`REGISTER_FAIL` payload)

| Code   | Name            | Description                        |
|--------|-----------------|------------------------------------|
| `0x00` | Unknown         | Unspecified failure                |
| `0x01` | NotAuthenticated| Client is not authenticated        |
| `0x02` | InvalidCipher   | Unsupported or invalid cipher suite|
| `0x03` | InvalidCid      | Invalid CID length or format       |
| `0x04` | InvalidKeys     | Invalid key material               |

### CloseCode (`CLOSE` payload)

| Code   | Name            | Description                        |
|--------|-----------------|------------------------------------|
| `0x00` | Normal          | Normal shutdown                    |
| `0x01` | AuthTimeout     | Authentication timeout             |
| `0x02` | IdleTimeout     | Idle timeout                       |
| `0x03` | ProtocolError   | Protocol error                     |
| `0x04` | ServerRestart   | Server shutdown or restart         |

## Cipher Suites

| ID     | Name               | Status    |
|--------|--------------------| --------- |
| `0x01` | AES-128-GCM        | Required  |
| `0x02` | ChaCha20-Poly1305  | Reserved  |

## Constants

### Lengths

| Constant             | Value  | Description                               |
|----------------------|--------|-------------------------------------------|
| `MAX_DCID_LEN`       | 20     | Maximum QUIC DCID length                   |
| `QUIC_DCID_PREFIX_LEN`| 20    | DCID prefix length for classification      |
| `CLIENT_ID_LEN`      | 16     | Client identifier length                   |
| `AUTH_CHALLENGE_LEN` | 32     | Authentication challenge length            |
| `AUTH_SIGNATURE_LEN` | 64     | Ed25519 signature length                   |
| `AUTH_PAYLOAD_LEN`   | 116    | Full AUTH payload length                   |
| `PING_PAYLOAD_LEN`   | 8      | PING/PONG payload length                   |
| `CLOSE_PAYLOAD_LEN`  | 1      | CLOSE payload length                       |
| `UPGRADE_ID_PAYLOAD_LEN`| 8    | Upgrade identifier payload length          |
| `UPGRADE_PROBE_PAYLOAD_LEN`| 16 | UDP upgrade probe/ack payload length       |

### Key Material

| Constant      | Value | Description               |
|---------------|-------|---------------------------|
| `HP_KEY_LEN`  | 16    | Header protection key     |
| `AEAD_KEY_LEN`| 16    | AEAD encryption key       |
| `AEAD_IV_LEN` | 12    | AEAD initialization vector|

### Frame Format

| Field   | Size     | Description                    |
|---------|----------|--------------------------------|
| TYPE    | 1 byte   | Message type identifier        |
| LEN     | 4 bytes  | Payload length (big-endian)    |
| PAYLOAD | Variable | Message-specific payload       |

## See Also

- [messages.md](../protocol/messages.md) - Detailed message schemas and field layouts
- [wire-format.md](../protocol/wire-format.md) - Frame encoding and transport details
