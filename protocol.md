# VPN v1 Protocol

This document is the authoritative definition of the VPN wire protocol, packet flow,
and state machines. If this document disagrees with `spec.txt` or the implementation,
update them to match this document.

## 1. Scope and roles

Terminology:
- Wrapper: process that owns public `:443/tcp` and `:443/udp` sockets and routes
  traffic to either VPN handlers or nginx.
- VPN handler: TLS-terminating server logic that runs the VPN protocol and TUN I/O.
- UDP-QSP: QUIC-shaped UDP packet protection for VPN data (short headers only).

This protocol multiplexes VPN traffic and public web traffic on the same endpoints.
Unknown traffic is forwarded to nginx; claimed traffic is handled by the VPN server.

## 2. Front door classification and routing

### 2.1 TCP classification (ClientHello token)

The wrapper inspects the TLS ClientHello `legacy_session_id` field.

Requirements:
- `legacy_session_id` length MUST be exactly 32 bytes.
- The 32 bytes are `part1 || part2`, each 16 bytes.
- `part1 = HMAC-SHA256(random[0:16] || server_secret)[:16]`
- `part2 = HMAC-SHA256(key_share || server_secret)[:16]`
- `key_share` is the X25519 key share (32 bytes) from the ClientHello.

Classification logic:
1) If `legacy_session_id` length != 32 -> PASS (forward to nginx).
2) Verify `part1` using ClientHello `random[0:16]`. If invalid -> PASS.
3) Verify `part2` using ClientHello X25519 key share. If missing/invalid -> PASS.
4) If both valid -> CLAIM (route to VPN handler).

### 2.2 UDP classification (QUIC-shaped)

The wrapper applies per-datagram rules:
- If datagram is not QUIC-format -> DROP.
- If QUIC long header -> PASS (forward to nginx).
- If QUIC short header:
  - If DCID exists in `cid_map` -> CLAIM (route to VPN UDP-QSP).
  - Else -> PASS (forward to nginx).

Unknown UDP is forwarded via a 4-tuple NAT mapping (`src_ip:src_port -> local_udp_socket`)
with LRU + idle timeout.

## 3. TCP VPN protocol (control + data)

### 3.1 Frame format

All VPN messages on TCP are framed as:

```
TYPE: u8
LEN:  u32 (big-endian)
PAYLOAD: LEN bytes
```

- `LEN` is the payload length only (not including the 5-byte header).
- `LEN` MUST be <= `max_frame_len` (config).

### 3.2 Message types

```
Type          Id    Direction     Payload
AUTH          0x01  C -> S        AuthPayload
AUTH_OK       0x02  S -> C        empty
AUTH_FAIL     0x03  S -> C        AuthFailPayload
REGISTER_CID  0x04  C -> S        RegisterCidPayload
REGISTER_OK   0x05  S -> C        RegisterOkPayload
REGISTER_FAIL 0x06  S -> C        RegisterFailPayload
PING          0x07  both          PingPayload
PONG          0x08  both          PongPayload
CLOSE         0x09  both          ClosePayload
DATA          0x0a  both          raw IP packet
UPGRADE_PROBE 0x0b  C -> S (UDP)  UpgradeProbePayload
UPGRADE_PROBE_ACK 0x0c  S -> C (UDP)  UpgradeProbeAckPayload
UDP_READY     0x0d  C -> S (TCP)  UdpReadyPayload
SWITCH_TO_UDP 0x0e  S -> C (TCP)  SwitchToUdpPayload
SWITCH_ACK    0x0f  C -> S (TCP)  SwitchAckPayload
```

### 3.3 State rules (TCP)

Before authentication completes:
- Only `AUTH`, `PING`, and `CLOSE` are valid from the client.
- Any `DATA` or `REGISTER_CID` received before `AUTH_OK` MUST be rejected (protocol error).

After `AUTH_OK`:
- `DATA` may be sent on TCP (until UDP-QSP becomes active).
- `REGISTER_CID` may be sent to enable UDP-QSP.
- UDP upgrade commit control on TCP uses:
  - `UDP_READY` (client -> server)
  - `SWITCH_TO_UDP` (server -> client)
  - `SWITCH_ACK` (client -> server)

### 3.4 Payload schemas

Constants:
- `QUIC_DCID_PREFIX_LEN = 20` (classifier prefix length for UDP-QSP)
- `MAX_DCID_LEN = 20`
- `AUTH_CHALLENGE_LEN = 32`
- `AUTH_SIGNATURE_LEN = 64`
- `HP_KEY_LEN = 16`
- `AEAD_KEY_LEN = 16`
- `AEAD_IV_LEN = 12`

#### AUTH payload (116 bytes)

```
offset size field
0      16   client_id
16     4    assigned_ipv4 (network order)
20     32   challenge
52     64   signature (Ed25519)
```

Challenge derivation:
- `challenge = TLS-Exporter("slt-auth-challenge", "", 32)`
- The exporter is computed after the TLS handshake completes.

Signature input:
```
context = b"slt-auth-v1" || client_id || assigned_ipv4 || challenge
signature = Ed25519.sign(client_private_key, context)
```

Server validation:
- `client_id` exists and enabled.
- `assigned_ipv4` matches server config for this `client_id`.
- `challenge` equals the TLS exporter output.
- `signature` verifies under the configured public key.

#### AUTH_OK payload
Empty payload (length 0).

#### AUTH_FAIL payload (1 byte)

```
0: code
```

`AuthFailCode` values:
- `0x00` Unknown
- `0x01` UnknownClient
- `0x02` Disabled
- `0x03` BadSignature
- `0x04` IpMismatch
- `0x05` ChallengeInvalid

#### REGISTER_CID payload

```
offset size field
0      1    client_to_server_cid_len (must be exactly `MAX_DCID_LEN`)
1      N    client_to_server_cid
1+N    1    server_to_client_cid_len (`0`..=`MAX_DCID_LEN`)
2+N    M    server_to_client_cid
...    1    cipher
...    16   hp_tx
...    16   hp_rx
...    16   aead_tx
...    16   aead_rx
...    12   iv_tx
...    12   iv_rx
...    8    pn_start (u64, big-endian)
...    8    pn_start_rx (u64, big-endian)
...    1    key_phase (0 or 1)
```

Total length = `109 + client_to_server_cid_len + server_to_client_cid_len` bytes.

Server requirements:
- `client_to_server_cid_len` MUST be exactly `MAX_DCID_LEN` (20 bytes).
- `server_to_client_cid_len` MUST be within `0..=MAX_DCID_LEN`.
- The server MUST reject `REGISTER_CID` if another active connection already
  uses the same `QUIC_DCID_PREFIX_LEN`-byte prefix. Retransmits or
  re-registrations for the same connection MAY replace the existing entry.

Key direction:
- For a client->server `REGISTER_CID`, `*_tx` are the keys the server uses to send
  packets to the client, and `*_rx` are the keys the server uses to open packets
  from the client. The client uses the opposite directions.
- `client_to_server_cid` is used for client->server packets.
- `server_to_client_cid` is used for server->client packets.
- `pn_start` is the initial packet number for server->client traffic.
- `pn_start_rx` is the initial packet number expected from the client.

Cipher suites:
- `0x01` AES-128-GCM (required)
- `0x02` ChaCha20-Poly1305 (reserved, currently unsupported)

#### REGISTER_OK payload

```
0: client_to_server_cid_len (must be exactly `MAX_DCID_LEN`)
1..: client_to_server_cid
```

#### REGISTER_FAIL payload (1 byte)

`RegisterFailCode` values:
- `0x00` Unknown
- `0x01` NotAuthenticated
- `0x02` InvalidCipher
- `0x03` InvalidCid
- `0x04` InvalidKeys

#### PING / PONG payload (8 bytes)

```
nonce: u64 (big-endian)
```

`PONG` MUST echo the received `PING` nonce. Clients need not validate the
nonce on receipt: transport security (TLS on TCP, AEAD on UDP-QSP) prevents
injection, and a late PONG with a stale nonce still proves liveness.

#### UPGRADE_PROBE / UPGRADE_PROBE_ACK payload (16 bytes)

```
upgrade_id: u64 (big-endian)
nonce:      u64 (big-endian)
```

`UPGRADE_PROBE_ACK` MUST echo both `upgrade_id` and `nonce` from the probe.

#### UDP_READY / SWITCH_TO_UDP / SWITCH_ACK payload (8 bytes)

```
upgrade_id: u64 (big-endian)
```

#### CLOSE payload (1 byte)

`CloseCode` values:
- `0x00` Normal
- `0x01` AuthTimeout
- `0x02` IdleTimeout
- `0x03` ProtocolError
- `0x04` ServerRestart

#### DATA payload

Raw IP packet (currently IPv4 only). The server MUST enforce
`src_ip == assigned_ipv4` and drop any packet that violates this.
`DATA` payload length MUST be <= `max_data_len` (config).
`tun_mtu` MUST be in `1..=1406`.

MTU rationale for `1406`:
- Target outer transport envelope: Ethernet IP MTU `1500`.
- Outer overhead budget (worst case): IPv6 header `40` + UDP header `8`.
- UDP-QSP + VPN framing overhead (worst case): short-header fields `1 + 20 + 4`,
  AEAD tag `16`, VPN frame header `5` => `46`.
- Budget: `1500 - 48 - 46 = 1406`.

## 4. UDP-QSP (QUIC-shaped data plane)

UDP-QSP uses QUIC short headers for wire shape only. There is no QUIC handshake
on the VPN path. Long-header QUIC traffic always goes to nginx.

### 4.1 Packet layout (short header)

```
first_byte | dcid | pn | ciphertext || tag
```

Short header first byte bits:
- bit7: header form (MUST be 0)
- bit6: fixed bit (MUST be 1)
- bit5: spin (unused, SHOULD be 0, receiver ignores)
- bit4-3: reserved (MUST be 0)
- bit2: key phase
- bit1-0: packet number length minus 1 (values 0..3 -> lengths 1..4 bytes)

Packet number length selection:
- Sender MUST use the minimal length (1..4 bytes) to encode the packet number.
- Full packet number space is `u64`.
- Senders MUST NOT wrap packet numbers; once `next_pn` would overflow `u64`,
  the session MUST be replaced.
- For UDP-QSP, the first `QUIC_DCID_PREFIX_LEN` bytes of the DCID are used as
  the classifier prefix.

### 4.2 Header protection (HP)

Header protection follows QUIC short-header rules:
- HP sample length = 16 bytes.
- Sample offset = `pn_offset + 4`, where `pn_offset = 1 + dcid_len`.
- Mask is derived by encrypting the 16-byte sample with AES-128-ECB using `hp_*` key.
- Apply mask:
  - `first_byte ^= mask[0] & 0x1f`
  - each PN byte `pn[i] ^= mask[1 + i]`

### 4.3 Payload protection (AEAD)

- Cipher: AES-128-GCM only (tag length 16 bytes).
- AEAD key/IV are from `REGISTER_CID`.
- Nonce: `iv XOR pn`, where `pn` is encoded as u64 and XORed into the last 8 bytes of `iv`.
- Associated data (AD): the unprotected header (first_byte + dcid + pn).
- Ciphertext = `AEAD(plaintext, ad)` followed by 16-byte tag.

### 4.4 Padding for HP sample

If the ciphertext (including tag) would be too short to provide a 16-byte HP sample,
the sender MUST append zero padding to the plaintext before encryption so that:

```
ciphertext_len >= (pn_offset + 4 + 16) - header_len
```

Receivers MUST ignore any trailing bytes after decoding the first framed message.

### 4.5 UDP-QSP payload

Each UDP datagram carries exactly one framed message using the same
`TYPE + LEN + PAYLOAD` format as TCP.

Allowed message types on UDP-QSP: `DATA`, `PING`, `PONG`, `CLOSE`,
`UPGRADE_PROBE`, and `UPGRADE_PROBE_ACK`.

`AUTH`, `AUTH_OK`, and `AUTH_FAIL` are TCP-only.
`REGISTER_CID`, `REGISTER_OK`, `REGISTER_FAIL`, `UDP_READY`, `SWITCH_TO_UDP`,
and `SWITCH_ACK` are control-plane messages on TCP.

### 4.6 Packet number reconstruction

Packet numbers are transmitted with 1-4 bytes. Receivers MUST reconstruct the
full packet number using the expected next value.

Definitions (per CID, per direction):
- `largest_pn`: highest packet number successfully accepted so far.
- `expected = largest_pn + 1`
- `pn_nbits = pn_len * 8`
- `pn_win = 1 << pn_nbits`
- `pn_hwin = pn_win / 2`
- `pn_mask = pn_win - 1`

Reconstruction:

```
candidate = (expected & ~pn_mask) | truncated

if candidate + pn_hwin <= expected:
    candidate += pn_win
else if candidate > expected + pn_hwin and candidate >= pn_win:
    candidate -= pn_win
```

Use the reconstructed `candidate` as the packet number for replay checks and
nonce generation.

### 4.7 Replay protection window

Each CID maintains a fixed replay window to tolerate reordering and reject
replays.

Constants:
- `PN_REPLAY_WINDOW = 1024` packets (1024-bit bitmap = 128 bytes).

Rules:
- If `pn > largest_pn`: accept, advance `largest_pn`, and slide the window.
- If `pn <= largest_pn`:
  - `delta = largest_pn - pn`
  - If `delta >= PN_REPLAY_WINDOW`: drop (too old).
  - If bit `delta` is already set: drop (replay).
  - Else set bit `delta` and accept.

Implementation note:
- Use a ring-buffer bitmap to avoid shifting `PN_REPLAY_WINDOW` bits per packet.

### 4.8 Key update and key phase

UDP-QSP key update is in-band and does not use `REGISTER_CID` retransmits.
Both sides derive new keys locally with HKDF from prior key state.

Requirements:
- Rekey interval MUST be much larger than `PN_REPLAY_WINDOW` (1024). A
  recommended baseline is `2^21` packets per direction.
- At most one key update may be in flight per direction.
- Key update rotates HP key, AEAD key, and IV together for that direction.

Sender behavior:
- When local TX packet number crosses the rekey interval threshold, derive next
  directional keys with HKDF, switch to them, and flip `key_phase` on outgoing
  packets.
- Continue sending with the new key phase; no explicit rekey ACK message is
  sent.

Receiver behavior:
- Maintain RX key states: `current` and `previous`.
- On packet open attempt:
  - try `current` first,
  - try `previous` only while inside a bounded grace window,
  - derive ephemeral `candidate = KDF(current)` and try it only inside a bounded
    rekey window around expected rekey packet number.
- If `candidate` succeeds, promote:
  - `previous = current`
  - `current = candidate`
- Rekey window uses asymmetric margins:
  - `early_margin`: small, before threshold,
  - `late_margin`: larger, after threshold.
- If receive state is beyond `late_margin` and packets still fail to open, the
  channel is treated as dead and the endpoint reconnects.

## 5. Connection flow and state machines

### 5.1 TCP VPN session establishment

1) Client connects to `:443/tcp` and presents a claim token in ClientHello.
2) Wrapper claims or passes through per Section 2.1.
3) VPN handler completes TLS handshake.
4) Client sends `AUTH` with signature proof.
5) Server replies `AUTH_OK` or `AUTH_FAIL`.

On `AUTH_OK`, the session is authenticated and TCP data is permitted.

### 5.2 UDP-QSP enablement

1) Client establishes a real QUIC connection to nginx to obtain a DCID.
2) Client sends the **initial** `REGISTER_CID` over the authenticated TCP channel with:
   - DCID
   - UDP-QSP keys
   - `pn_start` and `key_phase`
3) Server validates, inserts CID into `cid_map`, and replies `REGISTER_OK`.
4) Client starts UDP probing with `UPGRADE_PROBE(upgrade_id, nonce)` until an
   `UPGRADE_PROBE_ACK` is received.
5) After probe acknowledgment, client sends TCP `UDP_READY(upgrade_id)`.
6) Server sends TCP `SWITCH_TO_UDP(upgrade_id)` only after both conditions are true:
   - a valid UDP probe was observed
   - matching `UDP_READY` was observed on TCP
7) Client commits by sending TCP `SWITCH_ACK(upgrade_id)`.
8) Both sides treat UDP-QSP as active only after `SWITCH_ACK` is processed.

The server MUST NOT treat UDP-QSP as active before `SWITCH_ACK` commit. Control
messages remain split by transport: probes on UDP, commit on TCP.

### 5.3 Active transport and fallback

- Only one active data path per `client_id` at a time.
- Registration and switch-commit control remain on TCP (except UDP probes).
- `CLOSE` on UDP-QSP is best-effort; if dropped, idle timeout closes the session.
- If UDP-QSP fails (idle timeout), the server MAY fall back to TCP if still connected.
- A new authenticated session for the same `client_id` takes over and replaces any
  previous session (old CIDs are removed).

## 6. Keepalive and timeouts

Configurable timeouts:
- `auth_timeout`: time allowed from accept to `AUTH_OK`.
- `idle_timeout`: no inbound traffic on the active transport triggers disconnect.

Keepalive:
- PINGs are sent only on the active transport.
- Interval is randomized per connection: `uniform(ping_min, ping_max)`.

## 7. Security invariants

- No `DATA` is accepted or forwarded before authentication.
- Anti-spoofing is mandatory: `src_ip` must match the assigned IPv4.
- All classifier logic is bounded in CPU and memory.
- UDP-QSP packets with invalid headers, invalid PN length, or failed AEAD MUST be dropped.
