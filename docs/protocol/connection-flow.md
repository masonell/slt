# Connection Flow and State Machines

This document describes the VPN session lifecycle, from initial TCP connection through
UDP-QSP upgrade, including state transitions and termination handling.

## 1. TCP Session Establishment

The TCP connection flow establishes an authenticated VPN session over TLS.

### 1.1 Connection Sequence

```
Client                                    Server
  |                                         |
  |  1. TCP connect to :443                 |
  |---------------------------------------->|
  |                                         |
  |  2. TLS ClientHello with token          |
  |    (legacy_session_id = 32-byte HMAC)   |
  |---------------------------------------->|
  |                                         |  3. Validate token
  |                                         |     - Check legacy_session_id length
  |                                         |     - Verify part1 (random-based HMAC)
  |                                         |     - Verify part2 (key_share-based HMAC)
  |                                         |     - CLAIM or PASS decision
  |                                         |
  |                                         |  4. If CLAIM, acquire auth slot
  |                                         |     - Bounded by max_auth_inflight
  |                                         |     - Over-limit connections are closed
  |                                         |
  |  5. TLS handshake completes             |
  |<=======================================>|
  |                                         |
  |  6. AUTH message                        |
  |    - client_id (16 bytes)               |
  |    - assigned_ipv4 (4 bytes)            |
  |    - challenge (32 bytes, TLS exporter) |
  |    - signature (64 bytes, Ed25519)      |
  |---------------------------------------->|
  |                                         |  7. Validate AUTH
  |                                         |     - client_id exists and enabled
  |                                         |     - IPv4 matches config
  |                                         |     - challenge matches exporter
  |                                         |     - signature verifies
  |                                         |
  |  8. AUTH_OK or AUTH_FAIL                |
  |<----------------------------------------|
  |                                         |
  |  Session now AUTHENTICATED              |
  |                                         |
```

### 1.2 AUTH Message Details

The client proves its identity by signing a challenge derived from the TLS session:

```
challenge = TLS-Exporter("slt-auth-challenge", "", 32)
context = b"slt-auth-v1" || client_id || assigned_ipv4 || challenge
signature = Ed25519.sign(client_private_key, context)
```

### 1.3 Pre-Authentication Constraints

Before `AUTH_OK` is received:
- Only `AUTH`, `PING`, and `CLOSE` messages are valid from the client
- Any `DATA` or `REGISTER_CID` received before authentication MUST be rejected
- Server enforces `auth_timeout` from connection acceptance

### 1.4 Authentication Failure Codes

| Code | Name | Description |
|------|------|-------------|
| 0x00 | Unknown | Generic failure |
| 0x01 | UnknownClient | client_id not found |
| 0x02 | Disabled | client_id is disabled |
| 0x03 | BadSignature | Signature verification failed |
| 0x04 | IpMismatch | assigned_ipv4 does not match |
| 0x05 | ChallengeInvalid | TLS challenge mismatch |

---

## 2. UDP-QSP Enablement (Upgrade Flow)

After TCP authentication, the client may upgrade to UDP-QSP for better performance.
This is an optional but recommended optimization.

### 2.1 Prerequisites

Before UDP upgrade can begin:
1. TCP session must be `AUTHENTICATED`
2. Client must discover a QUIC DCID by establishing a real QUIC connection to nginx
3. Client generates UDP-QSP traffic secrets and packet number state

### 2.2 Upgrade Sequence

```
Client                                    Server
  |                                         |
  |  [Prerequisites: TCP authenticated,     |
  |   QUIC discovery complete]              |
  |                                         |
  |  1. REGISTER_CID over TCP               |
  |    - client_to_server_cid (20 bytes)    |
  |    - server_to_client_cid (0-20 bytes)  |
  |    - cipher                             |
  |    - secret_tx, secret_rx               |
  |    - pn_start, pn_start_rx              |
  |    - key_phase (0 or 1)                 |
  |---------------------------------------->|
  |                                         |  2. Validate and store CID
  |                                         |     - Check CID prefix uniqueness
  |                                         |     - Install keys in cid_map
  |                                         |
  |  3. REGISTER_OK                         |
  |<----------------------------------------|
  |                                         |
  |  [UDP-QSP session now registered]       |
  |                                         |
  |  4. UPGRADE_PROBE (UDP)                 |
  |    - upgrade_id (8 bytes)               |
  |    - nonce (8 bytes)                    |
  |---------------------------------------->|
  |                                         |  5. Validate probe
  |                                         |     - CID lookup succeeds
  |                                         |     - AEAD decryption passes
  |                                         |
  |  6. UPGRADE_PROBE_ACK (UDP)             |
  |<----------------------------------------|
  |                                         |
  |  [UDP path validated]                   |
  |                                         |
  |  7. UDP_READY (TCP)                     |
  |    - upgrade_id                         |
  |---------------------------------------->|
  |                                         |
  |  8. SWITCH_TO_UDP (TCP)                 |
  |    - upgrade_id                         |
  |<----------------------------------------|
  |                                         |
  |  9. SWITCH_ACK (TCP)                    |
  |    - upgrade_id                         |
  |---------------------------------------->|
  |                                         |
  |  [Server prefers UDP-QSP]               |
  |                                         |
  |  10. SWITCH_OK (TCP)                    |
  |    - upgrade_id                         |
  |<----------------------------------------|
  |                                         |
  |  [UDP-QSP is now preferred for DATA]    |
  |  [Both live ingress paths remain valid] |
  |                                         |
```

### 2.3 Upgrade State Machine (Client Side)

```
Idle -> Upgrading -> SWITCH_TO_UDP received -> AwaitingSwitchOk
                                                |
                                                | SWITCH_OK received
                                                v
                                          UDP-QSP preferred

Upgrading -- timeout/failure --> TcpOnlyBlockedUdp --> retry
```

The client installs the UDP-QSP receive state before it reports `UDP_READY`.
After receiving a matching `SWITCH_TO_UDP`, it sends `SWITCH_ACK` but keeps TCP
as its preferred outbound transport. A matching `SWITCH_OK` confirms that the
server processed the acknowledgement, after which the client prefers UDP-QSP.
TCP loss before confirmation ends the client session so reconnection can
establish unambiguous transport state.

### 2.4 Upgrade State Machine (Server Side)

```
Idle -> probe_seen + ready_seen -> SWITCH_TO_UDP sent
                                      |
                                      | SWITCH_ACK received
                                      v
                                UDP-QSP preferred
                                      |
                                      | send SWITCH_OK
                                      v
                              client may prefer UDP
```

The server has already installed the UDP-QSP receive state when it sends
`SWITCH_TO_UDP`. It makes UDP-QSP its preferred outbound transport after a
matching `SWITCH_ACK`, then confirms that commit with `SWITCH_OK` on TCP.

### 2.5 Transport Switching Invariant

`active_transport` selects the preferred transport for new outbound DATA; it
is not an ingress allowlist. Authenticated DATA is accepted on TCP and UDP-QSP
while those transports remain live. This make-before-break rule preserves
frames already in flight on the prior path without DATA transition buffers or
a cross-transport barrier. The `SWITCH_OK` control acknowledgement establishes
that both peers observed the commit. Packets may be reordered across the
switch, as on an ordinary IP network.

### 2.6 Upgrade Probing Details

- Maximum probe attempts: 8 per upgrade cycle
- Probe backoff: exponential with jitter
- Probe timeout triggers `TcpOnlyBlockedUdp` state with cooldown
- Each upgrade attempt uses one random `(upgrade_id, nonce)` pair for all probe retransmissions
- A probe with a different `upgrade_id` supersedes the active attempt

---

## 3. State Machine Summary

### 3.1 Session States

| State | Description | Active Transport |
|-------|-------------|------------------|
| CONNECTING | TCP connection in progress | None |
| AUTHENTICATING | TLS complete, awaiting AUTH result | None |
| AUTHENTICATED | AUTH_OK received, TCP data allowed | TCP |
| UDP_REGISTERING | REGISTER_CID sent, awaiting REGISTER_OK | TCP |
| UDP_PROBING | UPGRADE_PROBE sent, awaiting ACK | TCP |
| UDP_READY | UDP_READY sent, awaiting SWITCH_TO_UDP | TCP |
| UDP_SWITCH_PENDING | SWITCH_ACK sent, awaiting SWITCH_OK | TCP |
| UDP_ACTIVE | SWITCH_OK received; UDP-QSP preferred | UDP-QSP |
| TCP_ONLY_BLOCKED | UDP upgrade failed, cooldown active | TCP |

### 3.2 State Diagram

```
CONNECTING -> AUTHENTICATING -> AUTHENTICATED (TCP preferred)
                                      |
                                      v
                               UDP_REGISTERING
                                      |
                    +-----------------+----------------+
                    |                                  |
               REGISTER_FAIL                       REGISTER_OK
                    |                                  |
                    v                                  v
            retry or TCP-only                     UDP_PROBING
                                                  /          \
                                           timeout            probe acknowledged
                                             |                       |
                                             v                       v
                                    TCP_ONLY_BLOCKED             UDP_READY
                                             |                       |
                                          cooldown               SWITCH_TO_UDP
                                             |                       |
                                             +-> UDP_PROBING         v
                                                              UDP_SWITCH_PENDING
                                                                      |
                                                                  SWITCH_OK
                                                                      |
                                                                      v
                                                                 UDP_ACTIVE

UDP_ACTIVE -- FALLBACK_TO_TCP --> TCP preferred + UDP rediscovery
```

### 3.3 Valid Messages by State

| State | Valid Client Messages | Valid Server Messages |
|-------|----------------------|----------------------|
| AUTHENTICATING | AUTH, PING, CLOSE | AUTH_OK, AUTH_FAIL, PING, PONG, CLOSE |
| AUTHENTICATED | All except UPGRADE_* | All except SWITCH_TO_UDP |
| UDP_REGISTERING | (waiting for response) | REGISTER_OK, REGISTER_FAIL |
| UDP_PROBING | UPGRADE_PROBE, DATA, PING, PONG | UPGRADE_PROBE_ACK, DATA, PING, PONG |
| UDP_READY | (waiting for response) | SWITCH_TO_UDP |
| UDP_SWITCH_PENDING | DATA, PING, PONG, FALLBACK_TO_TCP, FALLBACK_OK | SWITCH_OK, DATA, PING, PONG, FALLBACK_TO_TCP, FALLBACK_OK |
| UDP_ACTIVE | DATA, PING, PONG, CLOSE, FALLBACK_TO_TCP, FALLBACK_OK | DATA, PING, PONG, CLOSE, FALLBACK_TO_TCP, FALLBACK_OK |

`FALLBACK_TO_TCP` and `FALLBACK_OK` are valid on TCP in every authenticated
state; a fallback request cancels any in-progress UDP switch.

---

## 4. Preferred Transport Rules

### 4.1 Single Preferred Transport

Only one transport is preferred for new outbound data at a time:

```
active_transport in { TCP, UDP_QSP }
```

- `TCP`: Initial state after authentication and the fallback target
- `UDP_QSP`: Preferred after successful UDP upgrade commit

The preferred transport does not restrict ingress. DATA authenticated by the
current TLS session or registered UDP-QSP keys is accepted from either live
path.

### 4.2 Transport Selection

```
func send_data(packet):
    match active_transport:
        TCP:
            tcp.write_message(DATA, packet)
        UDP_QSP:
            udp_qsp.write_message(DATA, packet)
```

### 4.3 TCP Fallback

Either peer can initiate fallback on the authenticated TCP control channel:

```
Requester                                Receiver
   |                                        |
   | FALLBACK_TO_TCP(fallback_id)           |
   |--------------------------------------->|
   |                                        | prefer TCP for outbound DATA
   | DATA (optional, ordered after request) |
   |--------------------------------------->|
   |                                        |
   | FALLBACK_OK(fallback_id)               |
   |<---------------------------------------|
```

The receiver changes its preferred egress before acknowledging the request.
TCP framing guarantees that DATA following `FALLBACK_TO_TCP` cannot overtake
it. Requests are idempotent, and a stale `FALLBACK_OK` does not change state.
Fallback is a hard egress cutover: protected UDP packets still buffered for
send are discarded rather than flushed or replayed over TCP. UDP receive state
is independent of that send queue.
The client keeps an existing authenticated UDP transport receive-capable while
it discovers and registers a replacement, then retires it after `REGISTER_OK`.
Clients with UDP upgrade disabled acknowledge fallback without starting
discovery.
When TCP is unavailable, the session reconnects instead of attempting an
uncoordinated fallback.

### 4.4 Session Takeover

A new authenticated session for the same `client_id` takes over any existing session:

```
on new_auth(client_id):
    if existing_session.exists(client_id):
        old_session = existing_session.get(client_id)
        old_session.send_close(Normal)
        old_session.cleanup()
        cid_map.remove(old_session.cids)
    existing_session.set(client_id, new_session)
```

This ensures:
- Only one active session per `client_id`
- Old connection IDs are invalidated
- Clean handoff during reconnection

---

## 5. Session Termination

### 5.1 Close Message Exchange

```
Client                                    Server
  |                                         |
  |  CLOSE (code)                           |
  |---------------------------------------->|
  |                                         |
  |  (optional) CLOSE (code)                |
  |<----------------------------------------|
  |                                         |
  |  [Session terminated]                   |
  |                                         |
```

Close is best-effort on UDP-QSP (may be dropped). TCP fallback is used if UDP fails.

### 5.2 Close Codes

| Code | Name | Description |
|------|------|-------------|
| 0x00 | Normal | Graceful shutdown |
| 0x01 | AuthTimeout | Authentication timed out |
| 0x02 | IdleTimeout | No activity within idle_timeout |
| 0x03 | ProtocolError | Protocol violation |
| 0x04 | ServerRestart | Server is shutting down |

### 5.3 Idle Timeout

Sessions terminate if no inbound traffic is received on the preferred transport:

```
idle_deadline = last_activity + idle_timeout

on idle_deadline_reached:
    send_close(IdleTimeout)
    terminate_session()
```

Keepalive PING/PONG exchanges prevent idle timeout during normal operation.

### 5.4 Server Restart

When the server shuts down gracefully:

```
on server_shutdown:
    for each session:
        session.send_close(ServerRestart)
        session.cleanup()
```

Clients should implement reconnection logic with exponential backoff.

### 5.5 Cleanup Actions

On session termination:

1. Remove CIDs from `cid_map`
2. Remove client_id from session registry
3. Release assigned IP (if applicable)
4. Close TUN channel
5. Abort background tasks (discovery, etc.)
6. Close sockets

---

## 6. Keepalive and Timeouts

### 6.1 Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| auth_timeout | 10s | End-to-end server TLS and AUTH deadline |
| tcp_write_timeout | 10s | Maximum TCP message write time; clients also apply it during authentication and UDP upgrade |
| udp_liveness_timeout | 90s | Server time without authenticated UDP-QSP ingress before TCP fallback |
| idle_timeout | 300s | Max idle time before disconnect |
| ping_min | 10s | Minimum keepalive interval |
| ping_max | 30s | Maximum keepalive interval |
| register_timeout | 10s | Time for REGISTER_OK/FAIL response |
| quic_discovery_timeout | 15s | Time for full QUIC DCID discovery attempt |

### 6.2 Ping Scheduling

```
next_ping = now + random(ping_min, ping_max)

on next_ping:
    send_ping()
    next_ping = now + random(ping_min, ping_max)
```

Random jitter prevents thundering herd when many clients reconnect simultaneously.

### 6.3 Activity Tracking

```
on any_inbound_message:
    last_activity = now

on authenticated_udp_qsp_packet:
    last_authenticated_udp_activity = now

if tcp_alive and now - last_authenticated_udp_activity >= udp_liveness_timeout:
    retire_udp_qsp()
    request_tcp_fallback()

on idle_deadline_reached:
    if now - last_activity >= idle_timeout:
        terminate_session()
```

---

## 7. Error Handling

### 7.1 UDP Errors

| Error | Action |
|-------|--------|
| AEAD decryption failure | Drop packet, increment metric |
| Unknown CID | Drop packet |
| Invalid packet number | Drop packet |
| Replay detected | Drop packet |
| UDP write failure | Fallback to TCP if alive |
| No authenticated UDP packet before `udp_liveness_timeout` | Fallback to TCP if alive |

### 7.2 TCP Errors

| Error | Action |
|-------|--------|
| TCP read returns 0 | If UDP active, continue on UDP; else terminate |
| TCP write failure | Terminate session |
| TCP write timeout | Terminate session |
| Frame too large | Terminate with ProtocolError |
| Invalid message type | Terminate with ProtocolError |

### 7.3 Protocol Errors

| Condition | Action |
|-----------|--------|
| DATA before AUTH_OK | Terminate with ProtocolError |
| REGISTER_CID before AUTH_OK | Terminate with ProtocolError |
| Unknown message type | Terminate with ProtocolError |
| Invalid payload encoding | Terminate with ProtocolError |
| CID mismatch in REGISTER_OK | Terminate with ProtocolError |

---

## 8. Message Flow Summary

### 8.1 TCP-Only Session

```
CONNECT -> TLS -> AUTH -> AUTH_OK -> [DATA, PING, PONG]* -> CLOSE
```

### 8.2 Full UDP Upgrade Session

```
CONNECT -> TLS -> AUTH -> AUTH_OK ->
REGISTER_CID -> REGISTER_OK ->
UPGRADE_PROBE -> UPGRADE_PROBE_ACK ->
UDP_READY -> SWITCH_TO_UDP -> SWITCH_ACK -> SWITCH_OK ->
[DATA, PING, PONG]* on UDP-QSP ->
CLOSE
```

At any point after authentication, either peer may exchange
`FALLBACK_TO_TCP -> FALLBACK_OK` on TCP and make TCP the preferred data path.

### 8.3 Message Types by Transport

| Message | TCP | UDP-QSP |
|---------|-----|---------|
| AUTH | Client -> Server | Never |
| AUTH_OK | Server -> Client | Never |
| AUTH_FAIL | Server -> Client | Never |
| REGISTER_CID | Client -> Server | Never |
| REGISTER_OK | Server -> Client | Never |
| REGISTER_FAIL | Server -> Client | Never |
| UDP_READY | Client -> Server | Never |
| SWITCH_TO_UDP | Server -> Client | Never |
| SWITCH_ACK | Client -> Server | Never |
| SWITCH_OK | Server -> Client | Never |
| FALLBACK_TO_TCP | Both | Never |
| FALLBACK_OK | Both | Never |
| UPGRADE_PROBE | Never | Client -> Server |
| UPGRADE_PROBE_ACK | Never | Server -> Client |
| DATA | Both | Both |
| PING | Both | Both |
| PONG | Both | Both |
| CLOSE | Both | Both |
