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
  |  4. TLS handshake completes             |
  |<=======================================>|
  |                                         |
  |  5. AUTH message                        |
  |    - client_id (16 bytes)               |
  |    - assigned_ipv4 (4 bytes)            |
  |    - challenge (32 bytes, TLS exporter) |
  |    - signature (64 bytes, Ed25519)      |
  |---------------------------------------->|
  |                                         |  6. Validate AUTH
  |                                         |     - client_id exists and enabled
  |                                         |     - IPv4 matches config
  |                                         |     - challenge matches exporter
  |                                         |     - signature verifies
  |                                         |
  |  7. AUTH_OK or AUTH_FAIL                |
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
3. Client generates UDP-QSP keys and packet number state

### 2.2 Upgrade Sequence

```
Client                                    Server
  |                                         |
  |  [Prerequisites: TCP authenticated,    |
  |   QUIC discovery complete]             |
  |                                         |
  |  1. REGISTER_CID over TCP               |
  |    - client_to_server_cid (20 bytes)    |
  |    - server_to_client_cid (0-20 bytes)  |
  |    - cipher (AES-128-GCM)               |
  |    - hp_tx, hp_rx (header protection)   |
  |    - aead_tx, aead_rx (payload keys)    |
  |    - iv_tx, iv_rx (nonce bases)         |
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
  |  4. UPGRADE_PROBE (UDP)                  |
  |    - upgrade_id (8 bytes)               |
  |    - nonce (8 bytes)                    |
  |---------------------------------------->|
  |                                         |  5. Validate probe
  |                                         |     - CID lookup succeeds
  |                                         |     - AEAD decryption passes
  |                                         |
  |  6. UPGRADE_PROBE_ACK (UDP)              |
  |<----------------------------------------|
  |                                         |
  |  [UDP path validated]                   |
  |                                         |
  |  7. UDP_READY (TCP)                      |
  |    - upgrade_id                         |
  |---------------------------------------->|
  |                                         |
  |  8. SWITCH_TO_UDP (TCP)                  |
  |    - upgrade_id                         |
  |<----------------------------------------|
  |                                         |
  |  9. SWITCH_ACK (TCP)                     |
  |    - upgrade_id                         |
  |---------------------------------------->|
  |                                         |
  |  10. PING barrier (TCP)                  |
  |    - barrier_nonce                      |
  |---------------------------------------->|
  |                                         |
  |  11. PONG barrier (TCP)                  |
  |    - barrier_nonce                      |
  |<----------------------------------------|
  |                                         |
  |  [UDP-QSP now ACTIVE transport]         |
  |                                         |
```

### 2.3 Upgrade State Machine (Client Side)

```
                    +------------------+
                    |     Disabled     |  (config.disable_udp = true)
                    +------------------+
                             |
                             | enable_udp
                             v
+-------------------+  discovery  +-------------------+
|      Idle         |<------------|  NeedDiscovery    |
+-------------------+             +-------------------+
        |                                ^
        | register_ok                    | discovery_fail
        v                                |
+-------------------+  register_fail  +-------------------+
|  Active (UDP-QSP) |-------------->|     Pending       |
+-------------------+             +-------------------+
        |                                ^
        | upgrade_start                  | register_retry
        v                                |
+-------------------+             +------+------+
|    Upgrading      |             |             |
+-------------------+             |             |
        |                         |             |
        | probe_acked + ready     |             |
        | + switch_to_udp         |             |
        v                         |             |
+-------------------+             |             |
| AwaitingSwitch    |             |             |
| Commit            |             |             |
+-------------------+             |             |
        |                         |             |
        | barrier_pong            |             |
        v                         |             |
+-------------------+             |             |
|  Active (UDP-QSP) |<------------+-------------+
+-------------------+
        |
        | upgrade_timeout / failure
        v
+-------------------+
| TcpOnlyBlockedUdp |  (cooldown before retry)
+-------------------+
```

### 2.4 Upgrade State Machine (Server Side)

```
                    +------------------+
                    |      Idle        |
                    +------------------+
                             |
                             | upgrade_probe received
                             v
                    +------------------+
                    |  probe_seen=true |
                    +------------------+
                             |
                             | udp_ready received
                             v
                    +------------------+
                    | ready_seen=true  |
                    +------------------+
                             |
                             | both conditions met
                             v
                    +------------------+
                    | switch_to_udp    |
                    | sent             |
                    +------------------+
                             |
                             | switch_ack received
                             v
                    +------------------+
                    | ActiveTransport  |
                    | = UdpQsp         |
                    +------------------+
```

### 2.5 Barrier PING/PONG Purpose

The barrier PING/PONG exchange after `SWITCH_ACK` ensures:
- All in-flight TCP DATA messages have been processed by the server
- No data loss during the transport switch window
- Client only commits to UDP after confirming TCP is fully drained

The client MUST validate the barrier nonce matches before switching `active_transport` to UDP-QSP.

### 2.6 Upgrade Probing Details

- Maximum probe attempts: 8 per upgrade cycle
- Probe backoff: exponential with jitter
- Probe timeout triggers `TcpOnlyBlockedUdp` state with cooldown
- New probe with different `upgrade_id` supersedes previous attempt

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
| UDP_COMMITTING | SWITCH_ACK sent, awaiting barrier PONG | TCP |
| UDP_ACTIVE | UDP-QSP fully committed | UDP-QSP |
| TCP_ONLY_BLOCKED | UDP upgrade failed, cooldown active | TCP |

### 3.2 State Diagram

```
                              +-----------------+
                              |   CONNECTING    |
                              +-----------------+
                                       |
                                       | TCP connected + TLS handshake
                                       v
                              +-----------------+
                              | AUTHENTICATING  |
                              +-----------------+
                                       |
                         +-------------+-------------+
                         |                           |
                    AUTH_OK                     AUTH_FAIL
                         |                           |
                         v                           v
                +-----------------+          +-----------------+
                |  AUTHENTICATED  |          |   TERMINATED    |
                |  (TCP active)   |          +-----------------+
                +-----------------+
                         |
            +------------+------------+
            |                         |
      UDP disabled           UDP upgrade enabled
            |                         |
            |                         v
            |               +-----------------+
            |               | UDP_REGISTERING |
            |               +-----------------+
            |                         |
            |              +----------+----------+
            |              |                     |
            |         REGISTER_OK          REGISTER_FAIL
            |              |                     |
            |              v                     v
            |      +-----------------+   (retry or TCP-only)
            |      |   UDP_PROBING   |
            |      +-----------------+
            |              |
            |       +------+------+
            |       |             |
            |  probe_acked   probe_timeout
            |       |             |
            |       v             v
            | +-----------------+  +-------------------+
            | |   UDP_READY     |  | TCP_ONLY_BLOCKED  |
            | +-----------------+  +-------------------+
            |       |                      |
            |       v                      | cooldown
            | +-----------------+          |
            | | UDP_COMMITTING  |<---------+
            | +-----------------+
            |       |
            |       | barrier_pong
            |       v
            | +-----------------+
            +>|   UDP_ACTIVE    |
              +-----------------+
                       |
                       | UDP failure / timeout
                       v
              +-----------------+
              | TCP fallback    |
              | (if TCP alive)  |
              +-----------------+
```

### 3.3 Valid Messages by State

| State | Valid Client Messages | Valid Server Messages |
|-------|----------------------|----------------------|
| AUTHENTICATING | AUTH, PING, CLOSE | AUTH_OK, AUTH_FAIL, PING, PONG, CLOSE |
| AUTHENTICATED | All except UPGRADE_* | All except SWITCH_TO_UDP |
| UDP_REGISTERING | (waiting for response) | REGISTER_OK, REGISTER_FAIL |
| UDP_PROBING | UPGRADE_PROBE, DATA, PING, PONG | UPGRADE_PROBE_ACK, DATA, PING, PONG |
| UDP_READY | (waiting for response) | SWITCH_TO_UDP |
| UDP_COMMITTING | SWITCH_ACK, PING | PONG |
| UDP_ACTIVE | DATA, PING, PONG, CLOSE | DATA, PING, PONG, CLOSE |

---

## 4. Active Transport Rules

### 4.1 Single Active Transport

Only one transport may be active for data at any time:

```
active_transport in { TCP, UDP_QSP }
```

- `TCP`: Initial state after authentication
- `UDP_QSP`: After successful UDP upgrade commit

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

If UDP-QSP fails (idle timeout, AEAD errors, packet loss), the client may fall back to TCP:

```
on udp_failure:
    if tcp_alive:
        active_transport = TCP
        // Attempt UDP upgrade again after cooldown
        udp_upgrade_state = TcpOnlyBlockedUdp
    else:
        // Session terminates
        send_close(ProtocolError)
```

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

Sessions terminate if no inbound traffic is received on the active transport:

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
| auth_timeout | 30s | Time for client to send valid AUTH |
| idle_timeout | 300s | Max idle time before disconnect |
| ping_min | 10s | Minimum keepalive interval |
| ping_max | 30s | Maximum keepalive interval |
| register_timeout | 30s | Time for REGISTER_OK/FAIL response |

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

### 7.2 TCP Errors

| Error | Action |
|-------|--------|
| TCP read returns 0 | If UDP active, continue on UDP; else terminate |
| TCP write failure | Terminate session |
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
UDP_READY -> SWITCH_TO_UDP -> SWITCH_ACK ->
PING(barrier) -> PONG(barrier) ->
[DATA, PING, PONG]* on UDP-QSP ->
CLOSE
```

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
| UPGRADE_PROBE | Never | Client -> Server |
| UPGRADE_PROBE_ACK | Never | Server -> Client |
| DATA | Both | Both |
| PING | Both | Both |
| PONG | Both | Both |
| CLOSE | Both | Both |
