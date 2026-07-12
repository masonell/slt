# TOML Config Schema Reference

Quick reference for SLT configuration fields. For detailed explanations, see [User Guide: Configuration](../user-guide/configuration.md).

## Parsing Rules

SLT rejects unknown fields at the configuration root and in nested tables and
objects. A misspelled or incorrectly scoped field fails parsing with an error
that names the unknown field instead of being silently ignored.

TOML keys following a table header belong to that table. Put root fields before
the first table header. For example, client-wide transport controls must use
this placement:

```toml
enable_upgrade = true
require_udp = false

[network]
hostname = "vpn.example.com"
port = 443
```

Placing `enable_upgrade` or `require_udp` after `[tun]` makes it a TUN field,
which SLT rejects as unknown. The same placement rule applies to server root
fields such as `tcp_connection_cap`.

## ServerConfig

### Top-Level Fields

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `server_secret` | secret object | Yes | - | `{ hex = "..." }` or `{ file = "..." }` |
| `network` | table | Yes | - | See below |
| `tls` | table | Yes | - | See below |
| `tun` | table | Yes | - | See below |
| `timing` | table | No | defaults apply | See below |
| `transport` | table | No | defaults apply | See below |
| `udp_nat_max_entries` | integer | No | `1024` | > 0 |
| `session_queue_size` | integer | No | `1024` | > 0 |
| `max_auth_inflight` | integer | No | `128` | > 0 |
| `tcp_connection_cap` | integer | No | `512 * detected CPU count` | > 0 |
| `clients` | array of tables | Yes | - | May be empty |

When `tcp_connection_cap` is omitted, it is calculated as `512 * detected CPU
count` on the host that deserializes the config. `slt init` performs that
calculation on the initialization host and serializes the resulting integer
explicitly. A generated config therefore retains that value when copied to
another host; omit or edit the field if the deployment host should use a
different cap. Size it against nginx `worker_connections` and nginx's
connection timeout window for pass-through TCP traffic.

### `[network]`

| Field | Type | Required | Example |
|-------|------|----------|---------|
| `listen_tcp` | socket addr | Yes | `"0.0.0.0:443"` |
| `listen_udp` | socket addr | Yes | `"0.0.0.0:443"` |
| `nginx_tcp_upstream` | socket addr | Yes | `"127.0.0.1:8080"` |
| `nginx_udp_upstream` | socket addr | Yes | `"127.0.0.1:8080"` |

### `[tls]` (Server)

| Field | Type | Required |
|-------|------|----------|
| `tls_cert` | TlsMaterial | Yes |
| `tls_key` | TlsMaterial | Yes |

### `[tun]`

The preconfigured TUN interface SLT attaches to. The interface must already exist
(created and configured with `CAP_NET_ADMIN`/root) with a matching name, address,
prefix, MTU, and UP state before SLT starts. SLT validates the interface on attach
and refuses to start if any field mismatches.

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `tun_name` | string | No | `"tun0"` | non-empty; must match an existing interface |
| `tun_mtu` | integer | No | `1186` | 1-1406; must match the interface MTU and every authenticating client |
| `tun_ipv4` | IPv4 address | Yes | - | server's local overlay address; must be present on the interface |
| `tun_prefix` | integer | No | `24` | 1-32; overlay subnet prefix length |

The `1186` default fits an outer IPv6 PMTU of 1280 with the current UDP-QSP
overhead. An explicit inner MTU of `1280` needs at least 1374 bytes, and the
`1406` maximum needs at least 1500 bytes. These budgets use a base IPv6 header
without extension headers; see [TUN MTU
Constraints](../user-guide/configuration.md#tun-mtu-constraints).

### `[timing]` (Server)

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `ping_min` | duration | No | `"10s"` | >= 1ms, <= `ping_max` |
| `ping_max` | duration | No | `"30s"` | >= 1ms |
| `auth_timeout` | duration | No | `"10s"` | > 0, <= 1h |
| `tcp_write_timeout` | duration | No | `"10s"` | > 0, <= 1h |
| `udp_liveness_timeout` | duration | No | `"90s"` | > 0, <= 1h |
| `idle_timeout` | duration | No | `"5m"` | > 0, <= 1h |
| `metrics_interval` | duration | No | `"5m"` | > 0, <= 1h |
| `tcp_classification_timeout` | duration | No | `"60s"` | > 0, <= 1h |

`tcp_classification_timeout` bounds classification from TCP acceptance. For
connections classified as `CLAIM`, `auth_timeout` then bounds TLS completion and
AUTH as a separate phase.

### `[transport.udp_qsp]` (Server)

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `allowed_ciphers` | array of strings | No | `["aes-128-gcm", "chacha20-poly1305"]` | non-empty; one or both of `"aes-128-gcm"`, `"chacha20-poly1305"` |

Cipher suites the server accepts from a client `REGISTER_CID`. A suite that is
supported but omitted from this list is rejected with `RegisterFailCode::InvalidCipher`.
The list must not be empty.

### `[[clients]]`

The client list may be empty while provisioning a server. In that state, no VPN
clients can authenticate. `slt init` creates the empty list, and `slt add-client`
adds entries to it.

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `client_id` | hex string (16 bytes) | Yes | - | 32 hex chars |
| `pubkey_ed25519` | hex string (32 bytes) | Yes | - | 64 hex chars |
| `assigned_ipv4` | IPv4 address | Yes | - | e.g., `"10.10.0.2"` |
| `enabled` | boolean | No | `true` | - |

### Full Server Example

See the canonical [server configuration](../examples/server.toml). It is a
sanitized, self-contained example parsed and validated by the test suite.

---

## ClientConfig

### Top-Level Fields

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `network` | table | Yes | - | See below |
| `tls` | table | Yes | - | See below |
| `identity` | table | Yes | - | See below |
| `tun` | table | Yes | - | See below |
| `transport` | table | No | defaults apply | See below |
| `enable_upgrade` | boolean | No | `true` | - |
| `require_udp` | boolean | No | `false` | requires `enable_upgrade = true` |
| `timing` | table | No | defaults apply | See below |

### `[network]` (Client)

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `hostname` | string | Yes | - | non-empty |
| `port` | integer | Yes | - | 1-65535 |
| `ip` | IP address | No | `null` | bypasses DNS |

### `[tls]` (Client)

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `tls_ca` | TlsMaterial | Yes | CA for server cert verification |
| `quic_ca` | TlsMaterial | No | Uses host CA locations available to the Rust/BoringSSL verifier if omitted |

### `[identity]`

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `client_id` | hex string (16 bytes) | Yes | 32 hex chars |
| `shared_secret` | secret object | Yes | `{ hex = "..." }` or `{ file = "..." }` |
| `assigned_ipv4` | IPv4 address | Yes | e.g., `"10.10.0.2"` |
| `privkey_ed25519` | secret object | Yes | `{ hex = "..." }` or `{ file = "..." }` |

### `[tun]` (Client)

The preconfigured TUN interface SLT attaches to. The interface must already exist
with a matching name, address, prefix, MTU, and UP state before SLT starts.

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `tun_name` | string | No | `"tun0"` | non-empty; must match an existing interface |
| `tun_mtu` | integer | No | `1186` | 1-1406; must match the interface MTU and server MTU |
| `tun_ipv4` | IPv4 address | Yes | - | must equal this client's `assigned_ipv4` |
| `tun_prefix` | integer | No | `24` | 1-32; overlay subnet prefix length |

### `[transport.udp_qsp]` (Client)

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `cipher` | string | No | `"auto"` | `"auto"`, `"aes-128-gcm"`, or `"chacha20-poly1305"` |

`auto` selects AES-128-GCM when native AES-GCM acceleration is available and
ChaCha20-Poly1305 otherwise.

### `[timing]` (Client)

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `ping_min` | duration | No | `"10s"` | >= 1ms, <= `ping_max` |
| `ping_max` | duration | No | `"30s"` | >= 1ms |
| `auth_timeout` | duration | No | `"10s"` | > 0, <= 1h |
| `tcp_write_timeout` | duration | No | `"10s"` | > 0, <= 1h |
| `register_timeout` | duration | No | `"10s"` | > 0, <= 1h |
| `quic_discovery_timeout` | duration | No | `"15s"` | > 0, <= 1h |
| `udp_liveness_timeout` | duration | No | `"90s"` | > 0, <= 1h |
| `idle_timeout` | duration | No | `"5m"` | > 0, <= 1h |
| `metrics_interval` | duration | No | `"5m"` | > 0, <= 1h |
| `reconnect_min` | duration | No | `"200ms"` | >= 1ms, <= `reconnect_max` |
| `reconnect_max` | duration | No | `"5s"` | >= 1ms |

### Full Client Example

See the canonical [client configuration](../examples/client.toml). Its root
options precede the first TOML table, and the test suite verifies that UDP
upgrade is enabled after parsing.

---

## Field Type Reference

### TlsMaterial

TLS certificates and keys can be specified inline or via file reference.

| Format | Syntax | Example |
|--------|--------|---------|
| Inline PEM | table | `tls_cert = { pem = "-----BEGIN CERTIFICATE-----\n..." }` |
| File reference | table | `tls_cert = { file = "/etc/slt/server.crt" }` |

**Inline PEM syntax:**

```toml
tls_cert = { pem = "-----BEGIN CERTIFICATE-----\nMIIBIjAN...\n-----END CERTIFICATE-----" }
```

**File reference syntax:**

```toml
tls_cert = { file = "/etc/slt/server.crt" }
```

### Duration

Human-readable duration format via `humantime-serde`.

| Unit | Meaning | Example |
|------|---------|---------|
| `ms` | milliseconds | `"200ms"` |
| `s` | seconds | `"10s"` |
| `m` | minutes | `"5m"` |
| `h` | hours | `"1h"` |

**Compound durations:**

```toml
idle_timeout = "5m30s"      # 5 minutes 30 seconds
reconnect_min = "1s200ms"   # 1 second 200 milliseconds
```

### Hex String

Binary fields encoded as lowercase hexadecimal. `0x` prefix is optional; case-insensitive parsing.

| Type | Byte Length | Hex Length | Example |
|------|-------------|------------|---------|
| `ClientId` | 16 | 32 | `"0102030405060708090a0b0c0d0e0f10"` |
| `SharedSecret` | 32 | 64 | `"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"` |
| `PubKeyEd25519` | 32 | 64 | `"1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"` |
| `PrivKeyEd25519` | 32 | 64 | `"3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50"` |

**Private keys also accept file references:**

```toml
privkey_ed25519 = { file = "/etc/slt/client.key" }
```

The file can contain either raw 32 bytes or hex-encoded text (with optional trailing newline).

### IP Address

IPv4 dotted-decimal notation:

```toml
assigned_ipv4 = "10.10.0.2"
```

Socket address (IP:port):

```toml
listen_tcp = "0.0.0.0:443"
nginx_tcp_upstream = "127.0.0.1:8080"
```

---

## Exhaustive Semantic Validation Summary

This table lists every semantic `ConfigError` returned after TOML parsing.
Syntax errors, missing required fields, invalid field types, and unknown fields
are parse errors and occur before these checks.

| Error | Trigger |
|-------|---------|
| `EmptyHostname` | Client `hostname` is empty |
| `ZeroPort` | Client `network.port` or a server listener/upstream port is 0 |
| `EmptyTunName` | `tun_name` is empty |
| `InvalidTunMtu` | MTU is 0 or > 1406 |
| `InvalidTunPrefix` | `tun_prefix` is outside 1-32 |
| `ClientTunIpMismatch` | Client `tun_ipv4` differs from its `assigned_ipv4` |
| `ClientOutsideTunSubnet` | Server client `assigned_ipv4` is outside the `tun_ipv4`/`tun_prefix` subnet |
| `ClientUsesTunAddress` | Server client `assigned_ipv4` equals the server's `tun_ipv4` |
| `DuplicateClientId` | Two server client entries have the same `client_id` |
| `DuplicateAssignedIpv4` | Two server client entries have the same `assigned_ipv4` |
| `InvalidPingInterval` | `ping_min` > `ping_max` |
| `InvalidReconnectInterval` | `reconnect_min` > `reconnect_max` |
| `IntervalTooSmall` | A ping or reconnect interval is below 1 millisecond |
| `ZeroTimeout` | Any timeout is 0 |
| `TimeoutTooLarge` | Any timeout > 1 hour |
| `RequireUdpNeedsUpgrade` | `require_udp = true` without `enable_upgrade = true` |
| `ZeroSessionQueueSize` | Server `session_queue_size` is 0 |
| `ZeroMaxAuthInflight` | Server `max_auth_inflight` is 0 |
| `ZeroTcpConnectionCap` | Server `tcp_connection_cap` is 0 |
| `ZeroUdpNatMaxEntries` | Server `udp_nat_max_entries` is 0 |
| `EmptyUdpQspAllowedCiphers` | Server `transport.udp_qsp.allowed_ciphers` is empty |
