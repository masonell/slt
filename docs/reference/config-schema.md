# TOML Config Schema Reference

Quick reference for SLT configuration fields. For detailed explanations, see [User Guide: Configuration](../user-guide/configuration.md).

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
| `session_queue_size` | integer | No | `256` | > 0 |
| `max_auth_inflight` | integer | No | `128` | > 0 |
| `tcp_connection_cap` | integer | No | `512 * detected CPU count` | > 0 |
| `clients` | array of tables | Yes | - | At least one entry |

`tcp_connection_cap` is evaluated on the host that deserializes the config when
the field is omitted. Size it against nginx `worker_connections` and nginx's
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
| `tun_name` | string | Yes | - | non-empty; must match an existing interface |
| `tun_mtu` | integer | No | `1280` | 1-1406; must match the interface MTU |
| `tun_ipv4` | IPv4 address | No | `10.10.0.1` | server's local overlay address; must be present on the interface |
| `tun_prefix` | integer | No | `24` | 1-32; overlay subnet prefix length |

### `[timing]` (Server)

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `ping_min` | duration | No | `"10s"` | <= `ping_max` |
| `ping_max` | duration | No | `"30s"` | - |
| `auth_timeout` | duration | No | `"10s"` | > 0, <= 1h |
| `tcp_write_timeout` | duration | No | `"10s"` | > 0, <= 1h |
| `idle_timeout` | duration | No | `"5m"` | > 0, <= 1h |
| `metrics_interval` | duration | No | `"5m"` | > 0, <= 1h |
| `tcp_classification_timeout` | duration | No | `"60s"` | > 0, <= 1h |

### `[transport.udp_qsp]` (Server)

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `allowed_ciphers` | array of strings | No | `["aes-128-gcm", "chacha20-poly1305"]` | non-empty; one or both of `"aes-128-gcm"`, `"chacha20-poly1305"` |

Cipher suites the server accepts from a client `REGISTER_CID`. A suite that is
supported but omitted from this list is rejected with `RegisterFailCode::InvalidCipher`.
The list must not be empty.

### `[[clients]]`

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `client_id` | hex string (16 bytes) | Yes | - | 32 hex chars |
| `pubkey_ed25519` | hex string (32 bytes) | Yes | - | 64 hex chars |
| `assigned_ipv4` | IPv4 address | Yes | - | e.g., `"10.10.0.2"` |
| `enabled` | boolean | No | `true` | - |

### Full Server Example

```toml
server_secret = { hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
udp_nat_max_entries = 1024
session_queue_size = 256
max_auth_inflight = 128
tcp_connection_cap = 1024

[network]
listen_tcp = "0.0.0.0:443"
listen_udp = "0.0.0.0:443"
nginx_tcp_upstream = "127.0.0.1:8080"
nginx_udp_upstream = "127.0.0.1:8080"

[tls]
tls_cert = { file = "/etc/slt/server.crt" }
tls_key = { file = "/etc/slt/server.key" }

[tun]
tun_name = "tun0"
tun_mtu = 1280
tun_ipv4 = "10.10.0.1"
tun_prefix = 24

[timing]
ping_min = "10s"
ping_max = "30s"
auth_timeout = "10s"
tcp_write_timeout = "10s"
idle_timeout = "5m"
metrics_interval = "5m"
tcp_classification_timeout = "60s"

[transport.udp_qsp]
allowed_ciphers = ["aes-128-gcm", "chacha20-poly1305"]

[[clients]]
client_id = "0102030405060708090a0b0c0d0e0f10"
pubkey_ed25519 = "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"
assigned_ipv4 = "10.10.0.2"
enabled = true
```

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
| `enable_upgrade` | boolean | No | `false` | - |
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
| `tun_name` | string | Yes | - | non-empty; must match an existing interface |
| `tun_mtu` | integer | No | `1280` | 1-1406; must match the interface MTU |
| `tun_ipv4` | IPv4 address | No | `10.10.0.1` | must equal this client's `assigned_ipv4` |
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
| `ping_min` | duration | No | `"10s"` | <= `ping_max` |
| `ping_max` | duration | No | `"30s"` | - |
| `auth_timeout` | duration | No | `"10s"` | > 0, <= 1h |
| `tcp_write_timeout` | duration | No | `"10s"` | > 0, <= 1h |
| `register_timeout` | duration | No | `"10s"` | > 0, <= 1h |
| `quic_discovery_timeout` | duration | No | `"15s"` | > 0, <= 1h |
| `idle_timeout` | duration | No | `"5m"` | > 0, <= 1h |
| `metrics_interval` | duration | No | `"5m"` | > 0, <= 1h |
| `reconnect_min` | duration | No | `"200ms"` | <= `reconnect_max` |
| `reconnect_max` | duration | No | `"5s"` | - |

### Full Client Example

```toml
[network]
hostname = "vpn.example.com"
port = 443

[tls]
tls_ca = { file = "/etc/slt/ca.crt" }

[identity]
client_id = "0102030405060708090a0b0c0d0e0f10"
shared_secret = { hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
assigned_ipv4 = "10.10.0.2"
privkey_ed25519 = { file = "/etc/slt/client.key" }

[tun]
tun_name = "tun0"
tun_mtu = 1280
tun_ipv4 = "10.10.0.2"
tun_prefix = 24

enable_upgrade = true
require_udp = false

[transport.udp_qsp]
cipher = "auto"

[timing]
ping_min = "10s"
ping_max = "30s"
auth_timeout = "10s"
tcp_write_timeout = "10s"
register_timeout = "10s"
quic_discovery_timeout = "15s"
idle_timeout = "5m"
metrics_interval = "5m"
reconnect_min = "200ms"
reconnect_max = "5s"
```

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

## Validation Summary

| Error | Trigger |
|-------|---------|
| `EmptyHostname` | Client `hostname` is empty |
| `EmptyTunName` | `tun_name` is empty |
| `InvalidTunMtu` | MTU is 0 or > 1406 |
| `InvalidTunPrefix` | `tun_prefix` is outside 1-32 |
| `ClientTunIpMismatch` | Client `tun_ipv4` differs from its `assigned_ipv4` |
| `ClientOutsideTunSubnet` | Server client `assigned_ipv4` is outside the `tun_ipv4`/`tun_prefix` subnet |
| `ClientUsesTunAddress` | Server client `assigned_ipv4` equals the server's `tun_ipv4` |
| `InvalidPingInterval` | `ping_min` > `ping_max` |
| `InvalidReconnectInterval` | `reconnect_min` > `reconnect_max` |
| `ZeroTimeout` | Any timeout is 0 |
| `TimeoutTooLarge` | Any timeout > 1 hour |
| `RequireUdpNeedsUpgrade` | `require_udp = true` without `enable_upgrade = true` |
| `ZeroSessionQueueSize` | Server `session_queue_size` is 0 |
| `ZeroMaxAuthInflight` | Server `max_auth_inflight` is 0 |
| `ZeroTcpConnectionCap` | Server `tcp_connection_cap` is 0 |
| `ZeroUdpNatMaxEntries` | Server `udp_nat_max_entries` is 0 |
| `EmptyUdpQspAllowedCiphers` | Server `transport.udp_qsp.allowed_ciphers` is empty |
