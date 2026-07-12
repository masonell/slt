# Configuration Reference

This document provides a comprehensive reference for configuring SLT server and client. All configuration files use [TOML format](https://toml.io/en/).

## Table of Contents

1. [Server Configuration](#server-configuration)
2. [Client Configuration](#client-configuration)
3. [Field Types and Formats](#field-types-and-formats)
4. [Common Configuration Patterns](#common-configuration-patterns)

---

## Server Configuration

The server configuration (`ServerConfig`) defines how the SLT VPN server operates, including network listeners, TLS credentials, client allowlist, and timing parameters.

### Structure Overview

These snippets are schematic and use ellipses as placeholders; they are not
complete configurations. Use the canonical examples linked below for files that
parse as written.

```toml
# Server configuration (server.toml)
server_secret = { hex = "..." }  # 32-byte hex object
udp_nat_max_entries = 1024
session_queue_size = 1024
max_auth_inflight = 128
tcp_connection_cap = 1024

[network]
listen_tcp = "0.0.0.0:443"
listen_udp = "0.0.0.0:443"
nginx_tcp_upstream = "127.0.0.1:8080"
nginx_udp_upstream = "127.0.0.1:8080"

[tls]
tls_cert = { pem = "..." }      # { pem = "..." } or { file = "path" }
tls_key = { pem = "..." }       # { pem = "..." } or { file = "path" }

[tun]
tun_name = "tun0"
tun_mtu = 1186
tun_ipv4 = "10.10.0.1"
tun_prefix = 24

[timing]
ping_min = "10s"
ping_max = "30s"
auth_timeout = "10s"
tcp_write_timeout = "10s"
udp_liveness_timeout = "90s"
idle_timeout = "5m"
metrics_interval = "5m"
tcp_classification_timeout = "60s"

[[clients]]
client_id = "..."
pubkey_ed25519 = "..."
assigned_ipv4 = "10.10.0.2"
enabled = true
```

### Field Reference

#### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `server_secret` | secret object | Yes | Pre-shared secret for ClientHello classification. Used to generate/verify the HMAC token in TLS `legacy_session_id`. |
| `network` | [ServerNetworkConfig](#network-section) | Yes | Network listener and upstream configuration. |
| `tls` | [ServerTlsConfig](#tls-section) | Yes | TLS certificate and key configuration. |
| `tun` | [TunConfig](#tun-section) | Yes | TUN interface settings. |
| `timing` | [ServerTimingConfig](#timing-section) | No | Timing parameters with sensible defaults. |
| `udp_nat_max_entries` | integer | No | Maximum UDP NAT peers for nginx forwarding. Default: `1024`. Must be > 0. |
| `session_queue_size` | integer | No | Bounded queue size for per-session event channels. Default: `1024`. Must be > 0. |
| `max_auth_inflight` | integer | No | Maximum VPN-claimed TCP connections concurrently in TLS/AUTH. Default: `128`. Must be > 0. |
| `tcp_connection_cap` | integer | No | Maximum classifying and nginx-proxied TCP connections held by the front door. Default: `512 * detected CPU count` on the host loading the config. Must be > 0. |
| `clients` | array of [ServerClient](#clients-section) | Yes | List of authorized clients. |

`tcp_connection_cap` should be sized relative to nginx's `worker_connections`
and timeout configuration. Connections classified as pass-through stay in this
front-door cap until nginx closes them through settings such as
`client_header_timeout`, `client_body_timeout`, `send_timeout`, and
`keepalive_timeout`.

#### Network Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `listen_tcp` | socket address | Yes | TCP listener for TLS-wrapped VPN traffic. Typically `0.0.0.0:443`. |
| `listen_udp` | socket address | Yes | UDP listener for QUIC-based VPN traffic. Typically `0.0.0.0:443`. |
| `nginx_tcp_upstream` | socket address | Yes | Nginx TCP upstream for pass-through (non-VPN) traffic. |
| `nginx_udp_upstream` | socket address | Yes | Nginx UDP upstream for pass-through (non-VPN) traffic. |

#### TLS Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tls_cert` | [TlsMaterial](#tlsmaterial-type) | Yes | TLS certificate chain (PEM) for server authentication. |
| `tls_key` | [TlsMaterial](#tlsmaterial-type) | Yes | TLS private key (PEM) for server authentication. |

#### TUN Section

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `tun_name` | string | No | `tun0` | TUN interface name. Must not be empty and must already exist on the host. |
| `tun_ipv4` | IPv4 address | Yes | - | Server overlay gateway address expected on the interface. |
| `tun_prefix` | integer | No | `24` | Overlay subnet prefix length. Must be 1-32. Client IPs must fall within this subnet. |
| `tun_mtu` | integer | No | `1186` | TUN interface MTU. Must be 1-1406 and match the preconfigured interface and every authenticating client. |

#### Timing Section

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `ping_min` | duration | No | `10s` | Minimum ping interval. Must be >= 1ms and <= `ping_max`. |
| `ping_max` | duration | No | `30s` | Maximum ping interval. Must be >= 1ms. |
| `auth_timeout` | duration | No | `10s` | Server TLS and authentication deadline starting when TCP classification returns `CLAIM`. Must be > 0 and <= 1 hour. |
| `tcp_write_timeout` | duration | No | `10s` | Maximum time for one established-session TCP message write. Must be > 0 and <= 1 hour. |
| `udp_liveness_timeout` | duration | No | `90s` | Maximum time without authenticated UDP-QSP ingress before the server falls back to live TCP. Must be > 0 and <= 1 hour. |
| `idle_timeout` | duration | No | `5m` | Maximum time without an accepted inbound message on either live transport. Must be > 0 and <= 1 hour. |
| `metrics_interval` | duration | No | `5m` | Metrics snapshot logging interval. Must be > 0 and <= 1 hour. |
| `tcp_classification_timeout` | duration | No | `60s` | Maximum time to wait for enough TCP `ClientHello` bytes to classify. Must be > 0 and <= 1 hour. |

#### Clients Section

Each entry in the `[[clients]]` array has the following fields:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `client_id` | 16-byte hex string | Yes | - | Stable client identifier. |
| `pubkey_ed25519` | 32-byte hex string | Yes | - | Ed25519 public key for authentication. |
| `assigned_ipv4` | IPv4 address | Yes | - | VPN IP address assigned to this client. |
| `enabled` | boolean | No | `true` | If `false`, client is disabled without removing the entry. |

### Server Configuration Example

The canonical [server configuration example](../examples/server.toml) is
sanitized, complete, and parsed and validated by the test suite.

---

## Client Configuration

The client configuration (`ClientConfig`) defines how the SLT VPN client connects to the server, including identity credentials, TLS settings, and connection parameters.

### Structure Overview

```toml
# Client configuration (client.toml)
enable_upgrade = true
require_udp = false

[network]
hostname = "vpn.example.com"
port = 443
ip = "203.0.113.50"  # Optional: bypass DNS

[tls]
tls_ca = { pem = "..." }       # { pem = "..." } or { file = "path" }
quic_ca = { pem = "..." }      # Optional: for QUIC discovery

[identity]
client_id = "..."
shared_secret = { hex = "..." }
assigned_ipv4 = "10.10.0.2"
privkey_ed25519 = { hex = "..." }

[tun]
tun_name = "tun0"
tun_mtu = 1186
tun_ipv4 = "10.10.0.2"
tun_prefix = 24

[transport.udp_qsp]
cipher = "auto"

[timing]
ping_min = "10s"
ping_max = "30s"
auth_timeout = "10s"
tcp_write_timeout = "10s"
register_timeout = "10s"
quic_discovery_timeout = "15s"
udp_liveness_timeout = "90s"
idle_timeout = "5m"
metrics_interval = "5m"
reconnect_min = "200ms"
reconnect_max = "5s"
```

### Field Reference

#### Network Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | Yes | Server hostname used for SNI and certificate verification. Must not be empty. |
| `port` | integer | Yes | Server port to connect to. Typically `443`. |
| `ip` | IP address | No | Optional IP override for connecting without DNS lookup. |

#### TLS Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tls_ca` | [TlsMaterial](#tlsmaterial-type) | Yes | CA certificate for verifying the SLT server certificate (TCP). |
| `quic_ca` | [TlsMaterial](#tlsmaterial-type) | No | Optional CA for QUIC discovery. If omitted, uses host CA locations available to the Rust/BoringSSL verifier. Set this when nginx uses a custom CA; for Let's Encrypt, omit the field to use public trust anchors. |

#### Identity Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | 16-byte hex string | Yes | Stable client identifier assigned by server admin. |
| `shared_secret` | secret object | Yes | Pre-shared secret for ClientHello classification. Must match server's `server_secret`. |
| `assigned_ipv4` | IPv4 address | Yes | VPN IP address assigned to this client. |
| `privkey_ed25519` | secret object | Yes | Ed25519 private key for authentication. Corresponds to `pubkey_ed25519` in server config. |

#### TUN Section

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `tun_name` | string | No | `tun0` | TUN interface name. Must not be empty and must already exist on the host. |
| `tun_ipv4` | IPv4 address | Yes | - | Local overlay address expected on the interface. Must equal `assigned_ipv4`. |
| `tun_prefix` | integer | No | `24` | Overlay subnet prefix length. Must be 1-32. Client IPs must fall within this subnet. |
| `tun_mtu` | integer | No | `1186` | TUN interface MTU. Must be 1-1406 and match the preconfigured interface and server MTU. |

#### Transport Options

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enable_upgrade` | boolean | No | `true` | Enable QUIC DCID discovery and UDP-QSP upgrade. |
| `require_udp` | boolean | No | `false` | Require UDP upgrade success; if upgrade times out, fail the session. Requires `enable_upgrade = true`. |

#### UDP-QSP Transport Section

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cipher` | string | No | `auto` | UDP-QSP packet protection cipher. Use `auto`, `aes-128-gcm`, or `chacha20-poly1305`. |

`auto` selects AES-128-GCM when native AES-GCM acceleration is available and
ChaCha20-Poly1305 otherwise.

#### Timing Section

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `ping_min` | duration | No | `10s` | Minimum ping interval. Must be >= 1ms and <= `ping_max`. |
| `ping_max` | duration | No | `30s` | Maximum ping interval. Must be >= 1ms. |
| `auth_timeout` | duration | No | `10s` | Timeout for authentication handshake. Must be > 0 and <= 1 hour. |
| `tcp_write_timeout` | duration | No | `10s` | Maximum time for one TCP message write during authentication, registration, upgrade, or an established session. Must be > 0 and <= 1 hour. |
| `register_timeout` | duration | No | `10s` | Timeout for UDP-QSP registration. Must be > 0 and <= 1 hour. |
| `quic_discovery_timeout` | duration | No | `15s` | Timeout for the full QUIC DCID discovery attempt. Must be > 0 and <= 1 hour. |
| `udp_liveness_timeout` | duration | No | `90s` | Maximum time without authenticated UDP-QSP ingress before the client falls back to live TCP. Must be > 0 and <= 1 hour. |
| `idle_timeout` | duration | No | `5m` | Maximum time without an accepted inbound message on either live transport. Must be > 0 and <= 1 hour. |
| `metrics_interval` | duration | No | `5m` | Metrics snapshot logging interval. Must be > 0 and <= 1 hour. |
| `reconnect_min` | duration | No | `200ms` | Minimum reconnect backoff delay. Must be >= 1ms and <= `reconnect_max`. |
| `reconnect_max` | duration | No | `5s` | Maximum reconnect backoff delay. Must be >= 1ms. |

### Client Configuration Example

The canonical [client configuration example](../examples/client.toml) is
sanitized, complete, and parsed and validated by the test suite. Its root
scalars precede every TOML table so they cannot be scoped under `[tun]`.

---

## Field Types and Formats

### Hex Strings

Binary fields (keys, IDs, secrets) are encoded as lowercase hexadecimal strings in TOML configuration files. The `0x` prefix is optional.

| Type | Length | Hex String Length | Example |
|------|--------|-------------------|---------|
| `ClientId` | 16 bytes | 32 characters | `"0102030405060708090a0b0c0d0e0f10"` |
| `SharedSecret` | 32 bytes | 64 characters | `"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"` |
| `PubKeyEd25519` | 32 bytes | 64 characters | `"1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"` |
| `PrivKeyEd25519` | 32 bytes | 64 characters | `"3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50"` |

Both lowercase and uppercase hex characters are accepted during parsing. Whitespace around the hex string is trimmed.

```toml
# These are all equivalent:
client_id = "0102030405060708090a0b0c0d0e0f10"
client_id = "0102030405060708090A0B0C0D0E0F10"  # Mixed case
client_id = "0x0102030405060708090a0b0c0d0e0f10"  # With prefix
client_id = "  0102030405060708090a0b0c0d0e0f10  "  # With whitespace
```

### TlsMaterial Type

TLS material (certificates and keys) can be provided in two ways:

**1. Inline PEM object:**

```toml
tls_cert = { pem = "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkq...\n-----END CERTIFICATE-----" }
```

**2. File reference:**

```toml
tls_cert = { file = "/etc/slt/server.crt" }
tls_key = { file = "/etc/slt/server.key" }
```

For server configurations, using file references is recommended to keep certificates and keys in separate files.

### Secret Values

Secret fields (`server_secret`, `shared_secret`, `privkey_ed25519`) can be provided as hex or loaded from files:

```toml
# Inline hex
shared_secret = { hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

# Load from file containing raw bytes or hex text
shared_secret = { file = "/etc/slt/secret.key" }
privkey_ed25519 = { file = "/etc/slt/client.key" }
```

The file can contain either:
- Raw binary bytes (exactly N bytes)
- Hex-encoded text (with optional trailing newline)

### Duration Format

Duration fields use human-readable format via `humantime-serde`. Supported units:

| Unit | Meaning | Example |
|------|---------|---------|
| `ms` | milliseconds | `"200ms"` |
| `s` | seconds | `"10s"` |
| `m` | minutes | `"5m"` |
| `h` | hours | `"1h"` |

Compound durations are supported:

```toml
idle_timeout = "5m30s"  # 5 minutes 30 seconds
reconnect_min = "1s200ms"  # 1 second 200 milliseconds
```

### IP Address Format

IPv4 addresses use standard dotted-decimal notation:

```toml
assigned_ipv4 = "10.10.0.2"
```

Socket addresses combine IP and port:

```toml
listen_tcp = "0.0.0.0:443"
nginx_tcp_upstream = "127.0.0.1:8080"
```

### TUN MTU Constraints

The UDP-QSP packet budget uses 46 bytes for the current worst-case wrapper: a
25-byte short header (1-byte flags, 20-byte DCID, and 4-byte packet number), a
16-byte AEAD tag, and the 5-byte SLT frame header. The outer-header budget is
48 bytes for UDP over a base IPv6 header (40-byte IPv6 plus 8-byte UDP). It does
not reserve space for IPv6 extension headers or additional encapsulation.

Three values are useful when choosing the inner TUN MTU:

- **1186 bytes** is the conservative default. The complete UDP-QSP packet fits
  an outer IPv6 PMTU of 1280: `1186 + 46 + 48 = 1280`.
- **1280 bytes** is a valid explicit inner MTU, but it requires an outer IPv6
  PMTU of at least 1374: `1280 + 46 + 48 = 1374`.
- **1406 bytes** is the supported maximum and requires a known outer IPv6 PMTU
  of at least 1500: `1406 + 46 + 48 = 1500`.

Use a smaller inner MTU when the path has a smaller PMTU or extra outer headers.
`slt init` writes `tun_mtu = 1186`, while omitting the field uses the same
default. `slt add-client` copies the server's configured MTU into the generated
client configuration. Each preconfigured interface must match its local
configuration, and authentication rejects a client/server MTU mismatch (see
[Server Setup](../deployment/server-setup.md) and [Client
Setup](../deployment/client-setup.md)).

---

## Common Configuration Patterns

### Full Tunnel Setup

Route all traffic through the VPN:

The following excerpts highlight the relevant fields and are intentionally
incomplete. Start with the canonical [server](../examples/server.toml) and
[client](../examples/client.toml) examples, then replace their sample material.

**Server:**

```toml
server_secret = { hex = "your-32-byte-secret-in-hex-here-0123456789abcdef" }
max_auth_inflight = 128

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
tun_mtu = 1186
tun_ipv4 = "10.10.0.1"
tun_prefix = 24

# Default timing is fine for most cases

[[clients]]
client_id = "client1-id-in-hex-16-bytes"
pubkey_ed25519 = "client1-pubkey-in-hex-32-bytes"
assigned_ipv4 = "10.10.0.2"
```

**Client:**

```toml
enable_upgrade = true
require_udp = false

[network]
hostname = "vpn.example.com"
port = 443

[tls]
tls_ca = { file = "/etc/slt/ca.crt" }

[identity]
client_id = "client1-id-in-hex-16-bytes"
shared_secret = { hex = "your-32-byte-secret-in-hex-here-0123456789abcdef" }
assigned_ipv4 = "10.10.0.2"
privkey_ed25519 = { file = "/etc/slt/client.key" }

[tun]
tun_name = "tun0"
tun_mtu = 1186
tun_ipv4 = "10.10.0.2"
tun_prefix = 24
```

### Split Tunnel Setup

For split tunneling, you would configure routing rules outside of SLT (using system routing tables). The SLT configuration remains the same; only the client's routing table determines which traffic goes through the VPN.

### Multiple Clients

Add multiple `[[clients]]` entries in the server configuration:

```toml
# First client
[[clients]]
client_id = "0102030405060708090a0b0c0d0e0f10"
pubkey_ed25519 = "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"
assigned_ipv4 = "10.10.0.2"
enabled = true

# Second client
[[clients]]
client_id = "02030405060708091011121314151617"
pubkey_ed25519 = "3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50"
assigned_ipv4 = "10.10.0.3"
enabled = true

# Third client (temporarily disabled)
[[clients]]
client_id = "03040506070809101112131415161718"
pubkey_ed25519 = "5152535455565758596061626364656667686970717273747576777879808182"
assigned_ipv4 = "10.10.0.4"
enabled = false
```

### High-Performance Configuration

For environments requiring faster reconnection and lower latency:

```toml
[timing]
ping_min = "5s"
ping_max = "15s"
auth_timeout = "5s"
tcp_write_timeout = "5s"
register_timeout = "5s"
quic_discovery_timeout = "8s"
udp_liveness_timeout = "45s"
idle_timeout = "2m"
metrics_interval = "5m"
reconnect_min = "100ms"
reconnect_max = "2s"
```

### Conservative/Reliable Configuration

For unstable networks requiring more tolerance:

```toml
[timing]
ping_min = "15s"
ping_max = "45s"
auth_timeout = "30s"
tcp_write_timeout = "30s"
register_timeout = "30s"
quic_discovery_timeout = "45s"
udp_liveness_timeout = "2m"
idle_timeout = "10m"
metrics_interval = "5m"
reconnect_min = "500ms"
reconnect_max = "30s"
```

---

## Validation

Both server and client configurations are validated when loaded. Common validation errors include:

| Error | Cause | Fix |
|-------|-------|-----|
| `EmptyHostname` | Client `hostname` is empty | Provide a valid hostname |
| `EmptyTunName` | `tun_name` is empty | Set a TUN interface name |
| `InvalidTunMtu` | MTU is 0 or > 1406 | Use MTU between 1-1406 |
| `InvalidTunPrefix` | `tun_prefix` is outside 1-32 | Use a prefix between 1-32 |
| `ClientTunIpMismatch` | Client `tun_ipv4` differs from `assigned_ipv4` | Set client `tun_ipv4` equal to its `assigned_ipv4` |
| `ClientOutsideTunSubnet` | Server client IP is outside `tun_ipv4`/`tun_prefix` | Assign client IPs inside the TUN subnet |
| `ClientUsesTunAddress` | Server client IP equals the server's `tun_ipv4` | Assign a different client IP |
| `InvalidPingInterval` | `ping_min` > `ping_max` | Ensure `ping_min` <= `ping_max` |
| `InvalidReconnectInterval` | `reconnect_min` > `reconnect_max` | Ensure `reconnect_min` <= `reconnect_max` |
| `IntervalTooSmall` | A ping or reconnect interval is below 1 millisecond | Use an interval of at least 1ms |
| `ZeroTimeout` | Any timeout is 0 | Use positive duration |
| `TimeoutTooLarge` | Any timeout > 1 hour | Use duration <= 1 hour |
| `RequireUdpNeedsUpgrade` | `require_udp = true` but `enable_upgrade = false` | Set `enable_upgrade = true` |
| `ZeroSessionQueueSize` | Server `session_queue_size` is 0 | Use positive integer |
| `ZeroMaxAuthInflight` | Server `max_auth_inflight` is 0 | Use positive integer |
| `ZeroTcpConnectionCap` | Server `tcp_connection_cap` is 0 | Use positive integer |
| `ZeroUdpNatMaxEntries` | Server `udp_nat_max_entries` is 0 | Use positive integer |
