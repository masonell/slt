# SLT

A VPN that tunnels through HTTPS on port 443 and shares the port with ordinary web traffic, so VPN use is hard to distinguish from normal browsing.

## How it works

SLT runs alongside nginx on the same host, sharing ports 80 and 443:

- **Traffic classification.** The server inspects each TLS ClientHello for an HMAC token in the `legacy_session_id` field. Connections carrying a valid token are VPN sessions; everything else is transparently forwarded to nginx as decoy web traffic.
- **UDP-QSP data transport.** After authenticating over TLS, VPN data moves to UDP/443 using QUIC-shaped short-header packets protected with AES-128-GCM or ChaCha20-Poly1305. This reuses the QUIC wire format for header protection and AEAD framing without running a QUIC handshake.
- **WireGuard-style tooling.** The `slt` CLI handles key and certificate generation, project initialization, client provisioning, config validation, and TUN/network setup.

See [System Design](docs/architecture/overview.md) and the [Protocol Reference](docs/protocol/wire-format.md) for details.

## Status

**Early-stage development.** APIs and configuration may change. Not ready for production use.

## Documentation

- [Quick Start](docs/user-guide/quick-start.md) — bring up a server and client end to end
- [User Guide](docs/user-guide/README.md) — installation, configuration, troubleshooting
- [Deployment](docs/deployment/README.md) — server/client setup and nginx integration
- [Architecture](docs/architecture/README.md) — design, traffic classification, transport security
- [Protocol](docs/protocol/README.md) — wire format, messages, UDP-QSP, connection flow

## Components

| Crate | Role |
|-------|------|
| `slt-core` | Protocol definitions, crypto primitives, configuration, packet parsing |
| `slt-server` | VPN server: TCP/UDP front doors, auth, sessions, TUN integration |
| `slt-client` | VPN client: connection establishment, transport switching, TUN I/O |
| `slt-cli` | The `slt` management CLI: init, keys/certs, client management, validation, `net` setup |
| `slt-tools` | Helper CLIs for generating TLS/QUIC ClientHello packets |

An Android client (Kotlin/Compose) lives under [`android/`](android/).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Third-party code under [`vendor/`](vendor/) retains its upstream licenses; see
the license files inside each vendored package.
