# SLT

A VPN that multiplexes with web traffic on ports 80/443.

## What is SLT?

SLT is a VPN implementation that multiplexes VPN traffic with standard web traffic on ports 80/443. This allows VPN traffic to coexist with normal HTTPS traffic on the same server, making it harder to distinguish VPN usage from regular web browsing.

## Key Features

- **Traffic Multiplexing** - VPN and web traffic share ports 80/443 seamlessly
- **UDP-QSP** - High-performance data transport using QUIC-shaped packet protection
- **WireGuard-like UX** - Simple CLI tools for key generation and configuration
- **nginx Coexistence** - Non-VPN traffic is forwarded to nginx for regular web hosting

## Status

**Early-stage development** - APIs and configuration may change. Not ready for production use.

## Documentation

Full documentation is available in [docs/README.md](docs/README.md).

## Quick Start

```bash
# Generate server keys
slt-cli generate-keys --server

# Generate server certificates
slt-cli generate-certs

# Start the server (requires root for TUN)
sudo slt-server

# Generate client keys and connect
slt-cli generate-keys --client
slt-client
```

See the [User Guide](docs/user-guide/README.md) for detailed setup instructions.

## License

Not yet specified.
