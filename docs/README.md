# SLT Documentation

SLT is a VPN implementation that multiplexes VPN traffic with standard web traffic on port 443 (TCP and UDP). Port 80 is left to nginx, which serves plain HTTP and redirects to HTTPS. This allows VPN traffic to coexist with normal HTTPS/QUIC traffic on the same server, making it harder to distinguish VPN usage from regular web browsing.

## Documentation Index

### User Guide

Installation, configuration, and getting started with SLT.

- [Installation](user-guide/installation.md) - Installing SLT on client and server
- [Quick Start](user-guide/quick-start.md) - Get up and running quickly
- [Configuration](user-guide/configuration.md) - Configuration options for client and server

### Architecture

High-level system design and internal workings of SLT.

- [Overview](architecture/overview.md) - High-level design and traffic flow
- [Traffic Classification](architecture/traffic-classification.md) - How TCP/UDP traffic is classified and routed
- [Transport Security](architecture/transport-security.md) - TLS and UDP-QSP security model

### Protocol

The authoritative protocol specification for SLT.

- [Wire Format](protocol/wire-format.md) - Frame format and message structure
- [Messages](protocol/messages.md) - Payload schemas for all message types
- [UDP-QSP](protocol/udp-qsp.md) - UDP-QSP packet protection
- [Connection Flow](protocol/connection-flow.md) - State machines and connection establishment
- [Key Update](protocol/key-update.md) - Key phase and rekeying

### Deployment

Production deployment guides for servers and clients.

- [Server Setup](deployment/server-setup.md) - Server OS configuration
- [Client Setup](deployment/client-setup.md) - Client configuration
- [nginx Integration](deployment/nginx-integration.md) - nginx configuration for traffic passthrough
- [NixOS Deployment](deployment/nixos.md) - NixOS flake module deployment

### Reference

Quick reference materials for configuration and protocol details.

- [Config Schema](reference/config-schema.md) - Full TOML config schema
- [Message Types](reference/message-types.md) - Message type IDs and error codes

## Reading Guide

### For Users and Operators

If you want to deploy and operate SLT:

1. Start with the [User Guide](user-guide/README.md) for installation and basic configuration
2. Follow the [Deployment](deployment/README.md) guides for production setup
3. Use the [Reference](reference/README.md) section for quick config lookups

### For Developers

If you want to understand or modify the SLT implementation:

1. Start with [Architecture Overview](architecture/overview.md) to understand the system design
2. Read the [Protocol](protocol/README.md) specification for wire format and message details
3. Refer to [Transport Security](architecture/transport-security.md) for the cryptographic model

### For Quick Reference

If you need to look up specific details:

- [Config Schema](reference/config-schema.md) - Full configuration options
- [Message Types](reference/message-types.md) - Protocol message IDs and error codes
- [Wire Format](protocol/wire-format.md) - Frame structure and encoding

## Related Resources

- [Main README](../README.md) - Project overview and repository information
