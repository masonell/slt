# SLT Architecture

This section covers the high-level system design of SLT, a VPN implementation that multiplexes VPN traffic with standard web traffic on ports 80/443.

## Documentation

- [Overview](overview.md) - High-level design and traffic flow
- [Traffic Classification](traffic-classification.md) - How TCP/UDP traffic is classified and routed
- [Transport Security](transport-security.md) - TLS and UDP-QSP security model
- [Android / Rust Control Boundary](android-control-boundary.md) - Ownership split and UniFFI surface between the Android client and the Rust runtime

## Related Documentation

- [Protocol](../protocol/README.md) - Wire format and message specifications
- [User Guide](../user-guide/README.md) - Installation and configuration

## Audience

This section is intended for developers and implementers who need to understand how SLT works internally.
