# SLT User Guide

SLT is a VPN implementation that multiplexes VPN traffic with standard web traffic on port 443 (TCP and UDP). Port 80 is left to nginx, which serves plain HTTP and redirects to HTTPS. This allows VPN traffic to coexist with normal HTTPS/HTTP3 traffic on the same server, making it harder to distinguish VPN usage from regular web browsing.

## Documentation

- [Installation](installation.md) - Installing SLT on client and server
- [Quick Start](quick-start.md) - Get up and running quickly
- [Configuration](configuration.md) - Configuration options for client and server
