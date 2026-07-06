# SLT Architecture Overview

## What is SLT?

SLT is a VPN implementation that multiplexes VPN traffic with standard web traffic on port 443 (443/TCP, 443/UDP). Port 80 is owned by nginx, which serves plain HTTP and redirects to HTTPS. This allows VPN traffic to coexist with normal HTTPS traffic, making it appear as regular web browsing to network observers.

## Why This Approach?

The primary goal is to bypass firewalls and network restrictions that block non-HTTPS traffic. By sharing ports with standard web services:

- VPN traffic is indistinguishable from regular HTTPS traffic to passive observers
- No special firewall rules or port forwarding is required
- The service can run on standard web ports (443) that are rarely blocked
- Non-VPN traffic is forwarded to nginx, allowing the server to host regular websites

## Network Topology

### Public Ports

| Port | Protocol | Owner | Purpose |
|------|----------|-------|---------|
| 80/tcp | TCP | nginx (passthrough) | HTTP, ACME challenges, redirect to HTTPS |
| 443/tcp | TCP | Wrapper | Routes to VPN handler or nginx passthrough |
| 443/udp | UDP | Wrapper | Routes to VPN UDP-QSP handler or nginx QUIC forwarder |

### Internal Ports

| Port | Protocol | Service | Purpose |
|------|----------|---------|---------|
| 127.0.0.1:8080/tcp | TCP | nginx | TLS + HTTP/1.1 and/or HTTP/2 |
| 127.0.0.1:8080/udp | UDP | nginx | HTTP/3 / QUIC |

Internal ports are firewall-blocked from the internet and only accessible to the wrapper process.

### Network Diagram

```
                              INTERNET
                                 |
                                 |
                    +------------+------------+
                    |      Public Ports       |
                    |       :443/tcp          |
                    |       :443/udp          |
                    +------------+------------+
                                 |
                                 v
                    +------------------------+
                    |        Wrapper         |
                    |    (Front Door)        |
                    |                        |
                    |  - Classify traffic    |
                    |  - Route to VPN/nginx  |
                    +----------+-------------+
                               |
              +----------------+----------------+
              |                                 |
              v                                 v
    +------------------+              +------------------+
    |   VPN Handler    |              |      nginx       |
    |                  |              |                  |
    | - TLS terminate  |              | - Serve HTTPS    |
    | - Authenticate   |              | - HTTP/1.1, H2   |
    | - TUN I/O        |              | - HTTP/3 (QUIC)  |
    +--------+---------+              +--------+---------+
             |                                 |
             v                                 v
    +------------------+              +------------------+
    |   TUN Device     |              |   Web Content    |
    |   (tun0)         |              |                  |
    |                  |              |                  |
    | 10.10.0.0/24     |              |                  |
    +--------+---------+              +------------------+
             |
             v
    +------------------+
    |  Private Network |
    |  (via NAT/masq)  |
    +------------------+
```

## Components

### Wrapper (Front Door)

The wrapper is the only process that listens on public ports 443/tcp and 443/udp. It performs traffic classification and routing:

**Responsibilities:**
- Own public sockets on `:443/tcp` and `:443/udp`
- Classify incoming traffic as VPN or regular web traffic
- Route claimed traffic to VPN handlers
- Route unknown traffic to nginx (passthrough for TCP, NAT forwarder for UDP)
- Maintain CID map for UDP-QSP session routing

**Classification Logic:**

For TCP connections, the wrapper inspects the TLS ClientHello `legacy_session_id` field for a 32-byte HMAC token. If valid, the connection is claimed for VPN; otherwise, it is passed through to nginx.

For UDP datagrams:
- QUIC long headers are forwarded to nginx
- QUIC short headers with a known DCID are routed to VPN
- Unknown short headers are forwarded to nginx

### VPN Handler

The VPN handler processes authenticated VPN sessions:

**Responsibilities:**
- Terminate TLS for claimed connections
- Perform client authentication (Ed25519 signature verification)
- Manage session state and transport switching
- Read/write IP packets to/from TUN device
- Handle UDP-QSP registration and key management

### TUN Device

A Layer 3 virtual network interface that carries VPN traffic. SLT does not create or configure it — it attaches to an existing, preconfigured interface and validates on startup that the interface is up and that its MTU and overlay address match the `[tun]` config. Creating and addressing the interface (which needs `CAP_NET_ADMIN`) is a separate setup step, so the running SLT process needs no `CAP_NET_ADMIN`.

**Server side:**
- Created and configured by an external setup step (persistent interface)
- Assigned gateway IP (e.g., 10.10.0.1)
- Receives packets from clients via VPN, writes to TUN
- Reads packets from TUN, sends to appropriate client

**Client side:**
- Created and configured by an external setup step (persistent interface)
- Assigned client VPN IP (e.g., 10.10.0.2)
- Reads outgoing packets from TUN, sends via VPN
- Receives packets from VPN, writes to TUN

### nginx

Standard web server that handles non-VPN traffic:

**Responsibilities:**
- Serve HTTPS content on internal ports
- Handle HTTP/1.1, HTTP/2, and HTTP/3 (QUIC)
- Advertise `Alt-Svc: h3=":443"` for HTTP/3 upgrade
- Unaware of VPN traffic (receives only passed-through connections)

## Traffic Flow

### VPN Client Connection Flow

```
VPN Client                                    Server
   |                                            |
   |  1. TCP connect to :443                    |
   |  + TLS ClientHello with token              |
   |------------------------------------------->|
   |                                            |
   |                    2. Wrapper classifies   |
   |                       as VPN (CLAIM)       |
   |                                            |
   |                    3. VPN handler          |
   |                       terminates TLS       |
   |                                            |
   |  4. AUTH (client_id, signature)            |
   |------------------------------------------->|
   |                                            |
   |  5. AUTH_OK                                |
   |<-------------------------------------------|
   |                                            |
   |  6. DATA (IP packets) over TCP             |
   |<------------------------------------------>|
   |                                            |
   |  7. REGISTER_CID (DCID, UDP-QSP keys)      |
   |------------------------------------------->|
   |                                            |
   |  8. REGISTER_OK                            |
   |<-------------------------------------------|
   |                                            |
   |  9. UDP probing (UPGRADE_PROBE/ACK)        |
   |<------------------------------------------>|
   |                                            |
   |  10. UDP_READY / SWITCH_TO_UDP / SWITCH_ACK|
   |<------------------------------------------>|
   |                                            |
   |  11. DATA over UDP-QSP (active transport)  |
   |<------------------------------------------>|
   |                                            |
```

### Regular Web Client Flow

```
Web Client                                    Server
   |                                            |
   |  1. TCP connect to :443                    |
   |  + TLS ClientHello (no token)              |
   |------------------------------------------->|
   |                                            |
   |                    2. Wrapper classifies   |
   |                       as web (PASS)        |
   |                                            |
   |  3. TLS handshake (passthrough)            |
   |<------------------------------------------>|
   |                                            |
   |  4. HTTP request/response                  |
   |<------------------------------------------>|
   |                                            |
```

```
Web Client                                    Server
   |                                            |
   |  1. QUIC Initial to :443/udp               |
   |------------------------------------------->|
   |                                            |
   |                    2. Wrapper sees         |
   |                       long header (PASS)   |
   |                                            |
   |                    3. Forward via NAT      |
   |                       to nginx :8080       |
   |                                            |
   |  4. QUIC handshake                         |
   |<------------------------------------------>|
   |                                            |
   |  5. HTTP/3 request/response                |
   |<------------------------------------------>|
   |                                            |
```

### How VPN and Web Traffic Coexist

The key insight is that VPN traffic and regular web traffic look identical on the wire:

**TCP (port 443):**
- Both VPN and web clients establish TLS connections
- The only difference is the presence of a valid token in `legacy_session_id`
- Invalid tokens result in passthrough to nginx (behaves like normal web traffic)
- External observers cannot distinguish VPN attempts from regular HTTPS

**UDP (port 443):**
- QUIC long headers (handshakes) always go to nginx
- Only QUIC short headers with registered DCIDs go to VPN
- VPN clients first establish a real QUIC connection to nginx to obtain a DCID
- The DCID is then reused for UDP-QSP after registration over the TCP control channel

This design ensures:
1. VPN traffic is cryptographically indistinguishable from regular HTTPS
2. Failed VPN attempts look like normal web browsing
3. The server can host regular websites alongside VPN service
4. No special network configuration is required on the client side

## Crate Structure

SLT is organized into five Rust crates:

| Crate | Purpose |
|-------|---------|
| `slt-core` | Protocol definitions, crypto primitives, configuration types, packet parsing |
| `slt-server` | VPN server with TCP/UDP front doors, client authentication, session management, TUN integration |
| `slt-client` | VPN client with connection establishment, authentication, transport switching |
| `slt-cli` | WireGuard-style management CLI (`slt` binary) for project init, key/cert generation, and client management |
| `slt-tools` | CLI utilities for generating TLS/QUIC ClientHello packets |

## Key Protocol Concepts

- **Traffic Classification**: Server inspects TLS ClientHello `legacy_session_id` for a 32-byte HMAC token
- **UDP-QSP**: QUIC-shaped packet protection for VPN data using QUIC short headers with AES-128-GCM AEAD
- **Frame Format**: All VPN messages use `TYPE(1) + LEN(4) + PAYLOAD` framing
- **Transport Preference**: UDP-QSP preferred for data, with TCP fallback
- **Authentication**: Ed25519 signature over TLS-exported challenge
