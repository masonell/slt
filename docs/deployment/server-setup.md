# Server OS Configuration

This guide covers the OS-level configuration required to run an SLT VPN server. It assumes you have already installed the SLT binaries (see [Installation](../user-guide/installation.md)).

For detailed nginx configuration, see [nginx Integration](nginx-integration.md). For client setup, see [Client Setup](client-setup.md).

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Configuration](#system-configuration)
3. [Network Setup](#network-setup)
4. [NAT/Masquerade Configuration](#natmasquerade-configuration)
5. [nginx Configuration](#nginx-configuration)
6. [Running the Server](#running-the-server)
7. [Security Considerations](#security-considerations)

---

## Prerequisites

Before setting up the SLT server, ensure you have:

### Server Requirements

- **Server with a public IP address** - A VPS or dedicated server with a static public IPv4 address
- **Domain name** - A domain (e.g., `vpn.example.com`) with DNS A record pointing to your server's IP
- **Root or sudo access** - Required once for TUN device preconfiguration, NAT/firewall rules, and binding port 443 on the server

### Port Availability

SLT requires the following public ports:

| Port | Protocol | Purpose |
|------|----------|---------|
| 443/tcp | TLS | VPN over TCP and nginx HTTPS passthrough |
| 443/udp | QUIC | VPN over UDP-QSP and nginx HTTP/3 passthrough |
| 80/tcp | HTTP | ACME challenges and HTTP redirect (handled by nginx) |

**Important**: Port forwarding is NOT required. SLT listens directly on public ports.

---

## System Configuration

### Enable IP Forwarding

VPN traffic must be forwarded between the TUN interface and the WAN interface.
The recommended systemd setup below runs `slt net up --ipv4-forward`, which
sets `net.ipv4.ip_forward=1` during setup. If you are not using the shipped
setup unit, enable forwarding yourself:

```bash
# Check current value
cat /proc/sys/net/ipv4/ip_forward

# Enable temporarily (until reboot)
sudo sysctl -w net.ipv4.ip_forward=1

# Enable permanently
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-slt.conf

# Apply all sysctl changes
sudo sysctl -p /etc/sysctl.d/99-slt.conf
```

### File Limits (Optional)

If you expect many concurrent connections, you may need to increase file descriptor limits:

```bash
# Check current limits
ulimit -n

# Create a limits configuration file
sudo tee /etc/security/limits.d/slt.conf << 'EOF'
slt             soft    nofile          65536
slt             hard    nofile          65536
EOF
```

For systemd services (recommended), configure limits in the service unit file instead (see [Running the Server](#running-the-server)).

---

## Network Setup

### TUN Device Preconfiguration

SLT attaches to an existing, preconfigured TUN device — it does not create, address, or bring up the interface itself. The interface must already exist with a name, overlay address, prefix, and MTU that match the `[tun]` section of `server.toml`. On startup SLT opens the named interface, enables GRO/GSO offload, and validates that the interface is running and that its MTU and configured IPv4 address match the config; it refuses to start if anything differs.

Creating and addressing the interface requires `CAP_NET_ADMIN` (or root), but
the running server process does not need it (see [Running as Non-Root](#running-as-non-root)).
Use `slt net` for this privileged setup so TUN name, address, prefix, and MTU
come from the same `[tun]` section the server later validates.

#### Create the Interface

Create the TUN interface owned by the user that will run SLT (here `slt`),
assign the server's overlay gateway address, set the MTU, enable IPv4
forwarding, and install SLT-owned masquerade rules:

```bash
sudo slt net up \
  --config /etc/slt/server.toml \
  --user slt \
  --group slt \
  --ipv4-forward \
  --masquerade
```

Verify before starting SLT:

```bash
ip -brief addr show tun0          # expect: tun0  UP  10.10.0.1/24
ip link show tun0 | grep mtu      # expect: mtu 1406
sudo nft list table inet slt      # expect SLT forward + masquerade rules
```

To tear down the interface and SLT-owned nftables table:

```bash
sudo slt net down --config /etc/slt/server.toml --masquerade
```

> **Tip:** Use the shipped `slt-setup.service` so this privileged setup runs at
> boot and is cleaned up when the server service stops. SLT itself will simply
> attach on each start.

The interface parameters all come from `server.toml`'s `[tun]` section:

- **Interface name**: `tun_name` (default: `tun0`)
- **MTU**: `tun_mtu` (default: 1280, max: 1406)
- **Server overlay address**: `tun_ipv4` (default: `10.10.0.1`) — the gateway address clients reach
- **Subnet prefix**: `tun_prefix` (default: 24); every client `assigned_ipv4` must fall within this subnet and must not equal `tun_ipv4`

### VPN Subnet Selection

Choose a private subnet for VPN clients. Common choices:

| Subnet | Range | Usable IPs |
|--------|-------|------------|
| 10.10.0.0/24 | 10.10.0.1 - 10.10.0.254 | 254 clients |
| 10.100.0.0/24 | 10.100.0.1 - 10.100.0.254 | 254 clients |
| 172.16.0.0/24 | 172.16.0.1 - 172.16.0.254 | 254 clients |
| 192.168.100.0/24 | 192.168.100.1 - 192.168.100.254 | 254 clients |

**Recommendations**:
- Avoid subnets that conflict with your server's local network
- Use `/24` for up to 254 clients; use `/16` for larger deployments
- Reserve the first IP (e.g., `10.10.0.1`) as the gateway/server address

### Server Configuration File

Create the server configuration at `/etc/slt/server.toml`:

```toml
# /etc/slt/server.toml

server_secret = { hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
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
tun_mtu = 1406
tun_ipv4 = "10.10.0.1"
tun_prefix = 24

[[clients]]
client_id = "0102030405060708090a0b0c0d0e0f10"
pubkey_ed25519 = "client-public-key-in-hex-32-bytes-here"
assigned_ipv4 = "10.10.0.2"
```

Set `tcp_connection_cap` with nginx capacity in mind. Pass-through TCP
connections occupy front-door slots until nginx closes them, so nginx timeout
settings such as `client_header_timeout`, `client_body_timeout`, `send_timeout`,
and `keepalive_timeout` should remain bounded for the deployment.

See [Configuration Reference](../user-guide/configuration.md) for all options.

---

## NAT/Masquerade Configuration

VPN clients need internet access through the server. The recommended setup is
to let `slt net up --masquerade` install an SLT-owned nftables table:

```nft
table inet slt {
    chain slt_forward {
        type filter hook forward priority 0; policy accept;
        iifname "tun0" accept
        oifname "tun0" accept
    }
    chain slt_postrouting {
        type nat hook postrouting priority 100; policy accept;
        ip saddr 10.10.0.0/24 masquerade
    }
}
```

The interface name and source subnet are derived from `/etc/slt/server.toml`'s
`[tun]` section. `slt net down --masquerade` removes this table.

If the host already runs its own nftables firewall with a **drop** forward
policy, also allow the SLT tunnel interface there. Separate base chains do not
override each other's verdicts.

### Manual nftables Alternative

If you do not use `slt net --masquerade`, add equivalent rules yourself:

```bash
sudo nft add table inet slt
sudo nft add chain inet slt slt_forward { type filter hook forward priority 0 \; policy accept \; }
sudo nft add rule inet slt slt_forward iifname "tun0" accept
sudo nft add rule inet slt slt_forward oifname "tun0" accept
sudo nft add chain inet slt slt_postrouting { type nat hook postrouting priority 100 \; policy accept \; }
sudo nft add rule inet slt slt_postrouting ip saddr 10.10.0.0/24 masquerade
```

### Verify NAT Rules

```bash
# List SLT rules
sudo nft list table inet slt

# Monitor NAT connections
sudo conntrack -L 2>/dev/null | grep 10.10.0
```

---

## nginx Configuration

nginx handles non-VPN traffic (regular HTTPS and HTTP/3). It listens on internal ports, and SLT forwards unknown traffic to it.

### Internal Ports

nginx should listen on:

| Port | Protocol | Purpose |
|------|----------|---------|
| 127.0.0.1:8080/tcp | HTTPS | TLS and HTTP/2 |
| 127.0.0.1:8080/udp | HTTP/3 | QUIC |

### nginx Configuration Example

```nginx
# /etc/nginx/nginx.conf or /etc/nginx/sites-available/default

server {
    listen 127.0.0.1:8080 ssl http2;
    listen 127.0.0.1:8080 quic reuseport;

    server_name vpn.example.com;

    # TLS certificate (same as used by SLT)
    ssl_certificate /etc/slt/server.crt;
    ssl_certificate_key /etc/slt/server.key;

    # Advertise HTTP/3 on public port 443
    add_header Alt-Svc 'h3=":443"; ma=86400';

    root /var/www/html;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}

# HTTP on port 80 (public, for ACME and redirects)
server {
    listen 80;
    server_name vpn.example.com;

    # ACME challenge location
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    # Redirect to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}
```

### Install and Enable nginx

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install nginx

# Fedora/RHEL
sudo dnf install nginx

# Copy configuration
sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak
sudo tee /etc/nginx/sites-available/default < /path/to/your/nginx.conf

# Test configuration
sudo nginx -t

# Enable and start
sudo systemctl enable nginx
sudo systemctl start nginx
```

### Verify nginx is Listening

```bash
# Check TCP listener
ss -tlnp | grep 8080

# Check UDP listener
ss -ulnp | grep 8080
```

---

## Running the Server

### Direct Execution

For testing or manual operation (the TUN interface must already be preconfigured — see [TUN Device Preconfiguration](#tun-device-preconfiguration); `sudo` is only needed to bind port 443):

```bash
# Run with configuration file
sudo /usr/local/bin/slt-server --config /etc/slt/server.toml

# Or with verbose logging
RUST_LOG=debug sudo /usr/local/bin/slt-server --config /etc/slt/server.toml
```

### Systemd Service (Recommended)

SLT ships hardened, least-privilege systemd units in
[`deploy/systemd/`](../../deploy/systemd/), and they are the single source of
truth — install the shipped files rather than maintaining a separate
hand-written unit. The server validates the TUN interface on startup (name,
address, MTU, up-state, offload) and queries its addresses via `getifaddrs`,
which requires an `AF_NETLINK` socket, so the unit's settings must match the
daemon's expectations. Shipping both together keeps them aligned:

- `slt-setup.service` — privileged **oneshot** that creates and configures the
  TUN, enables IPv4 forwarding, and installs NAT (`slt net up`), then tears it
  all down on stop.
- `slt-server.service` — the unprivileged daemon (`User=slt`, only
  `CAP_NET_BIND_SERVICE`, no `CAP_NET_ADMIN`).

```bash
# Service account (binary + config already in place — see Prerequisites)
sudo useradd -r -s /usr/sbin/nologin -M -d /nonexistent slt

# Units. slt-setup.service reads TUN name/address/prefix/MTU from
# /etc/slt/server.toml via `slt net`.
sudo install -m 0644 deploy/systemd/slt-setup.service   /etc/systemd/system/
sudo install -m 0644 deploy/systemd/slt-server.service  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now slt-server.service   # pulls in slt-setup via Requires=
sudo systemctl status slt-server
```

[`deploy/systemd/README.md`](../../deploy/systemd/README.md) has the full setup
rationale, prerequisite checks, verification commands, and how to tune
deployment-local values via a drop-in override. TUN/NAT values come from
`/etc/slt/server.toml`'s `[tun]` section.

> If you edit the unit, keep it `Type=simple`, keep `AF_NETLINK` in
> `RestrictAddressFamilies`, and keep the companion setup unit preconfiguring
> the TUN. Dropping `AF_NETLINK` produces `Inspect { name: "tun0" }` with
> `EAFNOSUPPORT`; using `Type=notify` hangs activation; skipping the TUN setup
> fails the attach validation.

### Log Management

With systemd, logs are managed by journald:

```bash
# View recent logs
sudo journalctl -u slt-server -n 100

# Follow logs in real-time
sudo journalctl -u slt-server -f

# Filter by time
sudo journalctl -u slt-server --since "1 hour ago"

# Export logs
sudo journalctl -u slt-server --since today > slt-server.log
```

For persistent log files, configure RUST_LOG and redirect output:

```ini
# In service file
StandardOutput=append:/var/log/slt/server.log
StandardError=append:/var/log/slt/server.log
```

Use logrotate for log rotation:

```bash
sudo tee /etc/logrotate.d/slt << 'EOF'
/var/log/slt/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF
```

---

## Security Considerations

### Firewall Rules

The `slt net --masquerade` rules handle TUN forwarding and source NAT only; keep
your host firewall responsible for public ingress policy. Key points:

1. **Block internal ports** - Ports 8080 (nginx internal) must not be accessible from the internet
2. **Allow only necessary public ports** - 80/tcp, 443/tcp, 443/udp
3. **Restrict SSH** - Consider changing the default SSH port or using key-only authentication

### Running as Non-Root

Because the TUN interface is preconfigured separately (see [TUN Device Preconfiguration](#tun-device-preconfiguration)), the running server needs no `CAP_NET_ADMIN`. The shipped systemd unit grants only `CAP_NET_BIND_SERVICE` via `AmbientCapabilities`, which lets the daemon bind public port 443 without running as root. For a manual setup, the equivalent steps are:

```bash
# Create slt user
sudo useradd -r -s /usr/sbin/nologin -M slt

# Allow binding privileged ports (443) without full root.
# Do not use this together with AmbientCapabilities in systemd; pick one.
sudo setcap cap_net_bind_service+ep /usr/local/bin/slt-server

# Preconfigure the TUN interface owned by the slt user
sudo slt net up --config /etc/slt/server.toml --user slt --group slt --ipv4-forward --masquerade

# Set ownership of the config directory
sudo chown -R slt:slt /etc/slt

# Update systemd service (User=slt, AmbientCapabilities=CAP_NET_BIND_SERVICE)
sudo systemctl daemon-reload
sudo systemctl restart slt-server
```

`setcap cap_net_bind_service+ep` on the binary is the file-based alternative to `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the systemd unit — use one or the other, not both. The `--user slt --group slt` arguments grant the `slt` user permission to open and attach to the preconfigured TUN interface.

### Protecting Secrets

1. **File permissions** - Restrict access to configuration and key files:

   ```bash
   sudo chmod 700 /etc/slt
   sudo chmod 600 /etc/slt/server.toml
   sudo chmod 600 /etc/slt/server.key
   ```

2. **Separate key files** - Store private keys in separate files with restricted access

3. **Avoid logging secrets** - The server does not log secrets, but be cautious with debug logging

### Certificate Management

For production, use Let's Encrypt with certbot:

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx  # Debian/Ubuntu
# sudo dnf install certbot python3-certbot-nginx  # Fedora

# Obtain certificate
sudo certbot certonly --nginx -d vpn.example.com

# Certificates will be at:
# /etc/letsencrypt/live/vpn.example.com/fullchain.pem
# /etc/letsencrypt/live/vpn.example.com/privkey.pem
```

Update your SLT configuration:

```toml
[tls]
tls_cert = { file = "/etc/letsencrypt/live/vpn.example.com/fullchain.pem" }
tls_key = { file = "/etc/letsencrypt/live/vpn.example.com/privkey.pem" }
```

Set up auto-renewal:

```bash
# Test renewal
sudo certbot renew --dry-run

# Certbot adds a systemd timer for automatic renewal
sudo systemctl enable certbot.timer
```

### Keeping Software Updated

```bash
# Update system packages regularly
sudo apt update && sudo apt upgrade  # Debian/Ubuntu
# sudo dnf upgrade  # Fedora

# Rebuild SLT when updating
cd /path/to/slt
git pull
cargo build --release
sudo systemctl restart slt-server
```

---

## Troubleshooting

### TUN Device Issues

SLT attaches to a preconfigured interface and validates it on startup. Most TUN errors mean the interface does not exist yet, or its address/MTU/state does not match the `[tun]` section of `server.toml` (see [TUN Device Preconfiguration](#tun-device-preconfiguration)).

```bash
# Check if the TUN module is loaded
lsmod | grep tun

# Load the TUN module if missing
sudo modprobe tun

# The interface must exist BEFORE starting the server, with a matching
# address, MTU, and UP state
ip -brief addr show tun0          # expect: tun0  UP  10.10.0.1/24
ip link show tun0 | grep mtu      # expect: mtu 1406

# Recreate it from server.toml if needed
sudo slt net up --config /etc/slt/server.toml --user slt --group slt --ipv4-forward --masquerade
```

If the server logs an attach error, match it against the `[tun]` config:

| Symptom in logs | Cause |
|-----------------|-------|
| `failed to attach TUN tun0` | Interface does not exist, or the user cannot open `/dev/net/tun` |
| `TUN tun0 MTU is X, expected Y` | `tun_mtu` differs from the interface MTU |
| `TUN tun0 is not up/running` | Interface was not brought up (`ip link set tun0 up`) |
| `TUN tun0 is missing expected IPv4 address …` | Interface lacks the configured `tun_ipv4` |
| `TUN tun0 does not have TCP GSO offload enabled for this fd` | Offload could not be enabled on attach (kernel/TUN driver) |

### NAT Not Working

```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward

# List SLT NAT/forwarding rules
sudo nft list table inet slt

# Monitor NAT connections
sudo conntrack -L | grep 10.10.0
```

### Port Binding Issues

```bash
# Check what's using port 443
sudo ss -tlnp | grep :443
sudo ss -ulnp | grep :443

# Ensure nginx is NOT listening on public 443
# nginx should only listen on 127.0.0.1:8080
```

### Client Cannot Connect

1. Verify server is running: `sudo systemctl status slt-server`
2. Check firewall allows 443/tcp and 443/udp
3. Verify DNS resolves to correct IP: `dig vpn.example.com`
4. Check server logs: `sudo journalctl -u slt-server -f`
