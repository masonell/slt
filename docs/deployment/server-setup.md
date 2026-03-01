# Server OS Configuration

This guide covers the OS-level configuration required to run an SLT VPN server. It assumes you have already installed the SLT binaries (see [Installation](../user-guide/installation.md)).

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
- **Root or sudo access** - Required for network configuration, TUN device creation, and firewall rules

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

VPN traffic must be forwarded between the TUN interface and the WAN interface. Enable IP forwarding:

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

### TUN Device Requirements

SLT creates and manages the TUN device at runtime. The server binary requires the `CAP_NET_ADMIN` capability or root privileges to create TUN interfaces.

The TUN device configuration is handled by the SLT server process:

- **Interface name**: Configured in `server.toml` (default: `tun0`)
- **MTU**: Configured in `server.toml` (default: 1280, max: 1406)
- **IP assignment**: Handled automatically based on client `assigned_ipv4` addresses

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

server_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[network]
listen_tcp = "0.0.0.0:443"
listen_udp = "0.0.0.0:443"
nginx_tcp_upstream = "127.0.0.1:8443"
nginx_udp_upstream = "127.0.0.1:8443"

[tls]
tls_cert = { file = "/etc/slt/server.crt" }
tls_key = { file = "/etc/slt/server.key" }

[tun]
tun_name = "tun0"
tun_mtu = 1280

[[clients]]
client_id = "0102030405060708090a0b0c0d0e0f10"
pubkey_ed25519 = "client-public-key-in-hex-32-bytes-here"
assigned_ipv4 = "10.10.0.2"
```

See [Configuration Reference](../user-guide/configuration.md) for all options.

---

## NAT/Masquerade Configuration

VPN clients need internet access through the server. Configure NAT/masquerading using nftables.

### Identify Your WAN Interface

```bash
# List network interfaces
ip link show

# Find the interface with your public IP
ip addr show | grep -A2 "inet.*global"
```

Common WAN interface names: `eth0`, `ens3`, `enp1s0`, `ens192`

### nftables Configuration

Create an nftables configuration that masquerades VPN traffic:

```bash
# Create nftables rules file
sudo tee /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f

# Flush existing rules
flush ruleset

# Base table
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established/related connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Allow ICMP (ping)
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Allow SSH (adjust port as needed)
        tcp dport 22 accept

        # Allow SLT public ports
        tcp dport { 80, 443 } accept
        udp dport 443 accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;

        # Allow forwarding for VPN traffic
        iifname "tun0" accept
        oifname "tun0" accept
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}

# NAT table for masquerading
table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;

        # Masquerade VPN traffic going to WAN
        # Replace eth0 with your WAN interface
        ip saddr 10.10.0.0/24 oifname "eth0" masquerade
    }
}
EOF

# Apply the rules
sudo nft -f /etc/nftables.conf

# Enable nftables service
sudo systemctl enable nftables
```

### Manual nftables Commands

If you prefer to add rules manually without a full configuration:

```bash
# Create a table for NAT
sudo nft add table ip nat

# Add masquerade rule (replace eth0 with your WAN interface)
sudo nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; }
sudo nft add rule ip nat postrouting ip saddr 10.10.0.0/24 oifname "eth0" masquerade
```

### Verify NAT Rules

```bash
# List NAT rules
sudo nft list table ip nat

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
| 127.0.0.1:8443/tcp | HTTPS | TLS and HTTP/2 |
| 127.0.0.1:8443/udp | HTTP/3 | QUIC |

### nginx Configuration Example

```nginx
# /etc/nginx/nginx.conf or /etc/nginx/sites-available/default

server {
    listen 127.0.0.1:8443 ssl http2;
    listen 127.0.0.1:8443 quic reuseport;

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
ss -tlnp | grep 8443

# Check UDP listener
ss -ulnp | grep 8443
```

---

## Running the Server

### Direct Execution

For testing or manual operation:

```bash
# Run with configuration file
sudo /usr/local/bin/slt-server --config /etc/slt/server.toml

# Or with verbose logging
RUST_LOG=debug sudo /usr/local/bin/slt-server --config /etc/slt/server.toml
```

### Systemd Service (Recommended)

Create a systemd service for automatic startup and management:

```bash
sudo tee /etc/systemd/system/slt-server.service << 'EOF'
[Unit]
Description=SLT VPN Server
Documentation=https://github.com/your-org/slt
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=notify
User=root
# Or use a dedicated user with capabilities:
# User=slt
# Group=slt
# AmbientCapabilities=CAP_NET_ADMIN

# File limits for many connections
LimitNOFILE=65536

# Environment
Environment=RUST_LOG=info

# Executable
ExecStart=/usr/local/bin/slt-server --config /etc/slt/server.toml
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run /var/log/slt
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Create log directory (if using file logging)
sudo mkdir -p /var/log/slt

# Reload systemd
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable slt-server
sudo systemctl start slt-server

# Check status
sudo systemctl status slt-server
```

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

The nftables configuration above provides basic firewall rules. Key points:

1. **Block internal ports** - Ports 8443 (nginx internal) must not be accessible from the internet
2. **Allow only necessary public ports** - 80/tcp, 443/tcp, 443/udp
3. **Restrict SSH** - Consider changing the default SSH port or using key-only authentication

### Running as Non-Root

For better security, run SLT as a dedicated user with specific capabilities:

```bash
# Create slt user
sudo useradd -r -s /usr/sbin/nologin -M slt

# Set capabilities on the binary (allows TUN creation without full root)
sudo setcap cap_net_admin+ep /usr/local/bin/slt-server

# Set ownership of config directory
sudo chown -R slt:slt /etc/slt

# Update systemd service (uncomment User/Group lines)
sudo systemctl daemon-reload
sudo systemctl restart slt-server
```

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

```bash
# Check if TUN module is loaded
lsmod | grep tun

# Load TUN module if missing
sudo modprobe tun

# Verify TUN device exists (after starting server)
ip link show tun0
ip addr show tun0
```

### NAT Not Working

```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward

# List NAT rules
sudo nft list table ip nat

# Monitor NAT connections
sudo conntrack -L | grep 10.10.0
```

### Port Binding Issues

```bash
# Check what's using port 443
sudo ss -tlnp | grep :443
sudo ss -ulnp | grep :443

# Ensure nginx is NOT listening on public 443
# nginx should only listen on 127.0.0.1:8443
```

### Client Cannot Connect

1. Verify server is running: `sudo systemctl status slt-server`
2. Check firewall allows 443/tcp and 443/udp
3. Verify DNS resolves to correct IP: `dig vpn.example.com`
4. Check server logs: `sudo journalctl -u slt-server -f`
