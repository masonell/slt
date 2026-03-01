# Client OS Configuration

This guide covers setting up an SLT VPN client. It assumes you have already installed the SLT binaries (see [Installation](../user-guide/installation.md)) and received a client configuration file from your server administrator.

For server setup instructions, see [Server Setup](server-setup.md).

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [TUN Device Setup](#tun-device-setup)
3. [Routing Configuration](#routing-configuration)
4. [Running the Client](#running-the-client)
5. [Platform-Specific Notes](#platform-specific-notes)
6. [Testing the Connection](#testing-the-connection)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before setting up the SLT client, ensure you have:

### Required Items

- **Client configuration file** - Provided by the server administrator. Contains your client ID, assigned VPN IP, private key, and server connection details.
- **Root or sudo access** - Required for TUN device creation and routing configuration.
- **Linux system** - Primary supported platform (see [Platform-Specific Notes](#platform-specific-notes) for other platforms).

### Network Requirements

| Requirement | Description |
|-------------|-------------|
| Outbound TCP/443 | Required for TLS-wrapped VPN connection |
| Outbound UDP/443 | Required for UDP-QSP transport (optional but recommended) |
| DNS resolution | Must resolve the server hostname |

### Client Configuration File

Your server administrator should provide a configuration file (typically `/etc/slt/client.toml`) containing:

```toml
[network]
hostname = "vpn.example.com"
port = 443

[tls]
tls_ca = { file = "/etc/slt/ca.crt" }

[identity]
client_id = "0102030405060708090a0b0c0d0e0f10"
shared_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
assigned_ipv4 = "10.10.0.2"
privkey_ed25519 = { file = "/etc/slt/client.key" }

[tun]
tun_name = "tun0"
tun_mtu = 1280

enable_upgrade = true
```

See [Configuration Reference](../user-guide/configuration.md) for all options.

---

## TUN Device Setup

### How SLT Creates the TUN Device

SLT automatically creates the TUN device at startup. The client binary requires `CAP_NET_ADMIN` capability or root privileges to create TUN interfaces.

**No manual TUN creation is needed.** When the client starts:

1. SLT opens `/dev/net/tun`
2. Creates the TUN interface with the name specified in `tun_name` (default: `tun0`)
3. Brings the interface up
4. Assigns the configured MTU (default: 1280)

### TUN Module Verification

Ensure the TUN kernel module is loaded:

```bash
# Check if TUN module is loaded
lsmod | grep tun

# Load TUN module if missing (most systems have it built-in)
sudo modprobe tun

# Verify /dev/net/tun exists
ls -la /dev/net/tun
```

### Post-Creation Configuration

After SLT creates the TUN device, you need to configure:

1. **IP address assignment** - Assign the VPN IP from your configuration
2. **Routing rules** - Direct traffic through the tunnel (see [Routing Configuration](#routing-configuration))

This can be done manually or via a script (see [Routing Scripts](#routing-scripts)).

---

## Routing Configuration

SLT supports two routing modes: **full tunnel** and **split tunnel**.

### Full Tunnel (All Traffic Through VPN)

Route all internet traffic through the VPN. This provides maximum privacy and protects all traffic.

#### Manual Setup

```bash
# Variables from your client config
TUN_DEV="tun0"
VPN_IP="10.10.0.2"          # Your assigned_ipv4
SERVER_IP="203.0.113.50"    # Your server's public IP
SERVER_PORT="443"

# 1. Assign the VPN IP to the TUN interface
sudo ip addr add ${VPN_IP}/32 dev ${TUN_DEV}

# 2. Bring up the interface
sudo ip link set ${TUN_DEV} up

# 3. Add a route to the server via your current gateway (before VPN)
CURRENT_GW=$(ip route | grep default | awk '{print $3}')
sudo ip route add ${SERVER_IP}/32 via ${CURRENT_GW}

# 4. Route all other traffic through the VPN
sudo ip route replace default dev ${TUN_DEV}

# 5. Add back the server route (to prevent routing loop)
sudo ip route add ${SERVER_IP}/32 via ${CURRENT_GW}
```

#### Using ip route with metric

Alternative approach using routing metrics:

```bash
# Add VPN route with lower metric (higher priority)
sudo ip route add default dev ${TUN_DEV} metric 100

# Original default route remains but with higher metric
# Traffic will prefer the VPN route
```

### Split Tunnel (Specific Routes Only)

Route only specific traffic through the VPN. Other traffic uses your regular internet connection.

#### Route Specific Subnets

```bash
# Variables
TUN_DEV="tun0"
VPN_IP="10.10.0.2"

# 1. Assign the VPN IP
sudo ip addr add ${VPN_IP}/32 dev ${TUN_DEV}

# 2. Bring up the interface
sudo ip link set ${TUN_DEV} up

# 3. Route specific subnets through VPN
# Example: Route 10.0.0.0/8 (corporate network) through VPN
sudo ip route add 10.0.0.0/8 dev ${TUN_DEV}

# Example: Route specific remote network
sudo ip route add 192.168.100.0/24 dev ${TUN_DEV}
```

#### Route Specific Applications (Linux)

Use network namespaces or cgroups for per-application routing:

```bash
# Example using ip rule (advanced)
# Mark packets from specific user
sudo iptables -t mangle -A OUTPUT -m owner --uid-owner vpnuser -j MARK --set-mark 0x1

# Route marked packets through VPN
sudo ip rule add fwmark 0x1 table 100
sudo ip route add default dev ${TUN_DEV} table 100
```

### DNS Configuration

For full tunnel setups, you may want to use DNS servers accessible through the VPN.

#### Using systemd-resolved

```bash
# Set DNS for the TUN interface
sudo resolvectl dns ${TUN_DEV} 10.10.0.1

# Set search domain (optional)
sudo resolvectl domain ${TUN_DEV} ~corp.example.com

# Route *.corp.example.com queries through VPN DNS
```

#### Using /etc/resolv.conf

```bash
# Backup current resolv.conf
sudo cp /etc/resolv.conf /etc/resolv.conf.bak

# Use VPN DNS (example: use server's VPN IP as DNS)
sudo tee /etc/resolv.conf << 'EOF'
nameserver 10.10.0.1
# Fallback to public DNS if needed
nameserver 8.8.8.8
EOF
```

#### Restore DNS After Disconnect

```bash
# Restore original resolv.conf
sudo mv /etc/resolv.conf.bak /etc/resolv.conf

# Or restart systemd-resolved
sudo systemctl restart systemd-resolved
```

### Routing Scripts

Create scripts to automate routing setup and teardown.

#### Setup Script (`/etc/slt/route-up.sh`)

```bash
#!/bin/bash
# /etc/slt/route-up.sh
# Called after SLT creates the TUN device

set -e

TUN_DEV="${1:-tun0}"
VPN_IP="${2:-10.10.0.2}"
SERVER_HOST="${3:-vpn.example.com}"
MODE="${4:-split}"  # full or split

# Resolve server IP
SERVER_IP=$(dig +short ${SERVER_HOST} | tail -1)

# Assign IP and bring up interface
ip addr add ${VPN_IP}/32 dev ${TUN_DEV}
ip link set ${TUN_DEV} up

if [ "${MODE}" = "full" ]; then
    # Full tunnel setup
    CURRENT_GW=$(ip route | grep default | awk '{print $3}')

    # Route to server via original gateway
    ip route add ${SERVER_IP}/32 via ${CURRENT_GW}

    # Route everything else through VPN
    ip route replace default dev ${TUN_DEV}

    # Ensure server route stays via original gateway
    ip route replace ${SERVER_IP}/32 via ${CURRENT_GW}

    # Configure DNS (optional)
    # resolvectl dns ${TUN_DEV} 10.10.0.1
else
    # Split tunnel: add specific routes
    ip route add 10.0.0.0/8 dev ${TUN_DEV}
fi

echo "Routing configured on ${TUN_DEV}"
```

#### Teardown Script (`/etc/slt/route-down.sh`)

```bash
#!/bin/bash
# /etc/slt/route-down.sh
# Called before SLT destroys the TUN device

set -e

TUN_DEV="${1:-tun0}"

# Remove routes (full tunnel restoration)
if ip route show default dev ${TUN_DEV} | grep -q .; then
    # Restore original default route via DHCP or static
    # This depends on your network setup
    dhclient -r eth0 && dhclient eth0 2>/dev/null || true
fi

# Remove IP from interface
ip addr flush dev ${TUN_DEV} 2>/dev/null || true

# Restore DNS (if modified)
# systemctl restart systemd-resolved

echo "Routing cleaned up for ${TUN_DEV}"
```

---

## Running the Client

### Direct Execution

For testing or manual operation:

```bash
# Run with configuration file
sudo /usr/local/bin/slt-client --config /etc/slt/client.toml

# Or with verbose logging
RUST_LOG=debug sudo /usr/local/bin/slt-client --config /etc/slt/client.toml

# Run in background
sudo /usr/local/bin/slt-client --config /etc/slt/client.toml &
```

### Command Line Options

```bash
slt-client [OPTIONS]

Options:
  -c, --config <FILE>  Path to configuration file [default: /etc/slt/client.toml]
  -v, --verbose        Enable verbose logging
  -h, --help           Print help information
  -V, --version        Print version information
```

### Systemd Service (Recommended)

Create a systemd service for automatic startup and management.

#### Basic Service File

```bash
sudo tee /etc/systemd/system/slt-client.service << 'EOF'
[Unit]
Description=SLT VPN Client
Documentation=https://github.com/your-org/slt
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=root
# Or use a dedicated user with capabilities:
# User=slt
# Group=slt
# AmbientCapabilities=CAP_NET_ADMIN

# Environment
Environment=RUST_LOG=info

# Executable
ExecStart=/usr/local/bin/slt-client --config /etc/slt/client.toml
ExecStartPost=/etc/slt/route-up.sh tun0 10.10.0.2 vpn.example.com split
ExecStopPost=/etc/slt/route-down.sh tun0

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

# Reload systemd
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable slt-client
sudo systemctl start slt-client

# Check status
sudo systemctl status slt-client
```

#### Service with Routing Hooks

For more control, use a wrapper script:

```bash
sudo tee /usr/local/bin/slt-client-wrapper << 'EOF'
#!/bin/bash
set -e

CONFIG="/etc/slt/client.toml"
TUN_DEV=$(grep -Po 'tun_name\s*=\s*"\K[^"]+' ${CONFIG} || echo "tun0")
VPN_IP=$(grep -Po 'assigned_ipv4\s*=\s*"\K[^"]+' ${CONFIG})
SERVER_HOST=$(grep -Po 'hostname\s*=\s*"\K[^"]+' ${CONFIG})

# Start client in background
/usr/local/bin/slt-client --config ${CONFIG} &
CLIENT_PID=$!

# Wait for TUN device to appear
for i in {1..30}; do
    if ip link show ${TUN_DEV} 2>/dev/null; then
        break
    fi
    sleep 0.5
done

# Configure routing
/etc/slt/route-up.sh ${TUN_DEV} ${VPN_IP} ${SERVER_HOST} split

# Handle shutdown
cleanup() {
    /etc/slt/route-down.sh ${TUN_DEV}
    kill ${CLIENT_PID} 2>/dev/null
    wait ${CLIENT_PID} 2>/dev/null
}
trap cleanup EXIT INT TERM

# Wait for client
wait ${CLIENT_PID}
EOF

sudo chmod +x /usr/local/bin/slt-client-wrapper
```

### Log Management

With systemd, logs are managed by journald:

```bash
# View recent logs
sudo journalctl -u slt-client -n 100

# Follow logs in real-time
sudo journalctl -u slt-client -f

# Filter by time
sudo journalctl -u slt-client --since "1 hour ago"

# Export logs
sudo journalctl -u slt-client --since today > slt-client.log
```

---

## Platform-Specific Notes

### Linux (Primary Platform)

Linux is the primary and fully supported platform for SLT clients.

**Requirements:**
- Kernel with TUN module (`tun.ko`)
- glibc 2.17+ or musl 1.2+
- systemd (optional, for service management)

**Tested distributions:**
- Debian 11+
- Ubuntu 20.04+
- Fedora 36+
- RHEL/CentOS 8+
- Arch Linux

### macOS

**Status: Not currently supported**

SLT requires TUN device access which on macOS requires:
- Third-party TUN/TAP drivers (e.g., tuntaposx)
- Or System Extension framework (macOS 10.15+)

Future versions may include macOS support.

### Windows

**Status: Not currently supported**

Windows would require:
- WinTUN driver (used by WireGuard)
- Windows service integration

Future versions may include Windows support.

### Alternative: Running in a VM

For non-Linux platforms, run SLT in a Linux VM:

1. Create a minimal Linux VM (Alpine, Debian minimal)
2. Install SLT in the VM
3. Configure routing on the host to use VM as gateway
4. Or use SSH tunneling from host through VM

---

## Testing the Connection

### Verify TUN Interface

```bash
# Check TUN interface exists
ip link show tun0

# Check IP assignment
ip addr show tun0

# Expected output:
# 3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 qdisc fq_codel state UNKNOWN ...
#     inet 10.10.0.2/32 scope global tun0
```

### Ping Through Tunnel

```bash
# Ping the server's VPN gateway IP
ping -c 3 10.10.0.1

# Ping through VPN to external host
ping -c 3 -I tun0 8.8.8.8

# For full tunnel, regular ping goes through VPN
ping -c 3 8.8.8.8
```

### Check IP Routing

```bash
# Show routing table
ip route show

# For full tunnel, default route should be via tun0:
# default dev tun0 scope link

# For split tunnel, specific routes via tun0:
# 10.0.0.0/8 dev tun0 scope link

# Trace route to verify path
traceroute 8.8.8.8
# Should show VPN server IP as first hop (for full tunnel)
```

### Verify External IP

```bash
# Check your external IP (should be server's IP for full tunnel)
curl -s https://api.ipify.org

# Or
curl -s https://ifconfig.me
```

### Test DNS Resolution

```bash
# Test DNS through VPN (if configured)
nslookup google.com 10.10.0.1

# Or with dig
dig @10.10.0.1 google.com
```

### Check Transport Mode

Monitor client logs to verify transport:

```bash
# Look for transport switch in logs
sudo journalctl -u slt-client -f | grep -i "transport\|udp\|tcp"

# Successful output might show:
# INFO Transport switched from TCP to UDP-QSP
```

---

## Troubleshooting

### Permission Errors

**Symptom:** `Permission denied` or `Operation not permitted`

**Causes and fixes:**

```bash
# Check if running as root or with capabilities
whoami  # Should be root

# If running as non-root user, check capabilities
getcap /usr/local/bin/slt-client
# Should show: cap_net_admin+ep

# Add capability if missing
sudo setcap cap_net_admin+ep /usr/local/bin/slt-client

# Check /dev/net/tun permissions
ls -la /dev/net/tun
# Should be: crw-rw-rw- (or at least readable by your user)
```

### TUN Device Creation Fails

**Symptom:** `Failed to create TUN device`

**Diagnostic steps:**

```bash
# Check if TUN module is loaded
lsmod | grep tun

# Load TUN module
sudo modprobe tun

# Check if /dev/net/tun exists
ls -la /dev/net/tun

# Create if missing
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 200
sudo chmod 666 /dev/net/tun
```

### Connection Failures

**Symptom:** Client cannot connect to server

**Diagnostic steps:**

```bash
# Verify DNS resolution
dig vpn.example.com
nslookup vpn.example.com

# Test TCP connectivity
nc -zv vpn.example.com 443

# Test UDP connectivity
nc -uzv vpn.example.com 443

# Check firewall (client side)
sudo nft list ruleset | grep 443
# Or
sudo iptables -L -n | grep 443

# Check with verbose logging
RUST_LOG=debug sudo /usr/local/bin/slt-client --config /etc/slt/client.toml
```

### Authentication Failures

**Symptom:** `AUTH_FAIL` or connection rejected

**Causes:**
1. Wrong client ID
2. Wrong private key
3. Client disabled on server
4. Clock skew (if applicable)

**Diagnostic steps:**

```bash
# Verify client ID matches server config
grep client_id /etc/slt/client.toml

# Verify private key file exists and is readable
ls -la /etc/slt/client.key

# Check key format (should be 32 bytes hex = 64 chars)
cat /etc/slt/client.key | wc -c
# Should be 64 (or 65 with newline)

# Contact server admin to verify:
# - Client is enabled
# - Public key matches
# - assigned_ipv4 is correct
```

### No Traffic Through Tunnel

**Symptom:** TUN interface exists but traffic doesn't go through VPN

**Diagnostic steps:**

```bash
# Check IP assignment
ip addr show tun0

# Check routing table
ip route show

# For full tunnel, verify default route
ip route show default
# Should show: default dev tun0

# Test with explicit interface
ping -I tun0 10.10.0.1

# Check if server can ping back
# (Run on server)
ping 10.10.0.2
```

### Routes Not Persisting

**Symptom:** Routes disappear after client restart

**Solution:** Use routing scripts or systemd service with `ExecStartPost`:

```bash
# In systemd service file
ExecStartPost=/etc/slt/route-up.sh tun0 10.10.0.2 vpn.example.com split
```

### UDP-QSP Not Working

**Symptom:** Client stays on TCP, never switches to UDP

**Diagnostic steps:**

```bash
# Check if enable_upgrade is set
grep enable_upgrade /etc/slt/client.toml
# Should be: enable_upgrade = true

# Check UDP connectivity
nc -uzv vpn.example.com 443

# Check for UDP blocking
sudo tcpdump -i any udp port 443

# Check server supports UDP-QSP
# Contact admin to verify UDP listener is running
```

### DNS Leaks

**Symptom:** DNS queries bypass VPN

**Fix for full tunnel:**

```bash
# Configure VPN DNS server
sudo resolvectl dns tun0 10.10.0.1

# Or edit /etc/resolv.conf directly
sudo tee /etc/resolv.conf << 'EOF'
nameserver 10.10.0.1
EOF

# Test DNS leak
# Visit: https://dnsleaktest.com
```

### Performance Issues

**Symptom:** Slow throughput or high latency

**Diagnostic steps:**

```bash
# Check MTU settings
ip link show tun0 | grep mtu
# Should match config (default 1280)

# Test for MTU issues
ping -s 1252 -M do 10.10.0.1
# 1252 + 28 (IP/ICMP headers) = 1280 MTU

# Check for packet loss
ping -c 100 10.10.0.1 | tail -2

# Verify using UDP-QSP (faster than TCP)
sudo journalctl -u slt-client | grep -i "transport"
```

### Client Crashes

**Symptom:** Client process terminates unexpectedly

**Diagnostic steps:**

```bash
# Check logs for errors
sudo journalctl -u slt-client -n 200

# Run manually with debug logging
RUST_LOG=debug sudo /usr/local/bin/slt-client --config /etc/slt/client.toml

# Check for core dumps
coredumpctl list
coredumpctl info

# Check system resources
dmesg | grep -i "killed process"
```

### Reconnection Issues

**Symptom:** Client fails to reconnect after disconnect

**Diagnostic steps:**

```bash
# Check if TUN device was cleaned up
ip link show tun0 2>/dev/null && echo "TUN still exists"

# Kill any stale processes
sudo pkill -9 slt-client

# Remove stale TUN device
sudo ip link delete tun0 2>/dev/null

# Restart client
sudo systemctl restart slt-client
```
