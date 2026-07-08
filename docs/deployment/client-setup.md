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
- **Root or sudo access** - Required once to preconfigure the TUN device (address, MTU, routes); the running client needs none of it
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
shared_secret = { hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
assigned_ipv4 = "10.10.0.2"
privkey_ed25519 = { file = "/etc/slt/client.key" }

[tun]
tun_name = "tun0"
tun_mtu = 1406          # copied from the server's tun_mtu by slt add-client
tun_ipv4 = "10.10.0.2"
tun_prefix = 24

enable_upgrade = true
```

See [Configuration Reference](../user-guide/configuration.md) for all options.

---

## TUN Device Setup

### Preconfiguring the TUN Device

SLT attaches to an existing, preconfigured TUN device — it does not create, address, or bring up the interface itself. The interface must already exist with a name, overlay address, prefix, and MTU that match the `[tun]` section of your `client.toml`. On startup SLT opens the named interface, enables GRO/GSO offload, and validates that the interface is running and that its MTU and configured IPv4 address match the config; it refuses to start if anything differs.

Creating and addressing the interface requires `CAP_NET_ADMIN` (or root), but this is a one-time setup step — the running client process needs none of it (see [Running the Client](#running-the-client)).

The client's overlay address is its `assigned_ipv4` (from `[identity]`), and `tun_ipv4` in `[tun]` must equal it. Create and configure a persistent interface owned by the user that will run SLT (here `slt`) from the `[tun]` section of `client.toml`:

```bash
# Create and configure tun0 from client.toml's [tun], owned by the slt user
sudo slt net up --config /etc/slt/client.toml --user slt --group slt
```

`slt net up` reads `tun_name`, `tun_ipv4`/`tun_prefix`, and `tun_mtu` straight from the config, so the interface always matches `[tun]`. To remove the interface completely (for example when uninstalling), run `sudo slt net down --config /etc/slt/client.toml`; normal client restarts keep the persistent interface in place. Verify before starting the client:

```bash
ip -brief addr show tun0          # expect: tun0  UP  10.10.0.2/24
ip link show tun0 | grep mtu      # expect: mtu 1406
```

> **Tip:** A persistent interface survives a client restart, so it only needs to be created once. Run `slt net up` from a provisioning step or the service's `ExecStartPre` so the interface is ready before the client starts — SLT simply attaches on each start.

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

### Routing

With the interface preconfigured and up, direct traffic through it according to your chosen mode — see [Routing Configuration](#routing-configuration).

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

# The interface is already addressed and up from preconfiguration
# (see "Preconfiguring the TUN Device"). The following only adds routes.

# 1. Add a route to the server via your current gateway (before VPN)
CURRENT_GW=$(ip route | grep default | awk '{print $3}')
sudo ip route add ${SERVER_IP}/32 via ${CURRENT_GW}

# 2. Route all other traffic through the VPN
sudo ip route replace default dev ${TUN_DEV}

# 3. Add back the server route (to prevent routing loop)
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

# The interface is already addressed and up from preconfiguration.
# Route specific subnets through VPN:

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
# Adds routes to the preconfigured TUN device (address/MTU/up set separately)

set -e

TUN_DEV="${1:-tun0}"
VPN_IP="${2:-10.10.0.2}"
SERVER_HOST="${3:-vpn.example.com}"
MODE="${4:-split}"  # full or split

# Resolve server IP
SERVER_IP=$(dig +short ${SERVER_HOST} | tail -1)

# Interface is already addressed and up from preconfiguration.

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
# Removes routes from the persistent TUN interface. The interface itself
# is not destroyed (it is preconfigured and reused across restarts).

set -e

TUN_DEV="${1:-tun0}"

# Remove routes (full tunnel restoration)
if ip route show default dev ${TUN_DEV} | grep -q .; then
    # Restore original default route via DHCP or static
    # This depends on your network setup
    dhclient -r eth0 && dhclient eth0 2>/dev/null || true
fi

# Remove routes pointing at the interface (split-tunnel routes, etc.)
ip route flush dev ${TUN_DEV} 2>/dev/null || true

# Restore DNS (if modified)
# systemctl restart systemd-resolved

echo "Routing cleaned up for ${TUN_DEV}"
```

---

## Running the Client

### Direct Execution

For testing or manual operation. The TUN interface must already be preconfigured and owned by your user (see [Preconfiguring the TUN Device](#preconfiguring-the-tun-device)):

```bash
# Run with configuration file (no root needed once the interface is preconfigured)
slt-client --config /etc/slt/client.toml

# Or with verbose logging
RUST_LOG=debug slt-client --config /etc/slt/client.toml

# Run in background
slt-client --config /etc/slt/client.toml &
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
# Run as an unprivileged user. The TUN interface is preconfigured and owned
# by this user (see "Preconfiguring the TUN Device"); the client binds no
# privileged ports, so it needs no special capabilities.
User=slt
Group=slt

# Environment
Environment=RUST_LOG=info

# Executable. Routes must already be configured on the persistent interface
# (see "Preconfiguring the TUN Device") to keep the client fully unprivileged.
ExecStart=/usr/local/bin/slt-client --config /etc/slt/client.toml

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

> **Note on privileges:** The unit above runs the client fully unprivileged because both the TUN interface *and* its routes are preconfigured. Manipulating routes at runtime (`ip route add`/`del`) still requires `CAP_NET_ADMIN`. If you need routes applied only while the client is connected, use the routing-hook variant below and grant `CAP_NET_ADMIN` (or run as root) so the hook can change routes — the interface itself still comes from preconfiguration.

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

# The TUN interface is preconfigured and already exists. Start the client,
# then apply routes now that the session is up.
/usr/local/bin/slt-client --config ${CONFIG} &
CLIENT_PID=$!

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
# 3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1406 qdisc fq_codel state UNKNOWN ...
#     inet 10.10.0.2/24 scope global tun0
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

**Symptom:** `Permission denied` or `Operation not permitted` when starting the client

**Causes and fixes:**

The client needs no `CAP_NET_ADMIN`. It only needs to open the preconfigured TUN interface (granted by owning it) and `/dev/net/tun`.

```bash
# Confirm the interface exists and is owned by your user (set at preconfiguration)
ip -brief addr show tun0
sudo slt net up --config /etc/slt/client.toml --user slt --group slt   # recreate if missing

# /dev/net/tun must be accessible
ls -la /dev/net/tun
# Should be: crw-rw-rw- (world-readable/writable) — the default on most distros

# The client binds no privileged ports, so no setcap is required.
```

If you see `failed to attach TUN tun0`, the interface does not exist or your user cannot open it — see [TUN Attach Fails](#tun-attach-fails).

### TUN Attach Fails

**Symptom:** The client exits at startup with a TUN attach/validation error.

The client attaches to a preconfigured interface and validates it on startup. Errors mean the interface does not exist, your user cannot open it, or its address/MTU/state does not match the `[tun]` section of `client.toml` (see [Preconfiguring the TUN Device](#preconfiguring-the-tun-device)).

```bash
# Check if the TUN module is loaded
lsmod | grep tun

# Load the TUN module
sudo modprobe tun

# Check if /dev/net/tun exists
ls -la /dev/net/tun
# Create if missing
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 200
sudo chmod 666 /dev/net/tun
```

Match the startup error against the `[tun]` config:

| Symptom in logs | Cause |
|-----------------|-------|
| `failed to attach TUN tun0` | Interface does not exist, or the user cannot open `/dev/net/tun` |
| `TUN tun0 MTU is X, expected Y` | `tun_mtu` differs from the interface MTU |
| `TUN tun0 is not up/running` | Interface was not brought up (run `slt net up`) |
| `TUN tun0 is missing expected IPv4 address …` | Interface lacks the configured `tun_ipv4` (must equal `assigned_ipv4`) |
| `TUN tun0 does not have TCP GSO offload enabled for this fd` | Offload could not be enabled on attach (kernel/TUN driver) |

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

**Solution:** Preconfigure routes on the persistent interface, or use the [Service with Routing Hooks](#service-with-routing-hooks) variant, which re-applies routes via `ExecStartPost` on each start (that variant requires `CAP_NET_ADMIN` for route manipulation):

```bash
# In the routing-hooks systemd service file
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
# The TUN interface is persistent and preconfigured; it is not created or
# destroyed by SLT. Do not delete it.
ip -brief addr show tun0          # should still show the preconfigured address

# Kill any stale processes
sudo pkill -9 slt-client

# Restart the client (it re-attaches to the existing interface)
sudo systemctl restart slt-client
```
