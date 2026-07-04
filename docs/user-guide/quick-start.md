# Quick Start Guide

This guide will help you get SLT VPN up and running quickly. By the end, you'll have a working VPN connection between a server and client.

## Prerequisites

Before starting, ensure SLT is installed on both your server and client machines. See the [Installation](installation.md) guide for build instructions.

You'll need:
- A server with a public IP address and a domain name
- A client machine (your laptop, workstation, etc.)
- Root/admin privileges on both machines for the one-time TUN device setup (the client then runs unprivileged)

## Step 1: Initialize Server Configuration

On your server, create a configuration directory and initialize the server setup. The `slt init` command generates certificates and creates a basic configuration.

```bash
# Create a directory for SLT configuration
sudo mkdir -p /etc/slt

# Initialize server configuration
sudo slt init --config-dir /etc/slt --domain vpn.example.com
```

Replace `vpn.example.com` with your actual domain name. This command creates:
- `/etc/slt/server.toml` - Server configuration file
- `/etc/slt/ca.pem` - Certificate Authority certificate
- `/etc/slt/server.pem` - Server certificate
- `/etc/slt/server-key.pem` - Server private key (restricted permissions)

By default, certificates are referenced by file path. Use `--inline-certs` to embed certificates directly in the config file:

```bash
# Embed certificates in config (useful for single-file deployment)
sudo slt init --config-dir /etc/slt --domain vpn.example.com --inline-certs
```

## Step 2: Add a Client

Add a client configuration to the server. This generates client credentials and outputs a client config file.

```bash
# Add a client with IP address 10.10.0.2
sudo slt add-client --config /etc/slt/server.toml --output-dir /etc/slt/clients --ip 10.10.0.2
```

This command:
- Generates a unique client ID
- Creates an Ed25519 keypair for the client
- Adds the client to the server configuration
- Writes a client config file to `/etc/slt/clients/client-<ID>.toml`

The output will show the client ID and config file path:

```
Added client: a1b2c3d4e5f67890a1b2c3d4e5f67890
  Assigned IP: 10.10.0.2
  Config file: /etc/slt/clients/client-a1b2c3d4e5f67890a1b2c3d4e5f67890.toml
```

## Step 3: Copy Client Configuration

Transfer the client configuration file to your client machine. Use a secure method like SCP:

```bash
# On the server, display the client config (for manual transfer)
sudo cat /etc/slt/clients/client-a1b2c3d4e5f67890a1b2c3d4e5f67890.toml

# Or copy directly with SCP (run from your client machine)
scp user@server-machine:/etc/slt/clients/client-a1b2c3d4e5f67890a1b2c3d4e5f67890.toml ~/slt-client.toml
```

On the client machine, save this file securely (e.g., `~/slt-client.toml`).

## Step 4: Start the Server

SLT attaches to a preconfigured TUN device. Configure it from `server.toml`'s `[tun]` section, and enable IPv4 forwarding plus NAT for tunneled traffic (one-time; root):

```bash
sudo slt net up --config /etc/slt/server.toml --ipv4-forward --masquerade
```

Then start the SLT server (root or `CAP_NET_BIND_SERVICE` is needed to bind port 443):

```bash
sudo slt-server --config /etc/slt/server.toml
```

You should see log output indicating the server is running:

```
INFO server starting: listen_tcp=0.0.0.0:443 listen_udp=0.0.0.0:443 tun_name="tun0" tun_mtu=1406
```

The server is now listening on port 443 for both TCP and UDP connections.

## Step 5: Start the Client

On your client machine, preconfigure the TUN device from the client config's `[tun]` section, owned by your user (one-time; root):

```bash
sudo slt net up --config ~/slt-client.toml --user "$USER"
```

Then start the SLT client (no root needed — the interface is owned by your user):

```bash
slt-client --config ~/slt-client.toml
```

You should see log output indicating a successful connection:

```
INFO client starting: hostname="vpn.example.com" port=443 tun_name="tun0" tun_mtu=1406
INFO session established: client_id=a1b2c3d4e5f67890a1b2c3d4e5f67890
```

## Step 6: Verify Connectivity

Test the VPN connection by pinging through the tunnel:

```bash
# From the client, ping the server's VPN IP (the server's TUN address)
ping 10.10.0.1

# Or ping the client's own VPN IP to verify the TUN interface is working
ping 10.10.0.2
```

You can also verify the TUN interface exists:

```bash
# Check TUN interface on client
ip addr show tun0

# Check TUN interface on server
ip addr show tun0
```

## Understanding the Configuration

### Server Configuration (`server.toml`)

The server configuration file contains:

```toml
# Pre-shared secret for client classification
server_secret = "hex-encoded-32-byte-secret"

[network]
listen_tcp = "0.0.0.0:443"        # TCP listener address
listen_udp = "0.0.0.0:443"        # UDP listener address
nginx_tcp_upstream = "127.0.0.1:8080"  # Forward non-VPN TCP here
nginx_udp_upstream = "127.0.0.1:8080"  # Forward non-VPN UDP here

[tls]
tls_cert = { file = "server.pem" }     # Server certificate
tls_key = { file = "server-key.pem" }  # Server private key

[tun]
tun_name = "tun0"        # TUN interface name
tun_mtu = 1406           # MTU (init uses 1406, default is 1280)
tun_ipv4 = "10.10.0.1"   # server overlay gateway address
tun_prefix = 24          # overlay subnet prefix length

[timing]
ping_min = "10s"
ping_max = "30s"
auth_timeout = "10s"
idle_timeout = "5m"
metrics_interval = "5m"

# Client entries are added by `slt add-client`
[[clients]]
client_id = "a1b2c3d4e5f67890a1b2c3d4e5f67890"
pubkey_ed25519 = "hex-encoded-32-byte-public-key"
assigned_ipv4 = "10.10.0.2"
enabled = true
```

### Client Configuration (`client-*.toml`)

The client configuration file contains:

```toml
[network]
hostname = "vpn.example.com"  # Server domain
port = 443

[tls]
tls_ca = '''-----BEGIN CERTIFICATE-----
... embedded server certificate for pinning ...
-----END CERTIFICATE-----'''

[identity]
client_id = "a1b2c3d4e5f67890a1b2c3d4e5f67890"
shared_secret = "hex-encoded-32-byte-secret"
assigned_ipv4 = "10.10.0.2"
privkey_ed25519 = "hex-encoded-32-byte-private-key"

[tun]
tun_name = "tun0"
tun_mtu = 1406          # copied from the server by `slt add-client`
tun_ipv4 = "10.10.0.2"  # equals assigned_ipv4
tun_prefix = 24

# Transport options (top-level)
enable_upgrade = true   # Enable UDP-QSP upgrade
require_udp = false     # Don't fail if UDP upgrade fails

[timing]
ping_min = "10s"
ping_max = "30s"
metrics_interval = "5m"
```

## Common Issues

### Permission Denied

If the server or client cannot attach to the TUN interface, the interface does not exist yet or your user cannot open it. Preconfigure it from the config's `[tun]` section (one-time; root):

```bash
# Client: configure the interface owned by your user
sudo slt net up --config ~/slt-client.toml --user "$USER"

# Server: also enable forwarding and NAT for tunneled traffic
sudo slt net up --config /etc/slt/server.toml --ipv4-forward --masquerade
```

The server still needs root (or `CAP_NET_BIND_SERVICE`) to bind port 443; the client needs none once the interface is owned by its user.

### Connection Timeout

If the client cannot connect:
1. Verify the server domain resolves correctly
2. Check that port 443 (TCP and UDP) is accessible through any firewalls
3. Ensure the server is running and listening

### Certificate Errors

If you see certificate verification errors:
1. Ensure the client config contains the correct server certificate
2. Verify the domain in the config matches the server certificate's SAN

## Next Steps

- [Configuration](configuration.md) - Detailed configuration options
- Set up multiple clients by running `slt add-client` with different IP addresses
- Configure your firewall to allow traffic through the VPN tunnel

## Manual Configuration (Advanced)

If you prefer to create configurations manually without the CLI:

### Generate Certificates

```bash
# Create directory
mkdir -p /etc/slt

# Generate CA and server certificates
slt generate-certs --config-dir /etc/slt --domain vpn.example.com
```

### Generate Client Keys

```bash
# Generate Ed25519 keypair
slt generate-keys
# Output:
# privkey: <hex-encoded-private-key>
# pubkey:  <hex-encoded-public-key>
```

### Validate Configuration

```bash
# Validate a server or client config file
slt validate /etc/slt/server.toml
slt validate ~/slt-client.toml
```

Then manually create the server and client TOML files using the structures shown above.
