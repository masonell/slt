# nginx Integration

This guide covers nginx configuration for traffic passthrough in an SLT deployment. SLT and nginx coexist on the same server, with SLT handling VPN traffic and forwarding non-VPN traffic to nginx.

For complete server setup including NAT and firewall rules, see [Server Setup](server-setup.md).

## Table of Contents

1. [Overview](#overview)
2. [nginx Configuration](#nginx-configuration)
3. [Traffic Flow](#traffic-flow)
4. [Example nginx.conf](#example-nginxconf)
5. [Alt-Svc Header](#alt-svc-header)
6. [Troubleshooting](#troubleshooting)

---

## Overview

### How SLT and nginx Coexist

SLT acts as a traffic multiplexer that owns the public-facing ports and routes traffic based on protocol inspection:

```
                    +-------------------+
                    |    SLT Server     |
                    |                   |
  443/tcp --------> |  TCP Classifier   | --CLAIM--> VPN TCP Handler
                    |                   | --PASS---> TCP Passthrough --> 127.0.0.1:8080/tcp
                    |                   |
  443/udp --------> |  UDP Classifier   | --CLAIM--> VPN UDP-QSP Handler
                    |                   | --PASS---> NAT Forwarder -----> 127.0.0.1:8080/udp
                    +-------------------+
                              |
                              v
                    +-------------------+
                    |      nginx        |
                    | 127.0.0.1:8080    |
                    +-------------------+
```

### Port Assignment

| Public Port | Owner | Purpose |
|-------------|-------|---------|
| 80/tcp | nginx (direct) | HTTP, ACME challenges, redirect to HTTPS |
| 443/tcp | SLT | VPN over TCP and nginx HTTPS passthrough |
| 443/udp | SLT | VPN over UDP-QSP and nginx HTTP/3 passthrough |

| Internal Port | Service | Purpose |
|---------------|---------|---------|
| 127.0.0.1:8080/tcp | nginx | TLS termination, HTTP/1.1 and HTTP/2 |
| 127.0.0.1:8080/udp | nginx | HTTP/3 (QUIC) |

**Important**: nginx must NOT listen on public 443. Only SLT binds to public 443/tcp and 443/udp.

---

## nginx Configuration

### Basic Requirements

nginx needs to:

1. Listen on `127.0.0.1:8080` for HTTPS (TCP)
2. Listen on `127.0.0.1:8080` for HTTP/3 (UDP/QUIC)
3. Use the same TLS certificate as SLT
4. Advertise HTTP/3 availability via Alt-Svc header

### HTTP/1.1 and HTTP/2 (TCP)

Configure nginx to listen on the internal port for TCP traffic:

```nginx
server {
    listen 127.0.0.1:8080 ssl http2;
    server_name vpn.example.com;

    # TLS certificate (same as used by SLT)
    ssl_certificate /etc/slt/server.crt;
    ssl_certificate_key /etc/slt/server.key;

    # Advertise HTTP/3 on public port 443
    add_header Alt-Svc 'h3=":443"; ma=86400' always;

    root /var/www/html;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

### HTTP/3 (QUIC)

For HTTP/3 support, nginx 1.25+ with QUIC module is required:

```nginx
server {
    # HTTP/3 over QUIC
    listen 127.0.0.1:8080 quic reuseport;

    # HTTP/2 fallback
    listen 127.0.0.1:8080 ssl http2;

    server_name vpn.example.com;

    # TLS certificate
    ssl_certificate /etc/slt/server.crt;
    ssl_certificate_key /etc/slt/server.key;

    # Advertise HTTP/3 on public port 443
    add_header Alt-Svc 'h3=":443"; ma=86400' always;

    root /var/www/html;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

### Certificate Paths

Both SLT and nginx must use the same TLS certificate. Common certificate locations:

| Source | Certificate Path | Key Path |
|--------|-----------------|----------|
| Self-signed | `/etc/slt/server.crt` | `/etc/slt/server.key` |
| Let's Encrypt | `/etc/letsencrypt/live/example.com/fullchain.pem` | `/etc/letsencrypt/live/example.com/privkey.pem` |

Update both SLT's `server.toml` and nginx configuration to reference the same files.

---

## Traffic Flow

### TCP Flow: SLT to nginx Passthrough

When a regular HTTPS client connects to port 443/tcp:

1. **Client** initiates TCP connection to `server:443`
2. **SLT** accepts the connection and reads the TLS ClientHello
3. **SLT classifier** inspects `legacy_session_id` for VPN token
4. If no VPN token found (**PASS**):
   - SLT opens a connection to `127.0.0.1:8080`
   - SLT forwards all bytes bidirectionally (pure passthrough)
   - TLS is terminated by nginx, not SLT
5. **nginx** handles the HTTPS request normally
6. **Response** travels back through SLT to the client

```
Client                    SLT                      nginx
  |                        |                         |
  |---- TLS ClientHello -->|                         |
  |                        |--- connect 127.0.0.1:8080 -->|
  |                        |---- forward bytes ----->|
  |                        |<--- response bytes -----|
  |<--- TLS response ------|                         |
```

### UDP Flow: SLT NAT to nginx

When a regular HTTP/3 client sends QUIC packets to port 443/udp:

1. **Client** sends QUIC Initial packet to `server:443`
2. **SLT** receives the datagram and inspects the QUIC header
3. **SLT classifier** checks if it's a long header (QUIC handshake)
4. Long headers are always **PASS** (forwarded to nginx)
5. SLT's NAT forwarder:
   - Creates or reuses a UDP socket to `127.0.0.1:8080`
   - Maps `client_ip:client_port` to a local socket
   - Forwards the datagram to nginx
6. **nginx** handles the QUIC handshake and HTTP/3 request
7. **Response** travels back through SLT's NAT to the client

```
Client                    SLT                      nginx
  |                        |                         |
  |-- QUIC Initial (public:443) -->|                |
  |                        |-- NAT translate -->     |
  |                        |-- forward to 127.0.0.1:8080 -->|
  |                        |                         |
  |                        |<-- QUIC response -------|
  |<-- NAT translate -------|                        |
```

For established QUIC connections, short-header packets are also forwarded unless the DCID matches a registered VPN client.

---

## Example nginx.conf

### Complete Working Configuration

```nginx
# /etc/nginx/nginx.conf
# nginx configuration for SLT integration

user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript
               application/xml application/xml+rss text/javascript;

    # TLS settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
                ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:
                ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # HTTP/3 settings (nginx 1.25+)
    quic_retry on;
    quic_gso on;

    # Upstream for any backend services (optional)
    upstream backend {
        server 127.0.0.1:3000;
    }

    # ===========================================
    # MAIN HTTPS SERVER (Internal Port 8080)
    # ===========================================
    server {
        # HTTP/3 over QUIC (UDP)
        listen 127.0.0.1:8080 quic reuseport;

        # HTTP/2 and HTTP/1.1 (TCP)
        listen 127.0.0.1:8080 ssl http2;

        server_name vpn.example.com www.vpn.example.com;

        # TLS certificate (same as SLT)
        ssl_certificate /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;

        # Advertise HTTP/3 on public port 443
        # This tells browsers to use H3 on port 443 (not 8080)
        add_header Alt-Svc 'h3=":443"; ma=86400' always;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

        # HSTS (optional, enable after confirming everything works)
        # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        root /var/www/html;
        index index.html index.htm;

        # Static content
        location / {
            try_files $uri $uri/ =404;
        }

        # Health check endpoint (optional)
        location /health {
            access_log off;
            return 200 "OK\n";
            add_header Content-Type text/plain;
        }

        # Proxy to backend service (optional)
        # location /api/ {
        #     proxy_pass http://backend/;
        #     proxy_set_header Host $host;
        #     proxy_set_header X-Real-IP $remote_addr;
        #     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        #     proxy_set_header X-Forwarded-Proto $scheme;
        # }
    }

    # ===========================================
    # HTTP SERVER (Public Port 80)
    # ===========================================
    server {
        listen 80;
        listen [::]:80;
        server_name vpn.example.com www.vpn.example.com;

        # ACME challenge location for Let's Encrypt
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
            allow all;
        }

        # Redirect all other HTTP traffic to HTTPS
        location / {
            return 301 https://$host$request_uri;
        }
    }

    # ===========================================
    # ADDITIONAL SERVER BLOCKS (Optional)
    # ===========================================

    # Example: Serve different content on another domain
    # server {
    #     listen 127.0.0.1:8080 ssl http2;
    #     server_name another.example.com;
    #
    #     ssl_certificate /etc/letsencrypt/live/another.example.com/fullchain.pem;
    #     ssl_certificate_key /etc/letsencrypt/live/another.example.com/privkey.pem;
    #
    #     add_header Alt-Svc 'h3=":443"; ma=86400' always;
    #
    #     root /var/www/another;
    # }
}
```

### Configuration Notes

1. **reuseport**: Required for QUIC when using multiple worker processes
2. **always** in `add_header`: Ensures header is added even for error responses
3. **127.0.0.1 binding**: Critical - nginx must NOT listen on public interfaces for 8080

---

## Alt-Svc Header

### What It Does

The `Alt-Svc` header tells HTTP clients that an alternative protocol is available on a different port. In our setup:

```http
Alt-Svc: h3=":443"; ma=86400
```

This means:
- **h3=":443"**: HTTP/3 is available on port 443 (the public port, not nginx's 8080)
- **ma=86400**: Max-age of 86400 seconds (24 hours) - how long to cache this information

### Why Port 443, Not 8080?

Although nginx listens on 8080, the SLT wrapper exposes HTTP/3 on the public port 443. Clients connect to `:443`, and SLT forwards the traffic to nginx's `:8080`. The Alt-Svc header advertises the public-facing port.

### Browser Behavior

1. **First request**: Browser makes HTTPS request over TCP (HTTP/2 or HTTP/1.1)
2. **Receives Alt-Svc**: Browser notes that HTTP/3 is available on port 443
3. **Background test**: Browser may attempt HTTP/3 connection in the background
4. **Subsequent requests**: If HTTP/3 works, browser uses it for future requests
5. **Cache**: Browser remembers Alt-Svc for `ma` seconds (86400 = 24 hours)

### Configuration Variations

```nginx
# Basic (HTTP/3 on default HTTPS port)
add_header Alt-Svc 'h3=":443"; ma=86400' always;

# Multiple alternatives
add_header Alt-Svc 'h3=":443"; h3-29=":443"; ma=86400' always;

# With host specification (rarely needed)
add_header Alt-Svc 'h3="vpn.example.com:443"; ma=86400' always;

# Shorter cache time for testing
add_header Alt-Svc 'h3=":443"; ma=3600' always;
```

### Verifying Alt-Svc

Check the header is being sent:

```bash
# Using curl
curl -I https://vpn.example.com 2>/dev/null | grep -i alt-svc

# Expected output:
# alt-svc: h3=":443"; ma=86400

# Using openssl
openssl s_client -connect vpn.example.com:443 -servername vpn.example.com 2>/dev/null | \
  head -20
```

---

## Troubleshooting

### Common nginx Issues

#### 1. nginx Not Starting

**Symptom**: nginx fails to start after configuration changes.

**Diagnosis**:
```bash
# Test configuration syntax
sudo nginx -t

# Check for detailed errors
sudo journalctl -u nginx -n 50
```

**Common causes**:
- Syntax error in configuration file
- Port already in use
- SSL certificate path incorrect
- Missing `reuseport` directive for QUIC

#### 2. QUIC/HTTP/3 Not Working

**Symptom**: HTTP/3 connections fail, only HTTP/2 works.

**Diagnosis**:
```bash
# Check nginx version (need 1.25+ for QUIC)
nginx -v

# Check if QUIC module is compiled in
nginx -V 2>&1 | grep -i quic

# Verify UDP listener exists
ss -ulnp | grep 8080

# Test HTTP/3 with curl (curl 8.0+)
curl --http3 -I https://vpn.example.com
```

**Common causes**:
- nginx version too old (need 1.25+)
- nginx compiled without QUIC support
- `reuseport` missing from QUIC listen directive
- Firewall blocking UDP traffic

#### 3. Port Binding Issues

**Symptom**: "Address already in use" errors.

**Diagnosis**:
```bash
# Check what's listening on 8080
sudo ss -tlnp | grep 8080
sudo ss -ulnp | grep 8080

# Check if SLT is already using public 443
sudo ss -tlnp | grep :443
sudo ss -ulnp | grep :443
```

**Resolution**:
- Ensure nginx only binds to `127.0.0.1:8080`, not `0.0.0.0:8080`
- Ensure SLT is not trying to bind to 8080
- Kill any stray processes using the ports

### How to Test nginx Directly

To isolate nginx issues from SLT issues, test nginx directly on its internal port:

#### Test TCP/HTTPS

```bash
# Direct connection to nginx (bypass SLT)
curl -k --resolve vpn.example.com:8080:127.0.0.1 https://vpn.example.com:8080/

# With verbose output
curl -vk --resolve vpn.example.com:8080:127.0.0.1 https://vpn.example.com:8080/

# Check headers
curl -I -k --resolve vpn.example.com:8080:127.0.0.1 https://vpn.example.com:8080/
```

#### Test UDP/HTTP/3

```bash
# Direct HTTP/3 to nginx (requires curl 8.0+ with HTTP/3 support)
curl --http3 --resolve vpn.example.com:8080:127.0.0.1 https://vpn.example.com:8080/

# Or using a browser with quiche/QUIC support pointing to:
# https://127.0.0.1:8080/ (will show certificate warning)
```

### Port Binding Issues

#### nginx Cannot Bind to 8080

```bash
# Check if port is already in use
sudo lsof -i :8080
sudo fuser 8080/tcp
sudo fuser 8080/udp

# Find the process
sudo ss -tlnp | grep 8080
sudo ss -ulnp | grep 8080
```

#### SLT Cannot Bind to 443

```bash
# Check if nginx is mistakenly binding to public 443
sudo ss -tlnp | grep ':443'
sudo ss -ulnp | grep ':443'

# If nginx is on 443, fix nginx config to use 127.0.0.1:8080 only
```

### Certificate Issues

```bash
# Verify certificate is valid
openssl x509 -in /etc/slt/server.crt -text -noout

# Verify certificate and key match
openssl x509 -noout -modulus -in /etc/slt/server.crt | openssl md5
openssl rsa -noout -modulus -in /etc/slt/server.key | openssl md5
# MD5 hashes should match

# Test TLS connection to nginx directly
openssl s_client -connect 127.0.0.1:8080 -servername vpn.example.com
```

### Debug Logging

Enable debug logging in nginx:

```nginx
# In nginx.conf, in the http block:
error_log /var/log/nginx/error.log debug;

# Or for a specific server:
server {
    error_log /var/log/nginx/error.log debug;
    # ...
}
```

Then monitor the log:

```bash
sudo tail -f /var/log/nginx/error.log
```

### Firewall Verification

Ensure firewall allows the necessary traffic:

```bash
# Check nftables rules
sudo nft list ruleset

# Verify public ports are open
sudo nft list chain inet filter input

# Test from external host
nmap -sT -p 80,443 vpn.example.com  # TCP scan
nmap -sU -p 443 vpn.example.com     # UDP scan
```

### SLT Forwarding Verification

Check if SLT is properly forwarding to nginx:

```bash
# Watch SLT logs for forwarding events
sudo journalctl -u slt-server -f | grep -i "pass\|forward\|nginx"

# Monitor connections in real-time
sudo watch -n 1 'ss -tn state established "( dport = :8080 or sport = :8080 )"'

# Check nginx access log for requests
sudo tail -f /var/log/nginx/access.log
```

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `bind() to 0.0.0.0:443 failed` | Port already in use | SLT owns 443; nginx should bind to 127.0.0.1:8080 |
| `no "ssl_certificate" defined` | Missing TLS config | Add ssl_certificate directives |
| `quic module not compiled in` | Old nginx or missing module | Install nginx with QUIC support |
| `connection refused` to 8080 | nginx not running | Start nginx: `sudo systemctl start nginx` |
| `Alt-Svc` header missing | Not configured | Add add_header Alt-Svc directive |
