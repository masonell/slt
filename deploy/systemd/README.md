# SLT systemd units

Two cooperating units that run `slt-server` with **minimum privileges**:

| Unit | Runs as | Role |
|------|---------|------|
| `slt-setup.service` | **root** (oneshot) | Creates & configures the TUN, enables IPv4 forwarding, installs NAT. Tears it all down on stop. |
| `slt-server.service` | **`slt`** (unprivileged) | Runs the daemon. Only ambient cap: `CAP_NET_BIND_SERVICE` (for `:443`). No `CAP_NET_ADMIN`. |

The split is required: the server does **not** create or configure the TUN — it
attaches to a pre-existing one and validates it
(`slt-core/src/transport/tun.rs`). So the privileged networking must happen in a
separate security context that exits before the daemon runs, leaving the daemon
with no network-admin power. `slt-setup` owns the TUN to the `slt` account
(`ip tuntap add ... user slt`), which is what lets the unprivileged daemon open
it.

Cleanup is automatic: `slt-setup` has `PartOf=slt-server.service`, so stopping
or restarting `slt-server` runs the setup unit's `ExecStop` (deletes the NAT
table and the TUN). System shutdown tears both down.

## Install

Prerequisites:

```sh
# 1. Dedicated, non-login service account
sudo useradd -r -s /usr/sbin/nologin -M -d /nonexistent slt

# 2. Binaries + config
sudo install -m 0755 slt                         /usr/local/bin/slt
sudo install -m 0755 slt-server                  /usr/local/bin/slt-server
sudo install -d -m 0750 -o root -g slt           /etc/slt
sudo install -m 0640 -o root -g slt server.toml  /etc/slt/server.toml
# The slt user must be able to read any TLS cert/key referenced by the config.
```

Install the units:

```sh
sudo install -m 0644 slt-setup.service   /etc/systemd/system/
sudo install -m 0644 slt-server.service  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now slt-server.service   # pulls in slt-setup via Requires=
```

> Do **not** `setcap cap_net_bind_service` the binary — the capability is granted
> via `AmbientCapabilities=`. Pick one, not both.

## Verify

```sh
systemctl status slt-server slt-setup
ip -br addr show tun0                       # tun0 UP, 10.10.0.1/24, mtu 1186
nft list table inet slt                     # forward + masquerade rules present
sudo sysctl net.ipv4.ip_forward             # = 1
journalctl -u slt-server -f
```

## Tuning

TUN interface name, address, prefix, and MTU are read from `/etc/slt/server.toml`
by `slt net`, so update the config's `[tun]` section to change them:

```toml
[tun]
tun_name = "tun1"
tun_mtu = 1186
tun_ipv4 = "10.20.0.1"
tun_prefix = 24
```

Override deployment-local values without editing files by setting them on
`slt-setup.service`:

```sh
sudo systemctl edit slt-setup.service
# [Service]
# Environment=SLT_CONFIG=/etc/slt/server.toml SLT_USER=slt SLT_GROUP=slt
```

The setup unit runs:

```sh
slt net up --config "$SLT_CONFIG" --user "$SLT_USER" --group "$SLT_GROUP" --ipv4-forward --masquerade
slt net down --config "$SLT_CONFIG" --masquerade
```

`slt net` accepts either a server or client config because both use the same
`[tun]` schema. `--masquerade` installs an SLT-owned nftables table with forward
accept rules for the TUN interface and source NAT for the configured TUN subnet.
`--ipv4-forward` enables `net.ipv4.ip_forward`; shutdown intentionally leaves the
sysctl as-is because other services may rely on it.

If the host runs its own nftables firewall with a **drop** forward policy, allow
the tunnel interface there too — separate base chains do not override each
other's verdicts.
