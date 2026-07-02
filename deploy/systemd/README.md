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

# 2. Binary + config (config [tun] must match the SLT_* defaults below)
sudo install -m 0755 slt-server                  /usr/local/bin/slt-server
sudo install -d -m 0750 -o root -g slt           /etc/slt
sudo install -m 0640 -o root -g slt server.toml  /etc/slt/server.toml
# The slt user must be able to read any TLS cert/key referenced by the config.
```

Install the units and helper:

```sh
sudo install -m 0755 slt-net.sh          /usr/local/sbin/slt-net
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
ip -br addr show tun0                       # tun0 UP, 10.10.0.1/24, mtu 1406
nft list table inet slt                     # forward + masquerade rules present
sudo sysctl net.ipv4.ip_forward             # = 1
journalctl -u slt-server -f
```

## Tuning

Override the TUN/NAT values without editing files by setting them on
`slt-setup.service`:

```sh
sudo systemctl edit slt-setup.service
# [Service]
# Environment=SLT_IFACE=tun1 SLT_ADDR=10.20.0.1/24 SLT_MTU=1406 SLT_SUBNET=10.20.0.0/24 SLT_USER=slt SLT_GROUP=slt
```

`server.toml`'s `[tun]` (`tun_name`, `tun_ipv4`, `tun_prefix`, `tun_mtu`) must
agree with these, or the server will reject the interface on attach.

If the host runs its own nftables firewall with a **drop** forward policy, allow
the tunnel interface there too — separate base chains do not override each
other's verdicts.
