#!/bin/sh
# slt-net — bring SLT's TUN device, IPv4 forwarding, and NAT up/down.
#
# Runs privileged (as root) under slt-setup.service. It prepares everything the
# unprivileged slt-server needs so that the daemon itself never holds
# CAP_NET_ADMIN: it creates the TUN owned by the server account, configures it,
# enables forwarding, and installs NAT. `down` reverses all of it.
#
# All values can be overridden via environment (see slt-setup.service) and MUST
# match the [tun] section of /etc/slt/server.toml, since the server validates
# interface name, address, MTU, and up-state on attach.
set -eu

IFACE="${SLT_IFACE:-tun0}"
ADDR="${SLT_ADDR:-10.10.0.1/24}"
MTU="${SLT_MTU:-1406}"
SUBNET="${SLT_SUBNET:-10.10.0.0/24}"
TUN_USER="${SLT_USER:-slt}"
TUN_GROUP="${SLT_GROUP:-slt}"

up() {
    # Recreate the TUN owned by the unprivileged server account (user/group
    # set via TUNSETOWNER). Delete first so re-runs are idempotent.
    ip tuntap del dev "$IFACE" mode tun 2>/dev/null || true
    ip tuntap add dev "$IFACE" mode tun user "$TUN_USER" group "$TUN_GROUP"
    ip addr replace "$ADDR" dev "$IFACE"
    ip link set dev "$IFACE" mtu "$MTU"
    ip link set dev "$IFACE" up

    # Route client traffic from the tunnel out to the internet.
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # NAT (masquerade) + tun forwarding in a dedicated, fully-owned nftables
    # table that `down` can delete wholesale. Masquerading by source subnet
    # keeps this independent of the WAN interface name.
    #
    # Caveat: if the host already runs an nftables firewall with a drop policy
    # on the forward hook, also allow "$IFACE" there — separate base chains do
    # not override each other's verdicts.
    nft delete table inet slt 2>/dev/null || true
    nft -f - <<EOF
table inet slt {
    chain slt_forward {
        type filter hook forward priority 0; policy accept;
        iifname "$IFACE" accept
        oifname "$IFACE" accept
    }
    chain slt_postrouting {
        type nat hook postrouting priority 100; policy accept;
        ip saddr $SUBNET masquerade
    }
}
EOF
    echo "slt-net: $IFACE up ($ADDR mtu $MTU), forwarding on, NAT for $SUBNET"
}

down() {
    nft delete table inet slt 2>/dev/null || true
    ip link set dev "$IFACE" down 2>/dev/null || true
    ip tuntap del dev "$IFACE" mode tun 2>/dev/null || true
    # net.ipv4.ip_forward is intentionally left as-is; other services may rely on it.
    echo "slt-net: $IFACE down, NAT table removed"
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *) echo "usage: $0 {up|down}" >&2; exit 2 ;;
esac
