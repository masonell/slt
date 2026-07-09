# NixOS Deployment

SLT exposes a flake NixOS module and three package outputs:

| Package | Description |
|---------|-------------|
| `slt` | Builds SLT from source with Nix |
| `slt-bin-musl` | Installs static musl release binaries |
| `slt-bin-gnu` | Installs GNU/Linux release binaries with `autoPatchelfHook` |

The NixOS module generates SLT TOML configuration, systemd services, users, and
optional firewall/systemd-networkd TUN setup. Secret bytes are not written to the
Nix store. Secret options are plain absolute path strings and are passed to
systemd with `LoadCredential`.

## Flake Input

Add SLT to your NixOS flake:

```nix
{
  inputs.slt.url = "github:masonell/slt";

  outputs =
    { nixpkgs, slt, ... }:
    {
      nixosConfigurations.server = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        specialArgs = { inherit slt; };
        modules = [
          slt.nixosModules.default
          ./configuration.nix
        ];
      };
    };
}
```

## Package Selection

The module defaults to `inputs.slt.packages.${pkgs.system}.slt`, which builds from
source. Select a release-binary package when you want faster target-machine
activation:

```nix
{ pkgs, slt, ... }:

{
  services.slt.package = slt.packages.${pkgs.system}.slt-bin-musl;
}
```

Use `slt-bin-musl` for static release artifacts. Use `slt-bin-gnu` when the
release artifact is dynamically linked GNU/Linux and should be patched for NixOS.

## Server Example

```nix
{
  services.slt.servers.main = {
    serverSecretFile = "/run/secrets/slt/server-secret";

    openFirewall = true;

    network = {
      listenTcp = "0.0.0.0:443";
      listenUdp = "0.0.0.0:443";
      nginxTcpUpstream = "127.0.0.1:8080";
      nginxUdpUpstream = "127.0.0.1:8080";
    };

    tls = {
      certFile = "/etc/slt/server.pem";
      keyFile = "/run/secrets/slt/server-key.pem";
    };

    tun = {
      name = "slt0";
      mtu = 1406;
      ipv4 = "10.10.0.1";
      prefix = 24;
    };

    timing.tcpWriteTimeout = "10s";

    clients.laptop = {
      clientId = "0102030405060708090a0b0c0d0e0f10";
      pubkeyEd25519 = "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";
      assignedIpv4 = "10.10.0.2";
    };
  };
}
```

With `manageTun = true`, the module declares the TUN device through
`systemd.network`. Set `manageTun = false` if another NixOS networking module
manages the TUN device.

## Forwarding and NAT

Configure IPv4 forwarding and masquerading with standard NixOS networking
options. For the server example above, the generated networkd unit is
`systemd.network.networks."50-slt-server-main"`:

```nix
{
  networking.nat = {
    enable = true;
    externalInterface = "enp2s0";
    internalInterfaces = [ "slt0" ];
  };

  systemd.network.networks."50-slt-server-main".networkConfig = {
    IPv4Forwarding = true;
  };
}
```

Prefer `networking.nat` for masquerading instead of
`systemd.network.networks.<name>.networkConfig.IPMasquerade`.

## Client Example

```nix
{
  services.slt.clients.main = {
    network = {
      hostname = "vpn.example.com";
      port = 443;
    };

    tls.caFile = "/etc/slt/ca.pem";

    identity = {
      clientId = "0102030405060708090a0b0c0d0e0f10";
      sharedSecretFile = "/run/secrets/slt/shared-secret";
      assignedIpv4 = "10.10.0.2";
      privkeyEd25519File = "/run/secrets/slt/client-key";
    };

    tun = {
      name = "slt0";
      mtu = 1406;
      prefix = 24;
    };

    enableUpgrade = true;
    requireUdp = false;

    timing.tcpWriteTimeout = "10s";
  };
}
```

When `tun.ipv4` is omitted for a client, the module uses
`identity.assignedIpv4`.

## Secret Files

Use absolute string paths for secret files:

```nix
{
  services.slt.servers.main.serverSecretFile = "/run/secrets/slt/server-secret";
}
```

Do not use Nix path literals such as `./server-secret`, because those paths are
copied into the Nix store. The secret file contents must match SLT's TOML file
format expectations:

| Option | File contents |
|--------|---------------|
| `serverSecretFile` | 32 raw bytes or 64 hex characters |
| `identity.sharedSecretFile` | 32 raw bytes or 64 hex characters |
| `identity.privkeyEd25519File` | 32 raw bytes or 64 hex characters |
| `tls.keyFile` | PEM private key |
| TLS certificate/CA files | PEM certificate material |

Paths from `sops-nix` or `agenix` work well because they resolve to runtime files
under `/run`.

## Operations

The generated units are named from the instance name:

```bash
systemctl status slt-server-main
systemctl status slt-client-main
```

The generated config files are stored in the Nix store and contain only public
configuration plus `/run/credentials/...` references for secret material. Each
unit validates its generated TOML with `slt validate` before starting.
