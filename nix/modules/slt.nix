{
  self ? null,
}:

{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    concatLists
    concatStringsSep
    filter
    filterAttrs
    hasPrefix
    literalExpression
    mapAttrs
    mapAttrsToList
    mkIf
    mkMerge
    mkOption
    nameValuePair
    optional
    types
    unique
    ;

  cfg = config.services.slt;
  toml = pkgs.formats.toml { };

  flakePackages =
    if self == null || !(self ? packages) || !(builtins.hasAttr pkgs.system self.packages) then
      null
    else
      self.packages.${pkgs.system};

  defaultPackage =
    if flakePackages != null && builtins.hasAttr "slt" flakePackages then
      flakePackages.slt
    else
      throw "services.slt.package must be set when the SLT flake package is unavailable";

  cleanNulls =
    value:
    if builtins.isAttrs value then
      filterAttrs (_: v: v != null) (mapAttrs (_: cleanNulls) value)
    else if builtins.isList value then
      map cleanNulls value
    else
      value;

  credentialFile = unitName: credentialName: "/run/credentials/${unitName}.service/${credentialName}";

  safeUnitName = name: builtins.match "^[A-Za-z0-9_.-]+$" name != null;

  pathOption =
    description:
    mkOption {
      type = types.str;
      example = "/run/secrets/slt/secret";
      inherit description;
    };

  durationOption =
    default: example: description:
    mkOption {
      type = types.str;
      inherit default example description;
    };

  positiveIntOption =
    default: description:
    mkOption {
      type = types.ints.positive;
      inherit default description;
    };

  nullablePositiveIntOption =
    description:
    mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      inherit description;
    };

  tunMtuType = types.addCheck types.int (value: value >= 1 && value <= 1406);
  tunPrefixType = types.addCheck types.int (value: value >= 1 && value <= 32);

  portOf =
    socket:
    let
      match = builtins.match "^.*:([0-9]+)$" socket;
    in
    if match == null then
      throw "could not parse TCP/UDP port from SLT socket address `${socket}`"
    else
      builtins.fromJSON (builtins.elemAt match 0);

  serverClientOptions =
    { ... }:
    {
      options = {
        clientId = mkOption {
          type = types.str;
          example = "0102030405060708090a0b0c0d0e0f10";
          description = "Hex-encoded 16-byte client identifier.";
        };

        pubkeyEd25519 = mkOption {
          type = types.str;
          example = "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";
          description = "Hex-encoded 32-byte Ed25519 public key.";
        };

        assignedIpv4 = mkOption {
          type = types.str;
          example = "10.10.0.2";
          description = "Client IPv4 address inside the SLT overlay subnet.";
        };

        enabled = mkOption {
          type = types.bool;
          default = true;
          description = "Whether this client entry is accepted by the server.";
        };
      };
    };

  tunOptions =
    defaultIpv4:
    { ... }:
    {
      options = {
        name = mkOption {
          type = types.str;
          default = "tun0";
          example = "slt0";
          description = "TUN interface name expected by SLT.";
        };

        mtu = mkOption {
          type = tunMtuType;
          default = 1280;
          example = 1406;
          description = "TUN interface MTU. SLT supports values from 1 through 1406.";
        };

        ipv4 = mkOption {
          type = if defaultIpv4 == null then types.nullOr types.str else types.str;
          default = defaultIpv4;
          example = "10.10.0.1";
          description = "Local IPv4 address configured on the TUN interface.";
        };

        prefix = mkOption {
          type = tunPrefixType;
          default = 24;
          description = "IPv4 overlay subnet prefix length.";
        };
      };
    };

  serverOptions =
    { name, ... }:
    {
      options = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = "Whether to run this SLT server instance.";
        };

        package = mkOption {
          type = types.nullOr types.package;
          default = null;
          description = "Package to use for this instance. Defaults to services.slt.package.";
        };

        user = mkOption {
          type = types.str;
          default = "slt-server-${name}";
          description = "User account that runs the SLT server process.";
        };

        group = mkOption {
          type = types.str;
          default = "slt-server-${name}";
          description = "Group account that runs the SLT server process.";
        };

        createUser = mkOption {
          type = types.bool;
          default = true;
          description = "Whether to create the configured user and group.";
        };

        serverSecretFile = pathOption ''
          File containing the 32-byte server secret as raw bytes or hex text.
          The file is passed to the service with systemd credentials.
        '';

        openFirewall = mkOption {
          type = types.bool;
          default = false;
          description = "Whether to open the configured TCP and UDP listener ports.";
        };

        manageTun = mkOption {
          type = types.bool;
          default = true;
          description = "Whether to declare the configured TUN device with systemd-networkd.";
        };

        network = mkOption {
          default = { };
          type = types.submodule {
            options = {
              listenTcp = mkOption {
                type = types.str;
                default = "0.0.0.0:443";
                description = "TCP listener socket address.";
              };

              listenUdp = mkOption {
                type = types.str;
                default = "0.0.0.0:443";
                description = "UDP listener socket address.";
              };

              nginxTcpUpstream = mkOption {
                type = types.str;
                default = "127.0.0.1:8080";
                description = "TCP upstream socket address for non-SLT traffic.";
              };

              nginxUdpUpstream = mkOption {
                type = types.str;
                default = "127.0.0.1:8080";
                description = "UDP upstream socket address for non-SLT traffic.";
              };
            };
          };
        };

        tls = mkOption {
          default = { };
          type = types.submodule {
            options = {
              certFile = pathOption "PEM certificate chain file used by the SLT server.";
              keyFile = pathOption ''
                PEM private key file used by the SLT server.
                The file is passed to the service with systemd credentials.
              '';
            };
          };
        };

        tun = mkOption {
          default = { };
          type = types.submodule (tunOptions "10.10.0.1");
        };

        timing = mkOption {
          default = { };
          type = types.submodule {
            options = {
              pingMin = durationOption "10s" "10s" "Minimum ping interval.";
              pingMax = durationOption "30s" "30s" "Maximum ping interval.";
              authTimeout = durationOption "10s" "10s" "TLS/AUTH timeout.";
              tcpWriteTimeout =
                durationOption "10s" "10s"
                  "Maximum time for an established-session TCP message write.";
              udpLivenessTimeout =
                durationOption "90s" "90s"
                  "Maximum time without authenticated UDP-QSP ingress before TCP fallback.";
              idleTimeout =
                durationOption "5m" "5m" "Maximum time without accepted session ingress.";
              metricsInterval = durationOption "5m" "5m" "Metrics logging interval.";
              tcpClassificationTimeout = durationOption "60s" "60s" "TCP ClientHello classification timeout.";
            };
          };
        };

        transport = mkOption {
          default = { };
          type = types.submodule {
            options.udpQsp = mkOption {
              default = { };
              type = types.submodule {
                options.allowedCiphers = mkOption {
                  type = types.listOf (
                    types.enum [
                      "aes-128-gcm"
                      "chacha20-poly1305"
                    ]
                  );
                  default = [
                    "aes-128-gcm"
                    "chacha20-poly1305"
                  ];
                  description = "UDP-QSP cipher suites accepted from clients.";
                };
              };
            };
          };
        };

        udpNatMaxEntries = positiveIntOption 1024 "Maximum UDP NAT entries for nginx forwarding.";
        sessionQueueSize = positiveIntOption 256 "Bounded queue size for per-session events.";
        maxAuthInflight = positiveIntOption 128 "Maximum concurrent TLS/AUTH handshakes.";
        tcpConnectionCap = nullablePositiveIntOption "Maximum classifying and nginx-proxied TCP connections.";

        clients = mkOption {
          default = { };
          type = types.attrsOf (types.submodule serverClientOptions);
          description = "Server-side client allowlist.";
        };
      };
    };

  clientOptions =
    { name, ... }:
    {
      options = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = "Whether to run this SLT client instance.";
        };

        package = mkOption {
          type = types.nullOr types.package;
          default = null;
          description = "Package to use for this instance. Defaults to services.slt.package.";
        };

        user = mkOption {
          type = types.str;
          default = "slt-client-${name}";
          description = "User account that runs the SLT client process.";
        };

        group = mkOption {
          type = types.str;
          default = "slt-client-${name}";
          description = "Group account that runs the SLT client process.";
        };

        createUser = mkOption {
          type = types.bool;
          default = true;
          description = "Whether to create the configured user and group.";
        };

        manageTun = mkOption {
          type = types.bool;
          default = true;
          description = "Whether to declare the configured TUN device with systemd-networkd.";
        };

        logFilter = mkOption {
          type = types.nullOr types.str;
          default = null;
          example = "slt_client=debug,slt_core=debug";
          description = "Optional tracing filter passed to slt-client --log.";
        };

        network = mkOption {
          default = { };
          type = types.submodule {
            options = {
              hostname = mkOption {
                type = types.str;
                example = "vpn.example.com";
                description = "Server hostname used for SNI and certificate verification.";
              };

              port = mkOption {
                type = types.port;
                default = 443;
                description = "Server TCP/UDP port.";
              };

              ip = mkOption {
                type = types.nullOr types.str;
                default = null;
                example = "203.0.113.10";
                description = "Optional IP address override that bypasses DNS.";
              };
            };
          };
        };

        tls = mkOption {
          default = { };
          type = types.submodule {
            options = {
              caFile = pathOption "PEM CA file used to verify the SLT server certificate.";
              quicCaFile = mkOption {
                type = types.nullOr types.str;
                default = null;
                example = "/etc/slt/quic-ca.pem";
                description = "Optional PEM CA file used for QUIC discovery.";
              };
            };
          };
        };

        identity = mkOption {
          default = { };
          type = types.submodule {
            options = {
              clientId = mkOption {
                type = types.str;
                example = "0102030405060708090a0b0c0d0e0f10";
                description = "Hex-encoded 16-byte client identifier.";
              };

              sharedSecretFile = pathOption ''
                File containing the 32-byte shared secret as raw bytes or hex text.
                The file is passed to the service with systemd credentials.
              '';

              assignedIpv4 = mkOption {
                type = types.str;
                example = "10.10.0.2";
                description = "Client IPv4 address assigned by the SLT server.";
              };

              privkeyEd25519File = pathOption ''
                File containing the 32-byte Ed25519 private key as raw bytes or hex text.
                The file is passed to the service with systemd credentials.
              '';
            };
          };
        };

        tun = mkOption {
          default = { };
          type = types.submodule (tunOptions null);
        };

        enableUpgrade = mkOption {
          type = types.bool;
          default = false;
          description = "Whether to enable QUIC discovery and UDP-QSP upgrade.";
        };

        requireUdp = mkOption {
          type = types.bool;
          default = false;
          description = "Whether the session must fail if UDP upgrade fails.";
        };

        transport = mkOption {
          default = { };
          type = types.submodule {
            options.udpQsp = mkOption {
              default = { };
              type = types.submodule {
                options.cipher = mkOption {
                  type = types.enum [
                    "auto"
                    "aes-128-gcm"
                    "chacha20-poly1305"
                  ];
                  default = "auto";
                  description = "UDP-QSP packet protection cipher policy.";
                };
              };
            };
          };
        };

        timing = mkOption {
          default = { };
          type = types.submodule {
            options = {
              pingMin = durationOption "10s" "10s" "Minimum ping interval.";
              pingMax = durationOption "30s" "30s" "Maximum ping interval.";
              authTimeout = durationOption "10s" "10s" "TLS/AUTH timeout.";
              tcpWriteTimeout =
                durationOption "10s" "10s" "Maximum time for one TCP message write.";
              registerTimeout = durationOption "10s" "10s" "UDP-QSP registration timeout.";
              quicDiscoveryTimeout = durationOption "15s" "15s" "QUIC discovery timeout.";
              udpLivenessTimeout =
                durationOption "90s" "90s" "Authenticated UDP-QSP ingress timeout.";
              idleTimeout =
                durationOption "5m" "5m" "Maximum time without accepted session ingress.";
              metricsInterval = durationOption "5m" "5m" "Metrics logging interval.";
              reconnectMin = durationOption "200ms" "200ms" "Minimum reconnect backoff.";
              reconnectMax = durationOption "5s" "5s" "Maximum reconnect backoff.";
            };
          };
        };
      };
    };

  enabledServers = filter (entry: entry.value.enable) (mapAttrsToList nameValuePair cfg.servers);
  enabledClients = filter (entry: entry.value.enable) (mapAttrsToList nameValuePair cfg.clients);
  enabledInstances = enabledServers ++ enabledClients;
  managedTunInstances =
    map (entry: entry // { kind = "server"; }) (filter (entry: entry.value.manageTun) enabledServers)
    ++ map (entry: entry // { kind = "client"; }) (
      filter (entry: entry.value.manageTun) enabledClients
    );
  managedTunNames = map (entry: entry.value.tun.name) managedTunInstances;

  packageFor = instance: if instance.package != null then instance.package else cfg.package;
  networkdUnitName = entry: "50-slt-${entry.kind}-${entry.name}";
  tunIpv4For =
    instance: if instance.tun.ipv4 == null then instance.identity.assignedIpv4 else instance.tun.ipv4;
  tunCidrFor = instance: "${tunIpv4For instance}/${builtins.toString instance.tun.prefix}";

  serverToml =
    name: server:
    cleanNulls {
      server_secret = {
        file = credentialFile "slt-server-${name}" "server-secret";
      };
      network = {
        listen_tcp = server.network.listenTcp;
        listen_udp = server.network.listenUdp;
        nginx_tcp_upstream = server.network.nginxTcpUpstream;
        nginx_udp_upstream = server.network.nginxUdpUpstream;
      };
      tls = {
        tls_cert = {
          file = server.tls.certFile;
        };
        tls_key = {
          file = credentialFile "slt-server-${name}" "tls-key";
        };
      };
      tun = {
        tun_name = server.tun.name;
        tun_mtu = server.tun.mtu;
        tun_ipv4 = server.tun.ipv4;
        tun_prefix = server.tun.prefix;
      };
      timing = {
        ping_min = server.timing.pingMin;
        ping_max = server.timing.pingMax;
        auth_timeout = server.timing.authTimeout;
        tcp_write_timeout = server.timing.tcpWriteTimeout;
        udp_liveness_timeout = server.timing.udpLivenessTimeout;
        idle_timeout = server.timing.idleTimeout;
        metrics_interval = server.timing.metricsInterval;
        tcp_classification_timeout = server.timing.tcpClassificationTimeout;
      };
      transport = {
        udp_qsp = {
          allowed_ciphers = server.transport.udpQsp.allowedCiphers;
        };
      };
      udp_nat_max_entries = server.udpNatMaxEntries;
      session_queue_size = server.sessionQueueSize;
      max_auth_inflight = server.maxAuthInflight;
      tcp_connection_cap = server.tcpConnectionCap;
      clients = mapAttrsToList (_: client: {
        client_id = client.clientId;
        pubkey_ed25519 = client.pubkeyEd25519;
        assigned_ipv4 = client.assignedIpv4;
        enabled = client.enabled;
      }) server.clients;
    };

  clientToml =
    name: client:
    cleanNulls {
      network = {
        hostname = client.network.hostname;
        port = client.network.port;
        ip = client.network.ip;
      };
      tls = {
        tls_ca = {
          file = client.tls.caFile;
        };
        quic_ca =
          if client.tls.quicCaFile == null then
            null
          else
            {
              file = client.tls.quicCaFile;
            };
      };
      identity = {
        client_id = client.identity.clientId;
        shared_secret = {
          file = credentialFile "slt-client-${name}" "shared-secret";
        };
        assigned_ipv4 = client.identity.assignedIpv4;
        privkey_ed25519 = {
          file = credentialFile "slt-client-${name}" "privkey-ed25519";
        };
      };
      tun = {
        tun_name = client.tun.name;
        tun_mtu = client.tun.mtu;
        tun_ipv4 = if client.tun.ipv4 == null then client.identity.assignedIpv4 else client.tun.ipv4;
        tun_prefix = client.tun.prefix;
      };
      enable_upgrade = client.enableUpgrade;
      require_udp = client.requireUdp;
      transport = {
        udp_qsp = {
          cipher = client.transport.udpQsp.cipher;
        };
      };
      timing = {
        ping_min = client.timing.pingMin;
        ping_max = client.timing.pingMax;
        auth_timeout = client.timing.authTimeout;
        tcp_write_timeout = client.timing.tcpWriteTimeout;
        register_timeout = client.timing.registerTimeout;
        quic_discovery_timeout = client.timing.quicDiscoveryTimeout;
        udp_liveness_timeout = client.timing.udpLivenessTimeout;
        idle_timeout = client.timing.idleTimeout;
        metrics_interval = client.timing.metricsInterval;
        reconnect_min = client.timing.reconnectMin;
        reconnect_max = client.timing.reconnectMax;
      };
    };

  configFile =
    kind: name: settings:
    toml.generate "slt-${kind}-${name}.toml" settings;

  mkManagedTunNetdev =
    entry:
    nameValuePair (networkdUnitName entry) {
      netdevConfig = {
        Name = entry.value.tun.name;
        Kind = "tun";
        MTUBytes = builtins.toString entry.value.tun.mtu;
      };

      tunConfig = {
        User = entry.value.user;
        Group = entry.value.group;
      };
    };

  mkManagedTunNetwork =
    entry:
    nameValuePair (networkdUnitName entry) {
      matchConfig.Name = entry.value.tun.name;
      address = [ (tunCidrFor entry.value) ];
      linkConfig.RequiredForOnline = "no-carrier";
      networkConfig.ConfigureWithoutCarrier = true;
    };

  mkServerService =
    { name, value }:
    let
      unitName = "slt-server-${name}";
      package = packageFor value;
      file = configFile "server" name (serverToml name value);
    in
    nameValuePair unitName {
      description = "SLT server ${name}";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ] ++ optional value.manageTun "systemd-networkd.service";
      requires = optional value.manageTun "systemd-networkd.service";

      serviceConfig = {
        Type = "simple";
        User = value.user;
        Group = value.group;
        Restart = "on-failure";
        RestartSec = "5s";
        LoadCredential = [
          "server-secret:${value.serverSecretFile}"
          "tls-key:${value.tls.keyFile}"
        ];
        ExecStart = "${package}/bin/slt-server --config ${file}";
        ExecStartPre = [ "${package}/bin/slt validate ${file}" ];
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
      };
    };

  mkClientService =
    { name, value }:
    let
      unitName = "slt-client-${name}";
      package = packageFor value;
      file = configFile "client" name (clientToml name value);
    in
    nameValuePair unitName {
      description = "SLT client ${name}";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ] ++ optional value.manageTun "systemd-networkd.service";
      requires = optional value.manageTun "systemd-networkd.service";

      serviceConfig = {
        Type = "simple";
        User = value.user;
        Group = value.group;
        Restart = "on-failure";
        RestartSec = "5s";
        LoadCredential = [
          "shared-secret:${value.identity.sharedSecretFile}"
          "privkey-ed25519:${value.identity.privkeyEd25519File}"
        ];
        ExecStart = concatStringsSep " " (
          [
            "${package}/bin/slt-client"
            "--config"
            "${file}"
          ]
          ++ optional (value.logFilter != null) "--log"
          ++ optional (value.logFilter != null) value.logFilter
        );
        ExecStartPre = [ "${package}/bin/slt validate ${file}" ];
      };
    };

  createUserAttrs =
    instances:
    let
      withUsers = filter (entry: entry.value.createUser) instances;
      groups = unique (map (entry: entry.value.group) withUsers);
    in
    {
      users.groups = builtins.listToAttrs (map (group: nameValuePair group { }) groups);
      users.users = builtins.listToAttrs (
        map (
          entry:
          nameValuePair entry.value.user {
            isSystemUser = true;
            group = entry.value.group;
          }
        ) withUsers
      );
    };

  absolutePathAssertions =
    let
      serverPaths = concatLists (
        map (
          entry:
          let
            server = entry.value;
            base = "services.slt.servers.${entry.name}";
          in
          [
            {
              option = "${base}.serverSecretFile";
              path = server.serverSecretFile;
            }
            {
              option = "${base}.tls.certFile";
              path = server.tls.certFile;
            }
            {
              option = "${base}.tls.keyFile";
              path = server.tls.keyFile;
            }
          ]
        ) enabledServers
      );

      clientPaths = concatLists (
        map (
          entry:
          let
            client = entry.value;
            base = "services.slt.clients.${entry.name}";
          in
          [
            {
              option = "${base}.tls.caFile";
              path = client.tls.caFile;
            }
            {
              option = "${base}.identity.sharedSecretFile";
              path = client.identity.sharedSecretFile;
            }
            {
              option = "${base}.identity.privkeyEd25519File";
              path = client.identity.privkeyEd25519File;
            }
          ]
          ++ optional (client.tls.quicCaFile != null) {
            option = "${base}.tls.quicCaFile";
            path = client.tls.quicCaFile;
          }
        ) enabledClients
      );
    in
    map (item: {
      assertion = hasPrefix "/" item.path;
      message = "${item.option} must be an absolute path.";
    }) (serverPaths ++ clientPaths);

  firewallServers = filter (entry: entry.value.openFirewall) enabledServers;
in
{
  options.services.slt = {
    enable = mkOption {
      type = types.bool;
      default = cfg.servers != { } || cfg.clients != { };
      defaultText = literalExpression "config.services.slt.servers != {} || config.services.slt.clients != {}";
      description = "Whether to enable configured SLT server and client instances.";
    };

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = literalExpression "inputs.slt.packages.${pkgs.system}.slt";
      description = "Default SLT package used by server and client instances.";
    };

    servers = mkOption {
      default = { };
      type = types.attrsOf (types.submodule serverOptions);
      description = "SLT server instances.";
    };

    clients = mkOption {
      default = { };
      type = types.attrsOf (types.submodule clientOptions);
      description = "SLT client instances.";
    };
  };

  config = mkIf cfg.enable (mkMerge [
    (createUserAttrs enabledInstances)

    {
      assertions = [
        {
          assertion = builtins.all (entry: safeUnitName entry.name) enabledInstances;
          message = "SLT instance names may only contain ASCII letters, digits, dots, underscores, and dashes.";
        }
        {
          assertion = builtins.length managedTunNames == builtins.length (unique managedTunNames);
          message = "SLT instances with manageTun = true must use unique tun.name values.";
        }
      ]
      ++ absolutePathAssertions
      ++ map (entry: {
        assertion = !entry.value.requireUdp || entry.value.enableUpgrade;
        message = "services.slt.clients.${entry.name}.requireUdp requires enableUpgrade = true.";
      }) enabledClients;

      systemd.services = builtins.listToAttrs (
        map mkServerService enabledServers ++ map mkClientService enabledClients
      );

      systemd.network = mkIf (managedTunInstances != [ ]) {
        enable = true;
        netdevs = builtins.listToAttrs (map mkManagedTunNetdev managedTunInstances);
        networks = builtins.listToAttrs (map mkManagedTunNetwork managedTunInstances);
      };

      networking.firewall.allowedTCPPorts = unique (
        map (entry: portOf entry.value.network.listenTcp) firewallServers
      );
      networking.firewall.allowedUDPPorts = unique (
        map (entry: portOf entry.value.network.listenUdp) firewallServers
      );
    }
  ]);
}
