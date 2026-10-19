# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Delfim Leite
#
# Clean-room implementation. Written from the Tor Project's public relay
# operator documentation and the nftables manual. The "connections" mode
# follows the behaviour described in the public README of the stopped
# Enkidu-6/tor-ddos project (documentation only: none of its scripts or rules
# were read, and that repository carries no licence, so no code was reused).
{ config, lib, pkgs, ... }:

let
  cfg = config.services.tor.antiDoS;

  # One pair of rules per address family: nftables dynamic sets are typed, so
  # IPv4 and IPv6 sources are tracked separately.
  familyRules = family: saddr: ''
    tcp dport { ${lib.concatMapStringsSep ", " toString cfg.orPorts } } \
      ct state new \
      add @flooders-${family} { ${saddr} limit rate over ${toString cfg.rate}/second burst ${toString cfg.burst} packets } \
      ${lib.optionalString cfg.logDropped ''log prefix "tor-antidos ${family} " ''}counter drop
  '';

  isV6 = lib.hasInfix ":";
  v4Of = lib.filter (a: !isV6 a);
  v6Of = lib.filter isV6;
  portSet = "{ ${lib.concatMapStringsSep ", " toString cfg.orPorts} }";
  useRate = cfg.mode == "rate" || cfg.mode == "both";
  useConn = cfg.mode == "connections" || cfg.mode == "both";
  c = cfg.connections;

  # Directory authorities, from the consensus of 2026-10-19. They change
  # rarely; `lists.enable` keeps them current.
  authoritiesV4 = [
    "128.31.0.39" "131.188.40.189" "171.25.193.9" "193.23.244.244" "199.58.81.140"
    "204.13.164.118" "216.218.219.41" "217.196.147.77" "45.66.35.11" "66.111.2.131"
  ];
  authoritiesV6 = [
    "2001:470:164:2::2" "2001:638:a000:4140::ffff:189" "2001:678:558:1000::244" "2001:67c:289c::9"
    "2610:1c0:0:5::131" "2620:13:4000:6000::1000:118" "2a02:16a8:662:2203::1" "2a09:61c0::1337"
  ];

  allowAll = c.allowedAddresses ++ lib.optionals c.includeAuthorities (authoritiesV4 ++ authoritiesV6);

  # Address sets that can be filled from the config and, with `lists.enable`,
  # refreshed at runtime. Interval sets, so prefixes work too.
  addrSet = name: family: addrs: ''
    set ${name}-${family} {
      type ${if family == "v4" then "ipv4_addr" else "ipv6_addr"}
      flags interval
      ${lib.optionalString (addrs != [ ]) "elements = { ${lib.concatStringsSep ", " addrs} }"}
    }
  '';

  # Dynamic set used as a per-source concurrent-connection counter.
  meter = name: family: ''
    set ${name}-${family} {
      type ${if family == "v4" then "ipv4_addr" else "ipv6_addr"}
      flags dynamic
      size ${toString cfg.maxTrackedSources}
    }
  '';

  blockedSet = family: ''
    set blocked-${family} {
      type ${if family == "v4" then "ipv4_addr" else "ipv6_addr"}
      flags dynamic, timeout
      timeout ${c.blockFor}
      size ${toString c.maxBlocked}
    }
  '';

  # Concurrent-connection rules for one address family.
  #
  # A connection above the limit is dropped before it is ever confirmed, so a
  # source can never hold more than its limit open: "how many are open" can
  # not by itself tell a flood from a client asking twice. What marks a flood
  # is how often a source keeps asking after being refused, so every refusal
  # also feeds a per-source meter, and a source that overruns it is blocked.
  # The count is evaluated once per packet (a second `ct count` statement
  # would count the same connection again), then a shared chain refuses it.
  tier = name: family: saddr: sel: limit: ''
    ct state new ${saddr} ${sel} add @cc-${name}-${family} { ${saddr} ct count over ${toString limit} } jump refuse-${family}
  '';

  refuseChain = family: saddr: ''
    chain refuse-${family} {
      add @refused-${family} { ${saddr} limit rate over ${toString c.banAfterRefused}/minute burst ${toString c.banAfterRefused} packets } add @blocked-${family} { ${saddr} }
      counter drop
    }
  '';

  connRules = family: saddr: ''
    ${saddr} @allow-${family} accept
    ct state new ${saddr} @blocked-${family} ${lib.optionalString cfg.logDropped ''log prefix "tor-antidos blocked-${family} " ''}counter drop
    ${tier "many" family saddr "@many-${family}" c.maxPerManyInstanceAddress}
    ${tier "two" family saddr "@two-${family}" c.maxPerTwoInstanceAddress}
    ${tier "single" family saddr "!= @many-${family} ${saddr} != @two-${family}" c.maxPerAddress}
  '';
in
{
  options.services.tor.antiDoS = {
    enable = lib.mkEnableOption ''
      per-source rate limiting of new connections to the Tor ORPort.

      This limits how fast a *single* source address may open new connections.
      It does not cap the relay's total connection rate, which on a busy guard
      is legitimately high
    '';

    orPorts = lib.mkOption {
      type = lib.types.listOf lib.types.port;
      example = [ 9001 ];
      description = ''
        ORPort numbers to protect. These must match the ports configured in
        {option}`services.tor.settings.ORPort`; nothing verifies that for you,
        because the ORPort setting accepts several shapes.

        There is deliberately no default: protecting the wrong port silently
        does nothing, which is worse than failing to build.
      '';
    };

    mode = lib.mkOption {
      type = lib.types.enum [ "rate" "connections" "both" ];
      default = "rate";
      description = ''
        What to limit.

        - `rate`: how fast one source may open *new* connections (the
          original behaviour of this module).
        - `connections`: how many connections one source may hold open *at
          once*, with temporary blocking of sources that go well over. This is
          the model relay operators know from the stopped `tor-ddos` scripts.
        - `both`: apply the two.
      '';
    };

    rate = lib.mkOption {
      type = lib.types.ints.positive;
      default = 4;
      description = ''
        Sustained new connections per second allowed from one source address.
      '';
    };

    burst = lib.mkOption {
      type = lib.types.ints.positive;
      default = 20;
      description = ''
        New connections one source address may open before {option}`rate`
        starts applying. Tor clients open several connections when they first
        reach a relay, so a burst well above the rate is normal.
      '';
    };

    timeout = lib.mkOption {
      type = lib.types.str;
      default = "1m";
      example = "10m";
      description = ''
        How long a source address stays tracked after its last connection
        attempt, in nftables time syntax. Entries are pruned on expiry;
        without this the tracking sets would grow without bound.
      '';
    };

    maxTrackedSources = lib.mkOption {
      type = lib.types.ints.positive;
      default = 131072;
      description = ''
        Upper bound on tracked source addresses per address family. Once the
        set is full new sources are not tracked, so they are not limited
        either — the relay keeps serving rather than failing closed.
      '';
    };

    logDropped = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Log dropped connection attempts.

        ::: {.warning}
        Log entries contain the source IP addresses of clients, which on a Tor
        relay are the addresses of the people using it. Off by default for
        that reason.
        :::
      '';
    };

    connections = {
      maxPerAddress = lib.mkOption {
        type = lib.types.ints.positive;
        default = 1;
        description = "Concurrent connections allowed from an ordinary source address. New ones above this are dropped.";
      };
      banAfterRefused = lib.mkOption {
        type = lib.types.ints.positive;
        default = 10;
        description = ''
          A connection above the limit is dropped. A source that keeps
          asking after being refused, more than this many times and then more
          than this many per minute, is blocked for {option}`blockFor`.
        '';
      };
      maxPerTwoInstanceAddress = lib.mkOption {
        type = lib.types.ints.positive;
        default = 2;
        description = ''
          Concurrent connections allowed from addresses listed in
          {option}`twoInstanceAddresses` (relays running two Tor instances on
          one address). Above this the source is blocked.
        '';
      };
      maxPerManyInstanceAddress = lib.mkOption {
        type = lib.types.ints.positive;
        default = 4;
        description = ''
          Concurrent connections allowed from addresses listed in
          {option}`manyInstanceAddresses`. Above this the source is blocked.
        '';
      };
      blockFor = lib.mkOption {
        type = lib.types.str;
        default = "12h";
        description = "How long a blocked source stays blocked, in nftables time syntax.";
      };
      maxBlocked = lib.mkOption {
        type = lib.types.ints.positive;
        default = 65536;
        description = "Upper bound on blocked addresses per address family.";
      };
      allowedAddresses = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "192.0.2.10" "2001:db8::/32" ];
        description = "Sources never limited or blocked. Addresses or prefixes, IPv4 and IPv6 mixed.";
      };
      includeAuthorities = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Also exempt the Tor directory authorities (a snapshot of the consensus of 2026-10-19; see {option}`lists.enable` to keep it current).";
      };
      twoInstanceAddresses = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "Relays known to run two Tor instances on one address. Allowed {option}`maxPerTwoInstanceAddress` connections.";
      };
      manyInstanceAddresses = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "Relays known to run three or more Tor instances on one address. Allowed {option}`maxPerManyInstanceAddress` connections.";
      };
    };

    lists = {
      enable = lib.mkEnableOption ''
        refreshing the allow and multi-instance address sets from published
        relay lists. Opt-in: the module otherwise fetches nothing at runtime.
        If a fetch fails the sets keep their last contents, so the relay
        never loses protection because a list is unreachable
      '';
      baseUrl = lib.mkOption {
        type = lib.types.str;
        default = "https://enovamaker.github.io/tor-relay-lists/";
        description = "Directory serving authorities-v4.txt, 2-or.txt, above2-or.txt and their -v6 counterparts.";
      };
      interval = lib.mkOption {
        type = lib.types.str;
        default = "30min";
        description = "How often to refresh, in systemd time syntax.";
      };
    };

    kernelTuning.enable = lib.mkEnableOption ''
      the kernel network settings the `tor-ddos` documentation recommends for a
      relay under many connections (shorter FIN timeout, SYN cookies, a wider
      local port range, a larger SYN backlog). Off by default because it
      changes system-wide behaviour'';
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.orPorts != [ ];
        message = "services.tor.antiDoS.orPorts must list at least one port.";
      }
      {
        assertion = config.networking.nftables.enable;
        message = ''
          services.tor.antiDoS needs networking.nftables.enable = true.

          It is not enabled for you: switching the firewall backend on a
          running relay is not a side effect this option should have.
        '';
      }
      {
        assertion = cfg.burst >= cfg.rate;
        message = ''
          services.tor.antiDoS.burst (${toString cfg.burst}) is below rate
          (${toString cfg.rate}), so the burst allowance is never reached.
        '';
      }
    ];

    networking.nftables.tables.tor-antidos = {
      family = "inet";
      content = ''
        ${lib.optionalString useRate ''
          # Both sets carry a timeout: without one they grow for every source
          # address ever seen and are never pruned, which on a busy relay is a
          # slow memory leak rather than a defence.
          set flooders-v4 {
            type ipv4_addr
            flags dynamic
            timeout ${cfg.timeout}
            size ${toString cfg.maxTrackedSources}
          }

          set flooders-v6 {
            type ipv6_addr
            flags dynamic
            timeout ${cfg.timeout}
            size ${toString cfg.maxTrackedSources}
          }
        ''}
        ${lib.optionalString useConn ''
          ${addrSet "allow" "v4" (v4Of allowAll)}
          ${addrSet "allow" "v6" (v6Of allowAll)}
          ${addrSet "two" "v4" (v4Of c.twoInstanceAddresses)}
          ${addrSet "two" "v6" (v6Of c.twoInstanceAddresses)}
          ${addrSet "many" "v4" (v4Of c.manyInstanceAddresses)}
          ${addrSet "many" "v6" (v6Of c.manyInstanceAddresses)}
          ${blockedSet "v4"}
          ${blockedSet "v6"}
          ${lib.concatMapStrings (n: meter n "v4" + meter n "v6") [ "refused" "cc-single" "cc-two" "cc-many" ]}

          ${refuseChain "v4" "ip saddr"}
          ${refuseChain "v6" "ip6 saddr"}

          chain connlimit {
            ${connRules "v4" "ip saddr"}
            ${connRules "v6" "ip6 saddr"}
          }

          # Before the packet reaches the local stack, and after connection
          # tracking, so the counters see it.
          chain prerouting {
            type filter hook prerouting priority mangle; policy accept;
            tcp dport ${portSet} jump connlimit
          }
        ''}
        chain input {
          type filter hook input priority filter - 100; policy accept;

          ${lib.optionalString useConn ''
            # Close what a blocked source already had open: the first packet it
            # sends gets a reset instead of waiting for a timeout.
            tcp dport ${portSet} ip saddr @blocked-v4 reject with tcp reset
            tcp dport ${portSet} ip6 saddr @blocked-v6 reject with tcp reset
          ''}
          ${lib.optionalString useRate ''
            ct state established,related accept
            iifname "lo" accept

            ${familyRules "v4" "ip saddr"}
            ${familyRules "v6" "ip6 saddr"}
          ''}
        }
      '';
    };

    boot.kernel.sysctl = lib.mkIf cfg.kernelTuning.enable {
      "net.ipv4.tcp_fin_timeout" = lib.mkDefault 20;
      "net.ipv4.tcp_keepalive_time" = lib.mkDefault 1200;
      "net.ipv4.tcp_syncookies" = lib.mkDefault 1;
      "net.ipv4.tcp_tw_reuse" = lib.mkDefault 1;
      "net.ipv4.ip_local_port_range" = lib.mkDefault "10000 65000";
      "net.ipv4.tcp_max_syn_backlog" = lib.mkDefault 8192;
      "net.ipv4.tcp_max_tw_buckets" = lib.mkDefault 5000;
    };

    systemd.services.tor-antidos-lists = lib.mkIf (cfg.lists.enable && useConn) {
      description = "Refresh the Tor anti-DoS address sets";
      after = [ "network-online.target" "nftables.service" ];
      wants = [ "network-online.target" ];
      path = [ pkgs.curl pkgs.nftables pkgs.coreutils pkgs.gnugrep ];
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_NETLINK" ];
      };
      script = ''
        base=${lib.escapeShellArg cfg.lists.baseUrl}
        refresh() { # file set-name family
          body=$(curl -fsS --max-time 60 "$base$1.txt") || { echo "fetch of $1 failed; set $2 left as it was"; return 0; }
          addrs=$(printf '%s\n' "$body" | grep -E '^[0-9a-fA-F.:/]+$' || true)
          # A short or empty list would silently remove protection: refuse it.
          [ "$(printf '%s\n' "$addrs" | grep -c .)" -ge "$4" ] || { echo "$1 has too few entries; set $2 left as it was"; return 0; }
          {
            echo "flush set inet tor-antidos $2"
            echo "add element inet tor-antidos $2 { $(printf '%s\n' "$addrs" | paste -sd, -) }"
          } | nft -f -
        }
        refresh authorities-v4 allow-v4 v4 5
        refresh authorities-v6 allow-v6 v6 4
        refresh 2-or two-v4 v4 1
        refresh 2-or-v6 two-v6 v6 1
        refresh above2-or many-v4 v4 1
        refresh above2-or-v6 many-v6 v6 1
      '';
    };
    systemd.timers.tor-antidos-lists = lib.mkIf (cfg.lists.enable && useConn) {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "2min";
        OnUnitActiveSec = cfg.lists.interval;
        RandomizedDelaySec = "5min";
      };
    };
  };
}
