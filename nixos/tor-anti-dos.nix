# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Delfim Leite
#
# Clean-room implementation. Written from the Tor Project's public relay
# operator documentation and the nftables manual only. No code from any
# existing anti-DoS tool was read while writing this.
{ config, lib, ... }:

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

        chain input {
          type filter hook input priority filter - 100; policy accept;

          ct state established,related accept
          iifname "lo" accept

          ${familyRules "v4" "ip saddr"}
          ${familyRules "v6" "ip6 saddr"}
        }
      '';
    };
  };
}
