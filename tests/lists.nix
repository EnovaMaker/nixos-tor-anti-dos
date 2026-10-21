# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Delfim Leite
#
# The optional list refresher: it must fill the sets, and a bad or short list
# must leave them as they were rather than removing protection.
{ pkgs, module }:

pkgs.testers.runNixOSTest {
  name = "tor-anti-dos-lists";

  nodes.relay = { ... }: {
    imports = [ module ];
    networking.nftables.enable = true;
    services.tor.antiDoS = {
      enable = true;
      mode = "connections";
      orPorts = [ 19001 ];
      connections.allowedAddresses = [ "192.0.2.77" ];
      kernelTuning.enable = true;
      lists = {
        enable = true;
        baseUrl = "file:///run/relay-lists/";
      };
    };
  };

  testScript = ''
    relay.wait_for_unit("nftables.service")

    def stamp(ago):
        return relay.succeed(f"date -u -d '{ago}' '+%a %b %d %Y %H:%M:%S UTC'").strip()

    def publish(name, lines, when="1 hour ago"):
        relay.succeed(f"mkdir -p /run/relay-lists && printf 'Updated:\n{stamp(when)}\n----\n{lines}' > /run/relay-lists/{name}.txt")

    publish("authorities-v4", "10.1.0.1\n10.1.0.2\n10.1.0.3\n10.1.0.4\n10.1.0.5\n10.1.0.6\n")
    publish("authorities-v6", "2001:db8::1\n2001:db8::2\n2001:db8::3\n2001:db8::4\n")
    publish("2-or", "10.2.0.1\n")
    publish("2-or-v6", "2001:db8:2::1\n")
    publish("above2-or", "10.3.0.1\n")
    publish("above2-or-v6", "2001:db8:3::1\n")

    with subtest("the refresher fills the sets from the published lists"):
        relay.succeed("systemctl start tor-antidos-lists.service")
        assert "10.1.0.6" in relay.succeed("nft list set inet tor-antidos allow-v4")
        assert "2001:db8::4" in relay.succeed("nft list set inet tor-antidos allow-v6")
        assert "10.2.0.1" in relay.succeed("nft list set inet tor-antidos two-v4")
        assert "10.3.0.1" in relay.succeed("nft list set inet tor-antidos many-v4")

    with subtest("addresses from the configuration and the Snowflake servers survive a refresh"):
        s4 = relay.succeed("nft list set inet tor-antidos allow-v4")
        assert "192.0.2.77" in s4 and "193.187.88.46" in s4 and "141.212.118.18" in s4, s4
        assert "2a0c:dd40:1:b::46" in relay.succeed("nft list set inet tor-antidos allow-v6")

    with subtest("each refresh logs how old a list says it is"):
        out = relay.succeed("journalctl -u tor-antidos-lists.service -o cat")
        assert "authorities-v4: Updated" in out and " h " in out, out
        assert "older than" not in out, out

    with subtest("a list older than warnAfterHours is reported at warning level"):
        publish("authorities-v4", "10.1.0.1\n10.1.0.2\n10.1.0.3\n10.1.0.4\n10.1.0.5\n10.1.0.6\n", when="8 hours ago")
        relay.succeed("systemctl start tor-antidos-lists.service")
        warn = relay.succeed("journalctl -u tor-antidos-lists.service -p warning -o cat")
        assert "authorities-v4: Updated" in warn and "older than 6 h" in warn, warn

    with subtest("a list without a readable Updated line says so instead of guessing"):
        relay.succeed("printf 'Updated:\nx\n----\n10.1.0.1\n10.1.0.2\n10.1.0.3\n10.1.0.4\n10.1.0.5\n10.1.0.6\n' > /run/relay-lists/authorities-v4.txt")
        relay.succeed("systemctl start tor-antidos-lists.service")
        warn = relay.succeed("journalctl -u tor-antidos-lists.service -p warning -o cat")
        assert "authorities-v4: no readable Updated line" in warn, warn

    with subtest("a list that is too short leaves the set as it was"):
        publish("authorities-v4", "10.9.9.9\n")
        relay.succeed("systemctl start tor-antidos-lists.service")
        s = relay.succeed("nft list set inet tor-antidos allow-v4")
        assert "10.1.0.6" in s and "10.9.9.9" not in s, s

    with subtest("an unreachable list leaves the set as it was"):
        relay.succeed("rm /run/relay-lists/2-or.txt")
        relay.succeed("systemctl start tor-antidos-lists.service")
        assert "10.2.0.1" in relay.succeed("nft list set inet tor-antidos two-v4")

    with subtest("kernel tuning is applied when asked for"):
        assert relay.succeed("sysctl -n net.ipv4.tcp_fin_timeout").strip() == "20"
  '';
}
