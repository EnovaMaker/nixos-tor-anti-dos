# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Delfim Leite
#
# Two nodes, because the module deliberately exempts loopback: a test that
# connected over "lo" would pass without ever touching the rules.
{ pkgs, module }:

pkgs.testers.runNixOSTest {
  name = "tor-anti-dos";

  nodes = {
    relay = { lib, pkgs, ... }: {
      imports = [ module ];

      networking.nftables.enable = true;
      networking.firewall.allowedTCPPorts = [ 19001 ];

      # Deliberately tiny so the limit is observable in a test. Real relays
      # want the defaults; see the burst option's description.
      services.tor.antiDoS = {
        enable = true;
        orPorts = [ 19001 ];
        rate = 1;
        burst = 4;
      };

      # Stand-in for tor itself: the module only ever sees a TCP port.
      # ipv6only=0 so one listener serves both families - with an IPv4-only
      # listener every IPv6 connection fails for want of a listener, and the
      # IPv6 subtest would pass without the rate limit doing anything.
      systemd.services.fake-orport = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart =
          "${lib.getExe' pkgs.socat "socat"} TCP6-LISTEN:19001,fork,reuseaddr,ipv6only=0 SYSTEM:'echo ok'";
      };
    };

    client = { ... }: { };
  };

  testScript = ''
    import re

    start_all()
    relay.wait_for_unit("nftables.service")
    relay.wait_for_open_port(19001)
    client.wait_for_unit("multi-user.target")

    v4 = client.succeed("getent ahostsv4 relay | head -1 | cut -d' ' -f1").strip()
    v6 = client.succeed("getent ahostsv6 relay | head -1 | cut -d' ' -f1").strip()
    print(f"relay is {v4} / {v6}")

    def dropped(family):
        """Packets the drop rule for one address family has counted so far."""
        line = relay.succeed(
            f"nft -a list table inet tor-antidos | grep 'flooders-{family}' | grep counter"
        )
        m = re.search(r"counter packets (\d+)", line)
        assert m is not None, line
        return int(m.group(1))

    def flood(addr, n, timeout=3):
        """Connections that got through, out of n attempted at once.

        The attempts run concurrently on purpose. A sequential loop paces
        itself at one attempt per timeout, which for a limit of one per
        second is the same speed the token bucket refills - so it measures
        the loop rather than the limit.
        """
        out = client.succeed(
            f"(for i in $(seq 1 {n}); do "
            f"(timeout {timeout} bash -c '</dev/tcp/{addr}/19001' >/dev/null 2>&1 "
            f"&& echo x) & done; wait) | wc -l"
        )
        return int(out.strip())

    def serial(addr, n, timeout=5):
        """Connections that got through, one after another."""
        out = client.succeed(
            f"ok=0; for i in $(seq 1 {n}); do "
            f"timeout {timeout} bash -c '</dev/tcp/{addr}/19001' 2>/dev/null "
            f"&& ok=$((ok+1)); done; echo $ok"
        )
        return int(out.strip())

    with subtest("the table is loaded, not merely generated"):
        ruleset = relay.succeed("nft list table inet tor-antidos")
        assert "19001" in ruleset, ruleset
        assert "limit rate over 1/second" in ruleset, ruleset

    with subtest("the tracking sets expire, so they cannot grow without bound"):
        # A set with no timeout keeps every source address it ever saw.
        for family in ["v4", "v6"]:
            spec = relay.succeed(f"nft list set inet tor-antidos flooders-{family}")
            assert "timeout" in spec, spec

    with subtest("loopback is exempt, so the relay can still talk to itself"):
        relay.succeed("timeout 5 bash -c '</dev/tcp/127.0.0.1/19001'")

    for family, addr in [("v4", v4), ("v6", v6)]:
        with subtest(f"the IP{family} burst allowance is per source, not a global cap"):
            # Four back-to-back connections must all survive. A single global
            # token bucket shared by every client would drop legitimate
            # traffic here, and would take a busy guard relay offline.
            got = serial(addr, 4)
            assert got == 4, f"IP{family}: only {got}/4 of the burst got through"
            # The limit is per second, so let the bucket refill before the
            # next family reuses it.
            client.succeed("sleep 6")

    # Each family is checked on its own: the first version of this test only
    # ever reached the relay over IPv6, so the IPv4 rule counted zero packets
    # and was never actually exercised.
    for family, addr in [("v4", v4), ("v6", v6)]:
        with subtest(f"a flood over IP{family} is dropped"):
            before = dropped(family)
            got = flood(addr, 40)
            after = dropped(family)

            assert after > before, (
                f"the IP{family} rule counted no drops: {before} -> {after}"
            )
            # All 40 arrive at once, so only the burst of 4 plus whatever the
            # bucket refills during the attempt should survive. A number near
            # 40 means the limit is not biting; a number near 26 would mean
            # the flood is being paced by the test instead of the module.
            assert got <= 12, f"IP{family}: {got}/40 got through, limit not biting"
            print(f"IP{family}: {got}/40 survived, {after - before} packets dropped")
  '';
}
