# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Delfim Leite
#
# Tests for mode = "connections": concurrent-connection limit, temporary
# blocking of a source that keeps asking, reset of what a blocked source had
# open, exemptions, and the two-instance tier. Three clients, because every
# behaviour here is per source address.
{ pkgs, module }:

let
  # One scenario script, run on a client against one address.
  #   hold N   open N connections one after another, keep them all open
  #   flood    after N, keep asking K more times
  #   probe    report whether an old connection was reset
  scenario = pkgs.writeText "scenario.py" ''
    import json, socket, sys
    addr, port, want, extra = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET

    def connect():
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect((addr, port))
            return s
        except OSError:
            s.close()
            return None

    held, got = [], []
    for _ in range(want):
        s = connect()
        got.append(s is not None)
        if s: held.append(s)
    refused = []
    for _ in range(extra):
        s = connect()
        refused.append(s is not None)
        if s: held.append(s)
    reset = None
    if held:
        try:
            held[0].send(b"x")
            held[0].settimeout(3)
            d = held[0].recv(10)
            reset = (d == b"")
        except (ConnectionResetError, BrokenPipeError):
            reset = True
        except OSError:
            reset = False
    print(json.dumps({"wanted": got, "extra": refused, "old_connection_reset": reset}))
  '';

  clientBase = { pkgs, ... }: {
    environment.systemPackages = [ pkgs.python3 ];
  };
in
pkgs.testers.runNixOSTest {
  name = "tor-anti-dos-connections";

  nodes = {
    relay = { lib, pkgs, nodes, ... }: {
      imports = [ module ];

      networking.nftables.enable = true;
      networking.firewall.allowedTCPPorts = [ 19001 ];

      services.tor.antiDoS = {
        enable = true;
        mode = "connections";
        orPorts = [ 19001 ];
        connections = {
          banAfterRefused = 3;
          blockFor = "1h";
          allowedAddresses = [
            nodes.clientb.networking.primaryIPAddress
            nodes.clientb.networking.primaryIPv6Address
          ];
          twoInstanceAddresses = [ nodes.clientc.networking.primaryIPAddress ];
        };
      };

      # Holds each connection open: the module counts concurrent connections,
      # so a listener that answers and hangs up would never be counted.
      systemd.services.fake-orport = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart =
          "${lib.getExe' pkgs.socat "socat"} TCP6-LISTEN:19001,fork,reuseaddr,ipv6only=0 SYSTEM:'sleep 300'";
      };
    };

    client = clientBase;
    clientb = clientBase;
    clientc = clientBase;
  };

  testScript = ''
    import json

    start_all()
    relay.wait_for_unit("nftables.service")
    relay.wait_for_open_port(19001)
    for m in (client, clientb, clientc):
        m.wait_for_unit("multi-user.target")

    v4 = client.succeed("getent ahostsv4 relay | head -1 | cut -d' ' -f1").strip()
    v6 = client.succeed("getent ahostsv6 relay | head -1 | cut -d' ' -f1").strip()

    def run(machine, addr, want, extra):
        out = machine.succeed(f"python3 ${scenario} {addr} 19001 {want} {extra}")
        return json.loads(out)

    with subtest("the ruleset is loaded with the connection sets"):
        rs = relay.succeed("nft list table inet tor-antidos")
        for name in ["blocked-v4", "allow-v4", "two-v4", "many-v4", "refused-v4", "cc-single-v4"]:
            assert name in rs, name

    with subtest("the blocked set expires, so it cannot grow without bound"):
        assert "timeout 1h" in relay.succeed("nft list set inet tor-antidos blocked-v4")

    for family, addr in [("v4", v4), ("v6", v6)]:
        with subtest(f"an ordinary source keeps one connection, the rest are refused (IP{family})"):
            r = run(client, addr, 1, 1)
            assert r["wanted"] == [True], r
            assert r["extra"] == [False], r

    with subtest("a source that keeps asking is blocked, and what it had open is reset"):
        # The earlier runs closed their connections; start clean per family.
        for family, addr in [("v4", v4), ("v6", v6)]:
            client.succeed("sleep 2")
            r = run(client, addr, 1, 8)
            assert r["wanted"] == [True], r
            assert not any(r["extra"]), r
            assert r["old_connection_reset"] is True, r
            # The address the relay actually sees: the one the route to it uses.
            ip = client.succeed(
                f"ip -o -{family[1]} route get {addr} | grep -o 'src [0-9a-f.:]*' | cut -d' ' -f2"
            ).strip()
            assert ip in relay.succeed(f"nft list set inet tor-antidos blocked-{family}"), (ip, family)

    with subtest("a blocked source stays blocked even with nothing open"):
        r = run(client, v4, 1, 0)
        assert r["wanted"] == [False], r

    with subtest("an allowed source is never limited"):
        for addr in (v4, v6):
            r = run(clientb, addr, 6, 0)
            assert all(r["wanted"]), r

    with subtest("a two-instance source gets two connections, not three"):
        r = run(clientc, v4, 2, 1)
        assert r["wanted"] == [True, True], r
        assert r["extra"] == [False], r
  '';
}
