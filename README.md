# nixos-tor-anti-dos

**Per-source rate limiting for a Tor relay's ORPort, declared once and tested in a VM.**

```nix
services.tor.antiDoS = {
  enable = true;
  orPorts = [ 19001 ];   # must match services.tor.settings.ORPort
};
```

That generates an `inet tor-antidos` nftables table with one dynamic set per address family and a
`limit rate over ... drop` rule for each.

---

## Why this exists

**This is not a second tool competing with a working one. It picks up a job that operators still
need and that nobody is doing any more.**

The demand is not hypothetical. `Enkidu-6/tor-ddos` — iptables rules for exactly this problem —
has **77 stars and 9 forks**. Relay operators were using it.

On 2 May 2026 its author wrote to the `tor-relays` list to say they were shutting it down, along
with `Enkidu-6/tor-relay-lists`, and that nobody had offered to take either over. Nobody has since.
Both repositories are still up and unarchived, but `tor-ddos` has not been touched since December
2024, and the services that fed the relay lists went down in May. **Not one of the forks has a
single star** — forking preserved the files and continued nothing. The three tools that followed,
`orport-guard`, `Cerberus` and `EndGameV3`, are in the same position.

The obvious answer would have been to adopt it rather than write anything new. **That route is
closed: none of those repositories declares a licence**, which leaves them all-rights-reserved.
However willing anyone is, they cannot legally be forked, continued or maintained.

So the capability continues here and the code does not. Same job — keeping a flood of new
connections from taking a relay off the network — reimplemented from public documentation,
declarative instead of a script to paste, covered by a VM test in CI, and carrying a licence from
its first line, so that this one can change hands if it ever needs to.

---

## The design decision that matters

**The limit is per source address, not global.**

```
per source (correct):  every client gets its own bucket
global     (wrong):    5 new connections/second in total, for everyone
```

A busy guard relay legitimately handles far more than a few new connections per second in
aggregate, from thousands of clients. **A global limit takes the relay off the network** — it
protects it from working. The subtest named `the burst allowance is per source, not a global cap`
exists to catch exactly that.

---

## Options

| Option | Default | |
|---|---|---|
| `orPorts` | **none** | Deliberate: protecting the wrong port does not fail, it silently does nothing |
| `rate` | `4` | New connections per second, per source address |
| `burst` | `20` | A Tor client opens several connections on arrival; the burst must absorb that |
| `timeout` | `"1m"` | How long a source stays tracked. **Without it the sets grow without bound** |
| `maxTrackedSources` | `131072` | Once full, new sources are not tracked — the relay keeps serving |
| `logDropped` | `false` | ⚠️ Logs contain the addresses of **the people using the relay**. Off for that reason |

**It does not enable `networking.nftables` for you.** Switching a running relay's firewall backend
is not a side effect a sub-option should have; there is an assertion saying so.

---

## The known limitation: shared NAT

**A per-address limit treats an entire CGNAT pool as one client.**

```
1 public IPv4 address  ->  thousands of users behind it
the module sees        ->  one source, with burst 20 and 4/s
```

⚠️ **This is worse here than for most services.** People reaching a Tor bridge are
disproportionately on networks where CGNAT is the norm, so the limit can throttle exactly the
users the relay exists to serve — and from their side that is indistinguishable from censorship.

| | |
|---|---|
| **Not a bug in this code** | It is inherent to limiting by address. No firewall rule tells a thousand people behind one NAT apart from a thousand requests from one person |
| **Partial mitigation** | Set `burst` well above what a single client needs. `rate = 4` and `burst = 20` are **not measured numbers** |
| **Fails open** | Once `maxTrackedSources` is full, new sources stop being tracked rather than being dropped |

**This is the main reason to test on a real relay before recommending it to anyone.**

---

## Verification

```
nix flake check
nix build .#checks.x86_64-linux.antidos -L
```

Two nodes, because the module exempts loopback: a test that connected over `lo` would pass without
touching the rules.

| Subtest | What it proves |
|---|---|
| `the table is loaded, not merely generated` | `nft` accepted the rules; Nix did not merely render them |
| `the tracking sets expire` | The sets carry a timeout and cannot grow without bound |
| `loopback is exempt` | The relay can still reach itself |
| `the IPv4/IPv6 burst allowance is per source` | The whole burst survives. **The assertion against a global limit** |
| `a flood over IPv4/IPv6 is dropped` | The drop counter rises **for each family separately** |

```
IPv4: 7/40 survived, 58 packets dropped
IPv6: 7/40 survived, 57 packets dropped
```

`burst` of 4, plus the ~3 tokens the bucket refills during the 3-second window. Drops above 33 are
SYN retransmissions, which `nft` counts individually. The exact figures move by one or two between
runs; what matters is that both families report the same one.

### Three versions of this test passed for the wrong reason

Recorded because it is the most expensive failure mode there is:

| | |
|---|---|
| **1st** | Only ever connected over IPv6. The IPv4 rule counted **zero packets** and was never exercised. Found by reading `nft`'s counter, not from the test |
| **2nd** | `socat` listened on IPv4 only, so every IPv6 connection failed for want of a listener. It reported `0/40` and the `<= 32` assertion passed with the limit doing nothing |
| **3rd** | The flood was **sequential**. Each blocked attempt spent its own timeout, so the loop ran at ~1 connection/second — **exactly the refill rate**. It measured the loop, not the limit |

**Only once both families reported the same numbers was the result worth anything.** The symmetry
is the evidence, not the fact that it passed.

---

## What it does not do

| | Where that already lives |
|---|---|
| Guard-discovery protection | `vanguards` |
| Circuit-level DoS mitigation | **EndGame**, inside Tor ≥ 0.4.7 |
| Relay and exit lists | The onionoo API and `check.torproject.org/torbulkexitlist` |

---

## Provenance

Written from the Tor Project's public relay-operator documentation, the Tor manual, and `man 8
nft`. **No code was read from any existing anti-DoS tool** — see [Why this exists](#why-this-exists)
for why that mattered.

---

## Status

🔴 **Not production-tested.** It evaluates, loads into nftables and passes the VM test. It has
**never run on a real relay**, and the defaults are a defensible starting point rather than a
measured one.

## Licence

MIT — see [`LICENSE`](LICENSE).
