# Testing Guide

> Behavioral Analysis and Detection of Simulated Botnet Based DDoS Traffic
> in a Controlled Virtual Environment

A minimal, end-to-end test suite that validates the topology
(`topology/topo.py`) and the botnet scripts (`botnet/c2.py`,
`botnet/bot.py`). Run every test in order — each one builds on the
previous one. A failure tells you exactly which subsystem to inspect.

---

## 0. Setup (once per VM session)

```bash
sudo mn -c                                  # wipe stale Mininet state
cd ~/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic
sudo python3 topology/topo.py               # launches Mininet CLI
```

You should land at the `mininet>` prompt and see the inventory summary:

```
*** Botnet DDoS lab topology
    ISPs          : 6
    Bots          : 45
    Normal hosts  : 37
    ...
```

If the script raises before reaching `mininet>`, the topology itself
is broken — fix that first; the rest of the tests assume the network
is up.

For the C2 + bot tests you need a second tmux pane (or SSH session)
attached to the `c2srv` namespace via `mnexec` — see
[`docs/topology.md`](topology.md) and the running guide.

---

## Test plan at a glance

| #  | Area      | What it proves                                                  |
|----|-----------|-----------------------------------------------------------------|
| 1  | Topology  | LAN connectivity inside one ISP                                 |
| 2  | Topology  | Inter-ISP routing through R-core                                |
| 3  | Topology  | Datacenter reachable from every ISP                             |
| 4  | C2 ACL    | Bots can reach the hidden C2 segment **(positive)**             |
| 5  | C2 ACL    | Normal hosts and the target are blocked from C2 **(negative)**  |
| 6  | Botnet    | C2 server accepts a single bot and lists it                     |
| 7  | Botnet    | All 45 bots register simultaneously                             |
| 8  | Botnet    | Attack command produces real traffic on the target              |
| 9  | Botnet    | `stop` command halts the attack cleanly                         |

Nine tests. ~5 minutes total once the topology is up.

---

## A. Topology tests

### Test 1 — Intra-LAN connectivity

**Goal:** verify that hosts in the same ISP can reach their gateway and
each other through the LAN switch.

```text
mininet> botA1 ping -c 2 10.0.1.1            # bot -> ISP-A gateway
mininet> botA1 ping -c 2 10.0.1.51           # bot -> normal host on same LAN
```

**Expected:** both pings return `0% packet loss`.

**Why it matters:** if this fails, host IPs / default routes /
switch wiring are wrong inside one ISP. Nothing further can work.

---

### Test 2 — Inter-ISP routing

**Goal:** verify that traffic crosses ISP boundaries through R-core.

```text
mininet> botA1 ping -c 2 10.0.5.21           # ISP-A bot -> ISP-E bot
mininet> normalB1 ping -c 2 10.0.6.51        # ISP-B normal -> ISP-F normal
```

**Expected:** `0% packet loss` on both.

**Why it matters:** confirms static routes on every edge router and
on R-core (`docs/topology.md` §8) are installed correctly. If this
fails, run `Rcore ip route` and check the `/24 via 172.16.x.2` lines.

---

### Test 3 — Datacenter reachability

**Goal:** every ISP, including the clean one, can reach the victim.

```text
mininet> botA1   ping -c 2 10.0.100.10       # bot -> target
mininet> normalF1 ping -c 2 10.0.100.10      # clean host -> target
```

**Expected:** `0% packet loss` on both.

**Why it matters:** the attack flow path
(`bot → R<x> → R-core → R-dc → target`) and the legitimate-traffic
path must both work. If this fails, check `Rdc ip route`.

---

## B. C2 isolation tests

These two tests are the **most important** — they prove the
topological + ACL isolation described in `docs/topology.md` §6.

### Test 4 — Bots can reach C2 (positive)

```text
mininet> botA1  ping -c 2 10.0.200.10
mininet> botE15 ping -c 2 10.0.200.10
```

**Expected:** `0% packet loss` on both.

**Why it matters:** the per-ISP `iprange` ACCEPT rules on `Rc2` must
allow every bot range. If a bot can't reach C2, no command will ever
arrive.

---

### Test 5 — Everything else is BLOCKED from C2 (negative)

```text
mininet> normalA1 ping -c 2 -W 2 10.0.200.10   # normal host
mininet> normalF1 ping -c 2 -W 2 10.0.200.10   # clean ISP host
mininet> target   ping -c 2 -W 2 10.0.200.10   # victim
mininet> webdecoy ping -c 2 -W 2 10.0.200.10   # decoy
```

**Expected:** **100 % packet loss** on every line.

**Why it matters:** this is the whole point of the hidden C2 segment.
If any of these succeed, the ACL is broken and the captured C2 PCAP
will be polluted. Inspect with:

```text
mininet> Rc2 iptables -L FORWARD -n -v
```

You should see `policy DROP` and ACCEPT rules only for the bot ranges
(`10.0.1.21-34`, `10.0.2.21-22`, `10.0.3.21-29`, `10.0.4.21-25`,
`10.0.5.21-35`).

---

## C. Botnet behavior tests

For these, leave the Mininet CLI running in pane A, and open a second
shell on the VM (pane B / second SSH session).

### Test 6 — C2 accepts a single bot

> **Ordering rule:** always start the C2 **before** the bots. If bots
> are already running when you (re)start C2, the 45 pending reconnects
> will flood the operator prompt with a wall of `REGISTER`/`ack` log
> lines and make it hard to type commands.

**Pane B**, attach to `c2srv` and run the C2 server. The
`--log-file` + `2>/tmp/c2.err` redirect keeps the `c2>` prompt clean
by sending the info logs to files instead of the terminal:

```bash
C2_PID=$(pgrep -f 'mininet:c2srv')
sudo mnexec -a "$C2_PID" python3 \
    /home/mininet/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic/botnet/c2.py \
    --log-file /tmp/c2.log 2>/tmp/c2.err
```

The terminal will show only `C2 ready. Type 'help' for commands.` and
the `c2>` prompt. Confirm C2 is actually listening in pane A:

```text
mininet> c2srv ss -tlnp | grep 6667
```

You should see a `LISTEN` line on `0.0.0.0:6667`. The
`C2 listening on 0.0.0.0:6667` banner itself is in `/tmp/c2.err`.

**Pane A**, launch one bot:

```text
mininet> botA1 python3 /home/mininet/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic/botnet/bot.py >/tmp/botA1.log 2>&1 &
```

Wait ~10 s, then in pane B:

```text
c2> list
```

**Expected:** the bot is listed with the correct Mininet host name,
not the VM hostname:

```
bot_id       addr                    age(s)  idle(s)
botA1        10.0.1.21:48312            6.4      0.5
-- 1 bot(s) --
```

> **Why `botA1` and not `mininet-vm`?** Mininet creates a new network
> namespace per host but **not** a new UTS namespace, so
> `socket.gethostname()` returns the VM's hostname for every bot. The
> bot script works around this by reading `/sys/class/net/` and using
> the `*-eth0` interface name as its identity. If `c2> list` shows
> `mininet-vm` rows instead of real bot names, your `bot.py` is out of
> date on the VM — re-sync it.

**Why it matters:** confirms the wire protocol (`register` + `ack`)
and the C2 listening socket are working. If the bot does not appear,
check `/tmp/botA1.log` — typical issue is a wrong path to `bot.py`.

---

### Test 7 — All 45 bots register

**Pane A**, kill the test bot first then launch all 45 in one shot:

```text
mininet> py [h.cmd('pkill -9 -f botnet/bot.py') for h in net.hosts if h.name.startswith('bot')]
mininet> py [h.cmd('nohup python3 /home/mininet/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic/botnet/bot.py --log-file /tmp/{}.log >/dev/null 2>&1 &'.format(h.name)) for h in net.hosts if h.name.startswith('bot')]
```

Each `py [...]` returns a list of 45 empty strings — one per backgrounded
bot — which is the normal "success" signature.

Wait ~15 s (bots have 0–5 s startup jitter), then in pane B:

```text
c2> list
```

**Expected:** the footer says `-- 45 bot(s) --`, with every name from
`botA1` … `botE15`.

**Why it matters:** validates the C2 under realistic concurrent load
and confirms every bot host has working routing to `10.0.200.10`.
A missing bot points to that specific host's namespace — check its
log file in `/tmp/`.

---

### Test 8 — Attack produces traffic on the target

**Pane A**, start a capture on the datacenter ingress.

Two notes before launching `tcpdump`:

1. Remove any stale pcap first — on Debian/Ubuntu, tcpdump drops
   privileges to user `tcpdump` after open, so a root-owned file from
   a previous run causes `Permission denied`.
2. Pass `-Z root` so tcpdump keeps root and can write freely.

```text
mininet> sh rm -f /tmp/cap_attack.pcap
mininet> Rdc tcpdump -i Rdc-eth0 -nn -Z root -c 5000 dst host 10.0.100.10 -w /tmp/cap_attack.pcap &
mininet> sh sleep 2
mininet> sh pgrep -af tcpdump            # must show one tcpdump line
```

> Note: we capture on `Rdc-eth0` (the datacenter gateway) rather than
> on `monitor-eth0`. `sdc` is an OVS learning switch, so after it has
> learned `target`'s MAC, frames are unicast to target's port only and
> `monitor` never sees them. The router interface sees every ingress
> packet regardless. If you specifically need `monitor` to sniff,
> force `sdc` into flood mode first:
> `mininet> sh ovs-ofctl mod-flows sdc actions=FLOOD`.

**Pane B**, launch a short, low-rate UDP attack:

```text
c2> attack udp 10.0.100.10 10 100
```

This means: 100 pps × 45 bots × 10 s = ~45 000 packets to `target`
(the capture stops early at 5 000 packets because of `-c 5000`).

Watch pane B — you should see `~45` lines of
`ack ... status=started ...`. Wait ~12 seconds for the attack to
finish.

After the attack ends, inspect in pane A:

```text
mininet> sh ls -l /tmp/cap_attack.pcap
mininet> sh tcpdump -nr /tmp/cap_attack.pcap 2>/dev/null | wc -l
mininet> sh tcpdump -nr /tmp/cap_attack.pcap 2>/dev/null | awk '{print $3}' | awk -F. '{print $1"."$2"."$3".0/24"}' | sort | uniq -c | sort -rn
```

**Expected:**
- Pcap file size in the **MB** range (not bytes/KB).
- Packet count is **5 000** (capped) or several thousand.
- The per-`/24` breakdown lists **exactly five** subnets:
  `10.0.1.0/24`, `10.0.2.0/24`, `10.0.3.0/24`, `10.0.4.0/24`,
  `10.0.5.0/24`. **`10.0.6.0/24` must be absent** — ISP-F is the
  clean control group.
- Roughly proportional counts per ISP (ISP-A 14 bots, ISP-E 15 bots
  → most packets; ISP-B 2 bots → fewest).

**Why it matters:** end-to-end proof that the C2 channel works, the
bots execute the attack, and the many-to-one DDoS pattern from
`docs/topology.md` §1 actually shows up in the dataset.

---

### Test 9 — `stop` halts the attack

**Pane A**, start a live packet log and a long attack from pane B:

```text
mininet> sh rm -f /tmp/live.txt
mininet> Rdc tcpdump -i Rdc-eth0 -nn -Z root -l dst host 10.0.100.10 >/tmp/live.txt 2>&1 &
```

**Pane B**:

```text
c2> attack udp 10.0.100.10 60 100
```

Wait ~5 s, then:

```text
c2> stop
```

**Pane A**, watch the log stop growing:

```text
mininet> sh tail -f /tmp/live.txt
```

**Expected:** packets stop arriving within ~1 s of the `stop` command.
All bots ack with `status=stopped`.

Stop the capture: `Ctrl-C` on the `tail`, then
`mininet> Rdc kill %tcpdump`.

**Why it matters:** confirms the bot's `_stop_attack()` path works
and that `AttackWorker` honours its stop event — important for
dataset hygiene (so consecutive attack runs don't bleed into each
other).

---

## Cleanup

Pane B:

```text
c2> quit
```

Pane A:

```text
mininet> py [h.cmd('pkill -f botnet/bot.py') for h in net.hosts if h.name.startswith('bot')]
mininet> exit
```

Then on the VM:

```bash
sudo mn -c
```

---

## Pass / fail summary

If all nine tests pass you have:

1. A correctly-wired multi-ISP topology with working static routing.
2. A hidden C2 segment that is reachable from bots and **only** from
   bots — provably, by negative test.
3. A working C2 ↔ bot control channel that scales to 45 concurrent
   clients.
4. Real, observable many-to-one DDoS traffic on the target,
   originating from 5 of 6 ISPs (ISP-F clean).
5. Clean attack start / stop semantics.

That is sufficient to start collecting PCAPs for the analysis phase
described in `docs/topology.md` §7.

---

## Troubleshooting — things we hit during bring-up

### Full clean restart (when things are just wedged)

```text
(pane B)   Ctrl-C                                   # exit c2>
(pane A)   mininet> py [h.cmd('pkill -9 -f botnet/bot.py') for h in net.hosts if h.name.startswith('bot')]
(pane A)   mininet> sh pkill -9 -f tcpdump
(pane A)   mininet> sh rm -f /tmp/bot*.log /tmp/c2.log /tmp/c2.err /tmp/cap_*.pcap /tmp/live.txt
(pane A)   mininet> exit
(VM shell) sudo mn -c
(VM shell) sudo python3 topology/topo.py            # back to mininet>
(pane B)   sudo mnexec -a $(pgrep -f mininet:c2srv) python3 \
               /home/mininet/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic/botnet/c2.py \
               --log-file /tmp/c2.log 2>/tmp/c2.err
(pane A)   mininet> py [h.cmd('nohup python3 /home/mininet/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic/botnet/bot.py --log-file /tmp/{}.log >/dev/null 2>&1 &'.format(h.name)) for h in net.hosts if h.name.startswith('bot')]
```

### Restart just the C2 without losing the bots

Freeze the bots so they don't hammer the old address during the gap:

```text
mininet> py [h.cmd('pkill -STOP -f botnet/bot.py') for h in net.hosts if h.name.startswith('bot')]
```

Start the new C2 in pane B, then resume:

```text
mininet> py [h.cmd('pkill -CONT -f botnet/bot.py') for h in net.hosts if h.name.startswith('bot')]
```

### Common issues and fixes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Exception: Unable to derive default datapath ID` | Switch name has no trailing digits | Non-issue in current `topo.py` (`sdc`/`sc2` ship explicit `dpid`). |
| `RTNETLINK answers: File exists` on startup | Leftover veth pairs from a killed run | `sudo mn -c` |
| All bots register as `mininet-vm` | Running stale `bot.py` (pre-fix) | Re-sync `bot.py` to the VM; ID is now derived from `*-eth0` |
| `c2> list` empty but bots "running" | Bots started before C2 was listening and are in exponential back-off | Wait 30 s, or `pkill -9 -f botnet/bot.py` then relaunch |
| `tcpdump: ... Permission denied` on pcap file | Stale `root`-owned pcap vs. tcpdump dropping to user `tcpdump` | `sh rm -f /tmp/cap_*.pcap` and add `-Z root` |
| Capture at `monitor` shows almost no packets | OVS learning switch unicasts to target's port only | Capture on `Rdc-eth0` (router), or `ovs-ofctl mod-flows sdc actions=FLOOD` |
| `c2>` prompt buried under log lines | Logger writes to stderr | Launch C2 with `--log-file /tmp/c2.log 2>/tmp/c2.err` |

### Where to look first when something is wrong

```text
mininet> sh cat /tmp/botA1.log                       # one bot's view
mininet> sh tail /tmp/c2.err                         # C2's view
mininet> c2srv ss -tlnp | grep 6667                  # is C2 listening?
mininet> Rc2 iptables -L FORWARD -n -v               # ACL counters
mininet> sh pgrep -af botnet/bot.py | wc -l          # how many bots alive (expect 45)
```
