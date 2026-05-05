# C2 Dataset Capture Runbook

This runbook is for phase 3/4 dataset collection. It captures only the
C2-driven botnet scenarios from `Traffic/attack_scripts_C2.sh`; do not use
the direct `hping3` script for onset prediction.

## Capture Design

Capture one run as one folder under `captures/<RUN_ID>/`.

Use these three vantage points:

| Capture point | Router/interface | Files |
|---|---|---|
| Datacenter ingress | `Rdc-eth1` | `dc_ingress.pcap` |
| Per-ISP egress | `R1-eth1` ... `R6-eth1` | `R1_egress.pcap` ... `R6_egress.pcap` |
| C2 uplink | `Rc2-eth1` | `c2_uplink.pcap` |

`Rdc-eth1` is the core-facing datacenter uplink in `topology/topo.py`.
If you want the older target-gateway view from `docs/TESTING.md`, capture
`Rdc-eth0` as an additional file, but keep `Rdc-eth1` as the canonical
datacenter-ingress capture.

The ML label is `phase`:

- `normal`: no attack now and not inside the forecast horizon.
- `pre_attack`: before the attack, within `--forecast-horizon` seconds.
- `attack`: attack is currently running.
- `post_attack`: after the attack finished.

## One-Time WSL Setup

Run on the WSL/Mininet VM host shell:

```bash
cd ~/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch tcpdump tshark curl dnsutils iputils-ping python3
chmod +x Traffic/normal_traffic.sh Traffic/attack_scripts_C2.sh
```

## Terminal 1: Start the Topology

Leave this terminal at the `mininet>` prompt.

```bash
cd ~/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic
sudo mn -c
sudo python3 topology/topo.py
```

Optional quick sanity checks inside `mininet>`:

```text
botA1 ping -c 2 10.0.100.10
botA1 ping -c 2 10.0.200.10
normalA1 ping -c 2 -W 2 10.0.200.10
```

Expected: bot to target and bot to C2 work; normal host to C2 is blocked.

## Terminal 2: Start Normal Traffic

```bash
cd ~/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic
sudo Traffic/normal_traffic.sh start
sudo Traffic/normal_traffic.sh status
```

## Terminal 2: Capture One C2-Driven Attack Run

Change `SCENARIO` for each run. Valid scenarios:

```text
tcp-low tcp-medium tcp-high
udp-low udp-medium udp-high
http-low http-medium http-high
icmp mixed
```

Recommended first set:

```text
udp-low udp-medium udp-high tcp-low tcp-medium tcp-high http-medium icmp mixed
```

Copy-paste this block for one run:

```bash
cd ~/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic

SCENARIO=udp-low
ATTACK_DURATION=60
PRE_ATTACK_DELAY=25
POST_ATTACK_DELAY=15
RUN_ID="c2__${SCENARIO}__${ATTACK_DURATION}s__$(date +%Y%m%d_%H%M%S)"
OUTDIR="captures/${RUN_ID}"
mkdir -p "$OUTDIR"

ns_pid() { pgrep -f "mininet:$1$" 2>/dev/null | head -n 1; }

RUN_START_EPOCH=$(date +%s.%N)

sudo mnexec -a "$(ns_pid Rdc)" tcpdump -i Rdc-eth1 -nn -s 0 -U -Z root \
  -w "$OUTDIR/dc_ingress.pcap" 'host 10.0.100.10' &
echo $! > "$OUTDIR/tcpdump.pids"

sudo mnexec -a "$(ns_pid Rc2)" tcpdump -i Rc2-eth1 -nn -s 0 -U -Z root \
  -w "$OUTDIR/c2_uplink.pcap" '(host 10.0.200.10 or port 6667)' &
echo $! >> "$OUTDIR/tcpdump.pids"

for r in R1 R2 R3 R4 R5 R6; do
  sudo mnexec -a "$(ns_pid "$r")" tcpdump -i "${r}-eth1" -nn -s 0 -U -Z root \
    -w "$OUTDIR/${r}_egress.pcap" '(host 10.0.100.10 or host 10.0.200.10 or port 6667)' &
  echo $! >> "$OUTDIR/tcpdump.pids"
done

sleep 3
sudo Traffic/attack_scripts_C2.sh start
sleep "$PRE_ATTACK_DELAY"

ATTACK_START_EPOCH=$(date +%s.%N)
sudo Traffic/attack_scripts_C2.sh "$SCENARIO" "$ATTACK_DURATION"

sleep "$POST_ATTACK_DELAY"
RUN_END_EPOCH=$(date +%s.%N)

while read -r pid; do sudo kill -2 "$pid" 2>/dev/null || true; done < "$OUTDIR/tcpdump.pids"
sleep 3
sudo pkill -2 tcpdump 2>/dev/null || true

cat > "$OUTDIR/run_meta.env" <<EOF
RUN_ID=$RUN_ID
SCENARIO=$SCENARIO
ATTACK_DURATION=$ATTACK_DURATION
PRE_ATTACK_DELAY=$PRE_ATTACK_DELAY
POST_ATTACK_DELAY=$POST_ATTACK_DELAY
RUN_START_EPOCH=$RUN_START_EPOCH
ATTACK_START_EPOCH=$ATTACK_START_EPOCH
RUN_END_EPOCH=$RUN_END_EPOCH
TARGET_IP=10.0.100.10
C2_IP=10.0.200.10
EOF

ls -lh "$OUTDIR"/*.pcap
```

Keep C2 running if you are collecting another scenario immediately. Stop it
only when all runs are finished:

```bash
sudo Traffic/attack_scripts_C2.sh stop
```

## Baseline Normal-Only Run

Collect at least one normal-only run with normal traffic enabled and no C2
attack command. This gives the model clean negative windows.

```bash
cd ~/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic

SCENARIO=none
RUN_SECONDS=120
RUN_ID="normal_only__${RUN_SECONDS}s__$(date +%Y%m%d_%H%M%S)"
OUTDIR="captures/${RUN_ID}"
mkdir -p "$OUTDIR"

ns_pid() { pgrep -f "mininet:$1$" 2>/dev/null | head -n 1; }
RUN_START_EPOCH=$(date +%s.%N)

sudo mnexec -a "$(ns_pid Rdc)" tcpdump -i Rdc-eth1 -nn -s 0 -U -Z root \
  -w "$OUTDIR/dc_ingress.pcap" 'host 10.0.100.10' &
echo $! > "$OUTDIR/tcpdump.pids"

sudo mnexec -a "$(ns_pid Rc2)" tcpdump -i Rc2-eth1 -nn -s 0 -U -Z root \
  -w "$OUTDIR/c2_uplink.pcap" '(host 10.0.200.10 or port 6667)' &
echo $! >> "$OUTDIR/tcpdump.pids"

for r in R1 R2 R3 R4 R5 R6; do
  sudo mnexec -a "$(ns_pid "$r")" tcpdump -i "${r}-eth1" -nn -s 0 -U -Z root \
    -w "$OUTDIR/${r}_egress.pcap" '(host 10.0.100.10 or host 10.0.200.10 or port 6667)' &
  echo $! >> "$OUTDIR/tcpdump.pids"
done

sleep "$RUN_SECONDS"
RUN_END_EPOCH=$(date +%s.%N)

while read -r pid; do sudo kill -2 "$pid" 2>/dev/null || true; done < "$OUTDIR/tcpdump.pids"
sleep 3
sudo pkill -2 tcpdump 2>/dev/null || true

cat > "$OUTDIR/run_meta.env" <<EOF
RUN_ID=$RUN_ID
SCENARIO=$SCENARIO
RUN_START_EPOCH=$RUN_START_EPOCH
RUN_END_EPOCH=$RUN_END_EPOCH
TARGET_IP=10.0.100.10
C2_IP=10.0.200.10
EOF

ls -lh "$OUTDIR"/*.pcap
```

## Convert PCAPs to the ML CSV

For an attack run:

```bash
cd ~/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic
source captures/<RUN_ID>/run_meta.env
mkdir -p dataset/processed

RUN_DURATION=$(python3 -c "print(float('$RUN_END_EPOCH') - float('$RUN_START_EPOCH'))")

python3 pipeline/pcap_to_ml_windows.py \
  --pcap-dir "captures/$RUN_ID" \
  --out "dataset/processed/${RUN_ID}.windows_1s.csv" \
  --scenario-id "$SCENARIO" \
  --run-start-epoch "$RUN_START_EPOCH" \
  --run-duration "$RUN_DURATION" \
  --attack-start-epoch "$ATTACK_START_EPOCH" \
  --attack-duration "$ATTACK_DURATION" \
  --forecast-horizon 10
```

For a normal-only run:

```bash
cd ~/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic
source captures/<RUN_ID>/run_meta.env
mkdir -p dataset/processed

RUN_DURATION=$(python3 -c "print(float('$RUN_END_EPOCH') - float('$RUN_START_EPOCH'))")

python3 pipeline/pcap_to_ml_windows.py \
  --pcap-dir "captures/$RUN_ID" \
  --out "dataset/processed/${RUN_ID}.windows_1s.csv" \
  --scenario-id none \
  --run-start-epoch "$RUN_START_EPOCH" \
  --run-duration "$RUN_DURATION" \
  --attack-duration 0 \
  --forecast-horizon 10
```

Combine all generated window CSVs:

```bash
python3 - <<'PY'
from pathlib import Path
import csv

files = sorted(Path("dataset/processed").glob("*.windows_1s.csv"))
out = Path("dataset/processed/windows_1s_all.csv")
out.parent.mkdir(parents=True, exist_ok=True)

with out.open("w", newline="") as fout:
    writer = None
    for path in files:
        with path.open(newline="") as fin:
            reader = csv.DictReader(fin)
            if writer is None:
                writer = csv.DictWriter(fout, fieldnames=reader.fieldnames)
                writer.writeheader()
            for row in reader:
                writer.writerow(row)

print(f"combined {len(files)} file(s) -> {out}")
PY
```

## Cleanup

When all captures are done:

```bash
sudo Traffic/attack_scripts_C2.sh stop
sudo Traffic/normal_traffic.sh stop
sudo pkill -2 tcpdump 2>/dev/null || true
sudo mn -c
```
