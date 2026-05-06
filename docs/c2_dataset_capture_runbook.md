# C2 Dataset Capture Runbook

This runbook is for phase 3/4 dataset collection. It captures only the
C2-driven botnet scenarios from `Traffic/attack_scripts_C2.sh`; do not use
the direct `hping3` script for onset prediction.

## Capture Design

Capture one run as one folder under `captures/<RUN_ID>/`.

Use these eight vantage points:

| Capture point | Router/interface | File |
|---|---|---|
| Datacenter ingress | `Rdc-eth1` | `dc_ingress.pcap` |
| Per-ISP egress | `R1-eth1` ... `R6-eth1` | `R1_egress.pcap` ... `R6_egress.pcap` |
| C2 uplink | `Rc2-eth1` | `c2_uplink.pcap` |

`Rdc-eth1` is the core-facing datacenter uplink in `topology/topo.py`.
If you want the older target-gateway view from `docs/TESTING.md`, capture
`Rdc-eth0` as an additional file, but keep `Rdc-eth1` as the canonical
datacenter-ingress capture.

### ML labels (3-class phase, secondary attack_family)

This dataset trains **two stacked models**:

- **Primary detector** -> `phase` in `{normal, pre_attack, attack}`.
- **Secondary classifier** (only on attack rows) -> `attack_family` in
  `{tcp, udp, icmp, http, mixed}`.

There is **no** `post_attack` class: windows after `attack_end` fold back
into `normal`. The defender goal is *early* detection during ramp-up,
not forensic decay analysis.

### Pre-attack ramp

Every scenario is preceded by a 10 s ramp emitted by
`Traffic/attack_scripts_C2.sh` (see `RAMP_DURATION` / `RAMP_STEPS`):
5 quadratic-spaced rate steps at **4 / 16 / 36 / 64 / 100 %** of the
scenario's peak rate, 2 s each. This makes `pre_attack` a real,
learnable phase: rolling features (`pps_slope_5s`, `bps_zscore`, ...)
see a slow build-up rather than a single 0 -> peak step. The
`--forecast-horizon` passed to `pipeline/pcap_to_ml_windows.py` **must**
equal `RAMP_DURATION` so the label window aligns with the wire ramp.

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

## Terminal 2: Run the Whole Dataset (recommended)

`Traffic/collect_dataset.sh` automates the full collection: 11 scenarios
* 5 repetitions = 55 captures, plus the per-run PCAP -> CSV conversion
and a final concatenation into `dataset/processed/windows_1s_all.csv`.

From a host shell (not the `mininet>` prompt), with the topology and
normal-traffic generators already up:

```bash
cd ~/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic
chmod +x Traffic/collect_dataset.sh
sudo Traffic/collect_dataset.sh 2>&1 | tee captures/collect.console.log
```

Defaults (override via env vars if needed):

| Variable          | Default | Meaning                                |
|-------------------|--------:|----------------------------------------|
| `REPS`            |       5 | repetitions per scenario               |
| `PRE_NORMAL`      |      30 | seconds of normal traffic per run      |
| `RAMP_DURATION`   |      10 | seconds of ramp (== forecast horizon)  |
| `ATTACK_DURATION` |      60 | seconds of full-rate attack            |
| `FLUSH_GRACE`     |       3 | seconds to flush tcpdump after attack  |

Wall-clock budget: ~110 s/run x 55 runs ~ **100 minutes**.

## Manual Single-Run Capture (debugging only)

Valid scenarios:

```text
tcp-low tcp-medium tcp-high
udp-low udp-medium udp-high
http-low http-medium http-high
icmp mixed
```

Use this block to capture one scenario by hand (the automated script
above is preferred for full dataset collection):

```bash
cd ~/Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic

SCENARIO=udp-low
PRE_NORMAL=30
RAMP_DURATION=10
ATTACK_DURATION=60
FLUSH_GRACE=3
RUN_ID="c2__${SCENARIO}__${ATTACK_DURATION}s__manual__$(date +%Y%m%d_%H%M%S)"
OUTDIR="captures/${RUN_ID}"
mkdir -p "$OUTDIR"

ns_pid() { pgrep -f "mininet:$1$" 2>/dev/null | head -n 1; }

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
sleep 2

sudo Traffic/attack_scripts_C2.sh start
RUN_START_EPOCH=$(date +%s.%N)
sleep "$PRE_NORMAL"

# attack_scripts_C2.sh emits a 10s ramp + ATTACK_DURATION steady-state.
# attack_start = ramp_start + RAMP_DURATION.
RAMP_START_EPOCH=$(date +%s.%N)
ATTACK_START_EPOCH=$(awk -v a="$RAMP_START_EPOCH" -v b="$RAMP_DURATION" 'BEGIN { printf "%.6f\n", a + b }')
sudo Traffic/attack_scripts_C2.sh "$SCENARIO" "$ATTACK_DURATION"

sleep "$FLUSH_GRACE"
RUN_END_EPOCH=$(date +%s.%N)

while read -r pid; do sudo kill -2 "$pid" 2>/dev/null || true; done < "$OUTDIR/tcpdump.pids"
sleep 2
sudo pkill -2 tcpdump 2>/dev/null || true

cat > "$OUTDIR/run_meta.env" <<EOF
RUN_ID=$RUN_ID
SCENARIO=$SCENARIO
PRE_NORMAL=$PRE_NORMAL
RAMP_DURATION=$RAMP_DURATION
ATTACK_DURATION=$ATTACK_DURATION
FLUSH_GRACE=$FLUSH_GRACE
RUN_START_EPOCH=$RUN_START_EPOCH
RAMP_START_EPOCH=$RAMP_START_EPOCH
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

For an attack run captured manually (the automated script does this for
you):

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
  --forecast-horizon "$RAMP_DURATION"   # must equal the ramp emitted by attack_scripts_C2.sh
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
