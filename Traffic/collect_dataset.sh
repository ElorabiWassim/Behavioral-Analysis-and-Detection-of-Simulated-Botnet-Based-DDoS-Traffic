#!/usr/bin/env bash
#
# Traffic/collect_dataset.sh
# ============================================================================
# End-to-end dataset collection for the two-stage detector.
#
# For every (scenario, repetition) pair this script:
#   1. starts tcpdump on the 8 vantage points (Rdc, Rc2, R1..R6),
#   2. runs ${PRE_NORMAL}s of pure baseline traffic (label = normal),
#   3. runs ${RAMP_DURATION}s of ramp via attack_scripts_C2.sh
#      (label = pre_attack; rates climb 4 -> 16 -> 36 -> 64 -> 100 % of peak),
#   4. runs ${ATTACK_DURATION}s of full-rate attack (label = attack),
#   5. waits a small flush grace, stops tcpdump,
#   6. writes captures/<RUN_ID>/run_meta.env with the exact epoch markers,
#   7. converts the per-run PCAPs to dataset/processed/<RUN_ID>.windows_1s.csv
#      via pipeline/pcap_to_ml_windows.py,
#   8. moves to the next repetition.
#
# After all runs finish, it concatenates every <RUN_ID>.windows_1s.csv into
# dataset/processed/windows_1s_all.csv (the file the model trainers consume).
#
# Pre-conditions
# --------------
#   - Mininet topology is up:        sudo python3 topology/topo.py
#   - Normal background is running:  sudo Traffic/normal_traffic.sh start
#   - C2 + bots are NOT yet started; this script will start them once and
#     reuse them across all runs to avoid the 20s registration penalty.
#
# Wall-clock budget
# -----------------
#   Per run :  ${PRE_NORMAL}s normal + ${RAMP_DURATION}s ramp +
#              ${ATTACK_DURATION}s attack + ~6s overhead  ~= 110 s
#   Total   :  11 scenarios x 5 reps x 110 s              ~= 100 minutes
#
# Re-runnable: each run gets a unique RUN_ID with a timestamp + rep index,
# and the all-CSV concatenation step is idempotent (always produced from
# whatever per-run CSVs are currently present in dataset/processed/).
# ============================================================================

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ATTACK_SCRIPT="$PROJECT_ROOT/Traffic/attack_scripts_C2.sh"
PIPELINE="$PROJECT_ROOT/pipeline/pcap_to_ml_windows.py"

# --------------------------------------------------------------------------
# User-tunable parameters
# --------------------------------------------------------------------------
SCENARIOS=(
    tcp-low tcp-medium tcp-high
    udp-low udp-medium udp-high
    http-low http-medium http-high
    icmp
    mixed
)
REPS=${REPS:-5}                    # repetitions per scenario
PRE_NORMAL=${PRE_NORMAL:-30}       # seconds of normal traffic per run
RAMP_DURATION=${RAMP_DURATION:-10} # must equal RAMP_DURATION in attack_scripts_C2.sh
ATTACK_DURATION=${ATTACK_DURATION:-60}
FLUSH_GRACE=${FLUSH_GRACE:-3}      # seconds to keep tcpdump running after attack ends

TARGET_IP=${TARGET_IP:-10.0.100.10}
C2_IP=${C2_IP:-10.0.200.10}

CAPTURES_ROOT="$PROJECT_ROOT/captures"
DATASET_DIR="$PROJECT_ROOT/dataset/processed"
COLLECT_LOG="$PROJECT_ROOT/captures/collect.log"

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
log() {
    mkdir -p "$(dirname "$COLLECT_LOG")"
    printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$COLLECT_LOG"
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: must be run as root (sudo)." >&2
        exit 1
    fi
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: '$1' not found.${2:+ $2}" >&2
        exit 1
    }
}

ns_pid() {
    # Mininet sets each host's bash argv[0] to "mininet:<host>". The end
    # anchor avoids "botA1" matching "botA10".
    pgrep -f "mininet:$1\$" 2>/dev/null | head -n 1 || true
}

require_topology() {
    for ns in target c2srv Rdc Rc2 R1 R2 R3 R4 R5 R6; do
        if [[ -z "$(ns_pid "$ns")" ]]; then
            echo "ERROR: namespace '$ns' not found; bring up the topology first:" >&2
            echo "       sudo python3 topology/topo.py" >&2
            exit 1
        fi
    done
}

# --------------------------------------------------------------------------
# Per-run capture pipeline
# --------------------------------------------------------------------------
start_tcpdumps() {
    local outdir="$1"
    local pidfile="$outdir/tcpdump.pids"
    : > "$pidfile"

    sudo mnexec -a "$(ns_pid Rdc)" tcpdump -i Rdc-eth1 -nn -s 0 -U -Z root \
        -w "$outdir/dc_ingress.pcap" 'host '"$TARGET_IP" \
        >/dev/null 2>&1 &
    echo $! >> "$pidfile"

    sudo mnexec -a "$(ns_pid Rc2)" tcpdump -i Rc2-eth1 -nn -s 0 -U -Z root \
        -w "$outdir/c2_uplink.pcap" '(host '"$C2_IP"' or port 6667)' \
        >/dev/null 2>&1 &
    echo $! >> "$pidfile"

    local r
    for r in R1 R2 R3 R4 R5 R6; do
        sudo mnexec -a "$(ns_pid "$r")" tcpdump -i "${r}-eth1" -nn -s 0 -U -Z root \
            -w "$outdir/${r}_egress.pcap" \
            '(host '"$TARGET_IP"' or host '"$C2_IP"' or port 6667)' \
            >/dev/null 2>&1 &
        echo $! >> "$pidfile"
    done
    sleep 2  # let tcpdump settle into the rings
}

stop_tcpdumps() {
    local outdir="$1"
    local pidfile="$outdir/tcpdump.pids"
    if [[ -f "$pidfile" ]]; then
        while read -r pid; do
            [[ -z "$pid" ]] && continue
            sudo kill -2 "$pid" 2>/dev/null || true
        done < "$pidfile"
        sleep 1
        # belt-and-suspenders for any tcpdump that ignored SIGINT
        sudo pkill -2 -f "tcpdump.*$outdir" 2>/dev/null || true
        sleep 1
    fi
}

run_one_capture() {
    local scenario="$1"
    local rep="$2"
    local stamp="$(date +%Y%m%d_%H%M%S)"
    local run_id
    run_id="c2__${scenario}__${ATTACK_DURATION}s__rep${rep}__${stamp}"
    local outdir="$CAPTURES_ROOT/$run_id"
    mkdir -p "$outdir"

    log "----------------------------------------------------------------"
    log "RUN  scenario=$scenario rep=$rep id=$run_id"
    log "----------------------------------------------------------------"

    start_tcpdumps "$outdir"

    local run_start ramp_start attack_start run_end
    run_start=$(date +%s.%N)
    log "phase: NORMAL for ${PRE_NORMAL}s"
    sleep "$PRE_NORMAL"

    ramp_start=$(date +%s.%N)
    # attack_scripts_C2.sh does ${RAMP_DURATION}s of ramp + ${ATTACK_DURATION}s
    # of steady-state; we set attack_start to ramp_start + RAMP_DURATION.
    attack_start=$(awk -v a="$ramp_start" -v b="$RAMP_DURATION" 'BEGIN { printf "%.6f\n", a + b }')
    log "phase: PRE_ATTACK + ATTACK via attack_scripts_C2.sh ($scenario, ${ATTACK_DURATION}s)"
    "$ATTACK_SCRIPT" "$scenario" "$ATTACK_DURATION" >> "$COLLECT_LOG" 2>&1

    sleep "$FLUSH_GRACE"
    run_end=$(date +%s.%N)

    stop_tcpdumps "$outdir"

    cat > "$outdir/run_meta.env" <<EOF
RUN_ID=$run_id
SCENARIO=$scenario
REP=$rep
PRE_NORMAL=$PRE_NORMAL
RAMP_DURATION=$RAMP_DURATION
ATTACK_DURATION=$ATTACK_DURATION
FLUSH_GRACE=$FLUSH_GRACE
RUN_START_EPOCH=$run_start
RAMP_START_EPOCH=$ramp_start
ATTACK_START_EPOCH=$attack_start
RUN_END_EPOCH=$run_end
TARGET_IP=$TARGET_IP
C2_IP=$C2_IP
EOF

    # ---- convert this run's PCAPs to a windowed CSV ----------------------
    local run_duration
    run_duration=$(awk -v a="$run_start" -v b="$run_end" 'BEGIN { printf "%.6f\n", b - a }')
    mkdir -p "$DATASET_DIR"
    log "convert: pcap -> $DATASET_DIR/${run_id}.windows_1s.csv"
    python3 "$PIPELINE" \
        --pcap-dir "$outdir" \
        --out "$DATASET_DIR/${run_id}.windows_1s.csv" \
        --scenario-id "$scenario" \
        --run-start-epoch "$run_start" \
        --run-duration "$run_duration" \
        --attack-start-epoch "$attack_start" \
        --attack-duration "$ATTACK_DURATION" \
        --forecast-horizon "$RAMP_DURATION" \
        >> "$COLLECT_LOG" 2>&1

    log "RUN done id=$run_id"
}

run_normal_only_baseline() {
    # One pure-normal capture (no attack) so the model has clean negative
    # windows that span longer than any single in-run normal phase.
    local stamp="$(date +%Y%m%d_%H%M%S)"
    local secs=120
    local run_id="normal_only__${secs}s__${stamp}"
    local outdir="$CAPTURES_ROOT/$run_id"
    mkdir -p "$outdir"

    log "----------------------------------------------------------------"
    log "BASELINE  normal-only ${secs}s id=$run_id"
    log "----------------------------------------------------------------"

    start_tcpdumps "$outdir"
    local run_start run_end
    run_start=$(date +%s.%N)
    sleep "$secs"
    run_end=$(date +%s.%N)
    stop_tcpdumps "$outdir"

    cat > "$outdir/run_meta.env" <<EOF
RUN_ID=$run_id
SCENARIO=none
RUN_START_EPOCH=$run_start
RUN_END_EPOCH=$run_end
TARGET_IP=$TARGET_IP
C2_IP=$C2_IP
EOF

    local run_duration
    run_duration=$(awk -v a="$run_start" -v b="$run_end" 'BEGIN { printf "%.6f\n", b - a }')
    python3 "$PIPELINE" \
        --pcap-dir "$outdir" \
        --out "$DATASET_DIR/${run_id}.windows_1s.csv" \
        --scenario-id none \
        --run-start-epoch "$run_start" \
        --run-duration "$run_duration" \
        --attack-duration 0 \
        --forecast-horizon "$RAMP_DURATION" \
        >> "$COLLECT_LOG" 2>&1
}

# --------------------------------------------------------------------------
# Aggregate concatenation
# --------------------------------------------------------------------------
concat_all_csvs() {
    log "concatenating per-run CSVs into windows_1s_all.csv"
    python3 - <<PY
from pathlib import Path
import csv

processed = Path("$DATASET_DIR")
out = processed / "windows_1s_all.csv"
files = sorted(processed.glob("*.windows_1s.csv"))
files = [p for p in files if p.name != out.name]

if not files:
    raise SystemExit("no per-run CSVs to concatenate")

with out.open("w", newline="") as fout:
    writer = None
    n = 0
    for path in files:
        with path.open(newline="") as fin:
            reader = csv.DictReader(fin)
            if writer is None:
                writer = csv.DictWriter(fout, fieldnames=reader.fieldnames)
                writer.writeheader()
            for row in reader:
                writer.writerow(row); n += 1
print(f"merged {len(files)} files, {n} rows -> {out}")
PY
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
main() {
    require_root
    require_cmd mnexec  "Is Mininet installed?"
    require_cmd tcpdump
    require_cmd python3
    require_cmd awk
    require_cmd pgrep
    require_topology

    mkdir -p "$CAPTURES_ROOT" "$DATASET_DIR"
    : > "$COLLECT_LOG"

    log "================================================================"
    log "DATASET COLLECTION  scenarios=${#SCENARIOS[@]}  reps=$REPS  total_runs=$(( ${#SCENARIOS[@]} * REPS ))"
    log "  pre_normal=${PRE_NORMAL}s  ramp=${RAMP_DURATION}s  attack=${ATTACK_DURATION}s"
    log "================================================================"

    log "starting C2 + bots (one-time, reused across all runs)..."
    "$ATTACK_SCRIPT" start >> "$COLLECT_LOG" 2>&1

    # Optional pure-normal baseline (uncomment if you want one).
    # run_normal_only_baseline

    local s rep
    for s in "${SCENARIOS[@]}"; do
        for (( rep = 1; rep <= REPS; rep++ )); do
            run_one_capture "$s" "$rep"
        done
    done

    log "stopping C2 + bots"
    "$ATTACK_SCRIPT" stop >> "$COLLECT_LOG" 2>&1 || true

    concat_all_csvs

    log "================================================================"
    log "DONE. captures dir : $CAPTURES_ROOT"
    log "      processed    : $DATASET_DIR"
    log "      master CSV   : $DATASET_DIR/windows_1s_all.csv"
    log "      log          : $COLLECT_LOG"
    log "================================================================"
}

main "$@"
