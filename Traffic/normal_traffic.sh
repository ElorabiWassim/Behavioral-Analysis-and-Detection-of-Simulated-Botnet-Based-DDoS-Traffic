#!/usr/bin/env bash
#
# traffic/normal_traffic.sh
# ============================================================================
# Generates realistic BACKGROUND / LEGITIMATE traffic from every non-bot host
# in the Mininet topology defined by topology/topo.py.
#
# This traffic is what the detection pipeline is supposed to learn as
# "normal"; it must run BEFORE and DURING every attack run so that the
# captured PCAPs contain a mix of benign and malicious flows, exactly like a
# real ISP uplink.
#
# Traffic profile per normal host (loops, jittered, forever):
#     HTTP GETs   -> target  (10.0.100.10:80)     curl   every  5-15 s
#     ICMP echo   -> webdecoy(10.0.100.11)        ping   every  3-8 s
#     DNS lookups -> dnsdecoy(10.0.100.12:53)     dig    every 10-25 s
#
# A minimal Python HTTP server is started on `target` so that the HTTP GETs
# complete a real TCP handshake and produce realistic request/response
# patterns in the captures.
#
# This script must run on the VM HOST SHELL (NOT inside the Mininet CLI)
# with root privileges. It locates each Mininet host's network namespace
# via the PID of its shell (Mininet names each host's shell
# "mininet:<host>"), then uses `mnexec -a <pid>` to launch commands inside.
#
# Usage:
#     sudo traffic/normal_traffic.sh start
#     sudo traffic/normal_traffic.sh status
#     sudo traffic/normal_traffic.sh stop
#
# Prerequisites on the VM:
#     sudo apt-get install -y curl dnsutils iputils-ping python3
#
# The Mininet topology (sudo python3 topology/topo.py) must be up first.
# ============================================================================

set -u

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
export TARGET="${TARGET:-10.0.100.10}"
export WEB="${WEB:-10.0.100.11}"
export DNS="${DNS:-10.0.100.12}"

PIDFILE=/tmp/normal_traffic.pids
SERVER_PIDFILE=/tmp/normal_traffic_server.pid
SERVER_DIR=/tmp/nt-www
LOGFILE=/tmp/normal_traffic.log

# Every non-bot host in topology/topo.py (37 total: 31 in infected ISPs +
# 6 in the clean ISP-F control group).
NORMALS=(
    normalA1 normalA2 normalA3 normalA4 normalA5 normalA6
    normalB1 normalB2 normalB3 normalB4 normalB5 normalB6
    normalB7 normalB8 normalB9 normalB10 normalB11
    normalC1 normalC2 normalC3 normalC4
    normalD1 normalD2 normalD3 normalD4 normalD5 normalD6 normalD7 normalD8
    normalE1 normalE2
    normalF1 normalF2 normalF3 normalF4 normalF5 normalF6
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

# Return the PID of the bash shell for Mininet host $1, or empty.
# Mininet sets each host's bash argv[0] to "mininet:<host>", so we match
# the end-of-line anchor to avoid "normalA1" also matching "normalA10" etc.
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
# Target HTTP server
# --------------------------------------------------------------------------
start_target_server() {
    local pid
    pid="$(ns_pid target)"
    if [[ -z "$pid" ]]; then
        log "WARN: target namespace not found; skipping HTTP server"
        return
    fi

    if [[ -f "$SERVER_PIDFILE" ]] && kill -0 "$(cat "$SERVER_PIDFILE")" 2>/dev/null; then
        log "target :80 server already running (pid $(cat "$SERVER_PIDFILE"))"
        return
    fi

    # Build a tiny document tree served as the index page.
    mkdir -p "$SERVER_DIR"
    printf '<html><body><h1>normal_traffic target</h1><p>ok</p></body></html>\n' \
        > "$SERVER_DIR/index.html"

    mnexec -a "$pid" python3 -m http.server 80 --directory "$SERVER_DIR" \
        >/tmp/normal_traffic_server.log 2>&1 &
    echo $! > "$SERVER_PIDFILE"
    sleep 1

    if kill -0 "$(cat "$SERVER_PIDFILE")" 2>/dev/null; then
        log "HTTP server up on target:80 (pid $(cat "$SERVER_PIDFILE"))"
    else
        log "WARN: HTTP server on target failed to start"
        log "      see /tmp/normal_traffic_server.log for details"
        rm -f "$SERVER_PIDFILE"
    fi
}

stop_target_server() {
    if [[ -f "$SERVER_PIDFILE" ]]; then
        kill "$(cat "$SERVER_PIDFILE")" 2>/dev/null || true
        rm -f "$SERVER_PIDFILE"
    fi
    local tp
    tp="$(ns_pid target)"
    if [[ -n "$tp" ]]; then
        mnexec -a "$tp" pkill -9 -f 'python3 -m http.server' 2>/dev/null || true
    fi
}

# --------------------------------------------------------------------------
# Worker spawn / kill
# --------------------------------------------------------------------------
spawn_workers_on() {
    # Spawn three background traffic loops inside the given host namespace.
    # $1 = mininet host name, $2 = namespace pid
    local host="$1" pid="$2"

    # We expand $TARGET / $WEB / $DNS into the bash -c argv (via the
    # break-out-of-single-quotes idiom '...'"$VAR"'...') so the literal
    # IPs show up in the loop shell's /proc/<pid>/cmdline. That is what
    # lets `pkill -f "curl.*<IP>"` during stop() match BOTH the outer
    # `bash -c` supervisor and its running curl/ping/dig child, which is
    # the only reliable way to kill a long-running loop inside a netns
    # when we cannot signal the mnexec parent directly.

    # HTTP GET loop  (curl connects + reads + closes every ~5-15 s)
    mnexec -a "$pid" bash -c 'while true; do curl -s --max-time 2 -o /dev/null "http://'"$TARGET"'/" || true; sleep $(( (RANDOM % 11) + 5 )); done' >/dev/null 2>&1 &
    echo $! >> "$PIDFILE"

    # ICMP echo loop (one ping every ~3-8 s)
    mnexec -a "$pid" bash -c 'while true; do ping -c 1 -W 1 '"$WEB"' >/dev/null 2>&1 || true; sleep $(( (RANDOM % 6) + 3 )); done' >/dev/null 2>&1 &
    echo $! >> "$PIDFILE"

    # DNS lookup loop (timeouts are fine; the UDP datagram still goes out)
    mnexec -a "$pid" bash -c 'while true; do dig @'"$DNS"' +tries=1 +time=1 +short example.com A >/dev/null 2>&1 || true; sleep $(( (RANDOM % 16) + 10 )); done' >/dev/null 2>&1 &
    echo $! >> "$PIDFILE"
}

# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
cmd_start() {
    require_topology

    if [[ -f "$PIDFILE" ]] && [[ -s "$PIDFILE" ]]; then
        local alive=0
        while read -r p; do kill -0 "$p" 2>/dev/null && alive=$((alive+1)); done < "$PIDFILE"
        if (( alive > 0 )); then
            echo "ERROR: normal traffic already running ($alive workers)." >&2
            echo "       Run '$0 stop' first." >&2
            exit 1
        fi
    fi

    : > "$PIDFILE"

    start_target_server

    log "starting normal traffic from ${#NORMALS[@]} hosts"
    local started=0 missing=0
    for h in "${NORMALS[@]}"; do
        local pid
        pid="$(ns_pid "$h")"
        if [[ -z "$pid" ]]; then
            log "WARN: $h namespace not found, skipping"
            missing=$((missing+1))
            continue
        fi
        spawn_workers_on "$h" "$pid"
        started=$((started+1))
    done

    local workers
    workers="$(wc -l < "$PIDFILE")"
    log "normal traffic: $started hosts active, $missing missing, $workers workers"

    if (( missing > 0 )); then
        log "         some namespaces are missing; re-check Mininet state"
    fi
}

cmd_stop() {
    log "stopping normal traffic"

    # Kill outer mnexec supervisors tracked in PIDFILE
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

    # Belt-and-suspenders: kill anything matching our traffic patterns inside
    # each normal namespace, in case a supervisor died without reaping.
    for h in "${NORMALS[@]}"; do
        local pid
        pid="$(ns_pid "$h")"
        [[ -z "$pid" ]] && continue
        mnexec -a "$pid" pkill -9 -f "curl.*$TARGET" 2>/dev/null || true
        mnexec -a "$pid" pkill -9 -f "ping.*$WEB"    2>/dev/null || true
        mnexec -a "$pid" pkill -9 -f "dig.*$DNS"     2>/dev/null || true
    done

    stop_target_server

    log "normal traffic stopped"
}

cmd_status() {
    echo "---- normal_traffic status ----"
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
        echo "pidfile:     $PIDFILE"
        echo "alive:       $alive"
        echo "dead/gone:   $dead"
    else
        echo "pidfile:     (none)"
        echo "workers:     not started by this script"
    fi

    if [[ -f "$SERVER_PIDFILE" ]]; then
        local sp
        sp="$(cat "$SERVER_PIDFILE")"
        if kill -0 "$sp" 2>/dev/null; then
            echo "http server: RUNNING (pid $sp)"
        else
            echo "http server: DEAD (pid $sp)"
        fi
    else
        echo "http server: not started by this script"
    fi

    echo "target:      $TARGET"
    echo "webdecoy:    $WEB"
    echo "dnsdecoy:    $DNS"
    echo "normal hosts:${#NORMALS[@]}"
}

print_usage() {
    cat <<EOF
Usage: sudo traffic/normal_traffic.sh <subcommand>

Subcommands:
    start     Start background traffic from every normal host, and start
              an HTTP server on target:80 so GETs complete cleanly.
    stop      Stop every worker and the HTTP server.
    status    Report how many workers are still alive.

Environment overrides (optional):
    TARGET=10.0.100.10
    WEB=10.0.100.11
    DNS=10.0.100.12

Run this from the VM host shell (NOT the Mininet CLI).
The Mininet topology (sudo python3 topology/topo.py) must be up first.
EOF
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
main() {
    require_root
    require_mnexec
    case "${1:-}" in
        start)   cmd_start ;;
        stop)    cmd_stop ;;
        status)  cmd_status ;;
        -h|--help|help) print_usage ;;
        "")      print_usage; exit 2 ;;
        *)       echo "unknown subcommand: $1" >&2; print_usage; exit 2 ;;
    esac
}

main "$@"
