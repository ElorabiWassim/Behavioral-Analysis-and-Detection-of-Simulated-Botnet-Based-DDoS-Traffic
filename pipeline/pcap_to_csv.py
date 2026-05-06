#!/usr/bin/env python3
"""Convert a PCAP into a flat packet-level CSV using tshark.

Why this exists
--------------
For dataset work you typically want a *simple, reproducible* packet table
that you can aggregate into 1s (or N-second) windows.

This script is intentionally minimal:
- reads a PCAP
- extracts a stable set of L2/L3/L4 fields
- writes a CSV (one row per packet)

Requirements
------------
- tshark must be installed and available on PATH.
  On Ubuntu/Debian: sudo apt-get install -y tshark

Example
-------
python3 pipeline/pcap_to_csv.py \
  --pcap captures/run_001_rdc.pcap \
  --out  packets/run_001_rdc.packets.csv
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


FIELDS: list[str] = [
    # Time / frame
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    # L3
    "ip.src",
    "ip.dst",
    "ip.proto",
    "ip.len",
    "ip.ttl",
    # TCP
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.len",
    "tcp.window_size_value",
    # UDP
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    # ICMP
    "icmp.type",
    "icmp.code",
]


def _require_tshark() -> str:
    tshark = shutil.which("tshark")
    if not tshark:
        raise SystemExit(
            "tshark not found on PATH. Install it first (e.g., `sudo apt-get install -y tshark`)."
        )
    return tshark


def pcap_to_csv(pcap_path: Path, out_csv: Path, display_filter: str | None) -> None:
    tshark = _require_tshark()

    if not pcap_path.exists():
        raise SystemExit(f"PCAP not found: {pcap_path}")

    out_csv.parent.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [
        tshark,
        "-n",  # no name resolution
        "-r",
        str(pcap_path),
    ]

    if display_filter:
        cmd += ["-Y", display_filter]

    cmd += [
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]

    for f in FIELDS:
        cmd += ["-e", f]

    # Write directly to file to avoid buffering massive outputs in memory.
    with out_csv.open("wb") as f:
        try:
            subprocess.run(cmd, check=True, stdout=f)
        except FileNotFoundError as exc:
            raise SystemExit(f"Failed to execute tshark: {exc}") from exc
        except subprocess.CalledProcessError as exc:
            raise SystemExit(f"tshark failed (exit {exc.returncode}).") from exc


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pcap", required=True, type=Path, help="Input .pcap/.pcapng")
    p.add_argument("--out", required=True, type=Path, help="Output .csv path")
    p.add_argument(
        "--display-filter",
        default=None,
        help="Optional Wireshark display filter (tshark -Y), e.g. 'ip'.",
    )
    return p


def main() -> None:
    args = build_arg_parser().parse_args()
    pcap_to_csv(args.pcap, args.out, args.display_filter)


if __name__ == "__main__":
    main()
