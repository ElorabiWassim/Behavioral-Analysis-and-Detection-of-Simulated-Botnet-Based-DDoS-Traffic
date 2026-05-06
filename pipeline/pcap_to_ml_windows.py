#!/usr/bin/env python3
"""Build ML-ready time-window features from C2-driven DDoS PCAP captures.

The output schema follows the phase-3/4 dataset design:

metadata columns:
    capture_id, scenario_id, window_start_time, window_duration,
    relative_time, attack_start_time

labels:
    phase            in {normal, pre_attack, attack}
    attack_family    in {none, tcp, udp, icmp, http, mixed, c2}

features:
    packet/byte rates, protocol counts/ratios, TCP flag ratios, flow/source
    diversity, C2-channel activity, burstiness, 5-second rolling context,
    and past-baseline z-scores.

Only past windows are used for the z-score baseline, so the derived features
are usable for onset/forecasting experiments without future leakage.

Phase semantics
---------------
``pre_attack`` is the ``--forecast-horizon``-second window immediately
before ``attack_start``; it should align with the ramp emitted by
``Traffic/attack_scripts_C2.sh`` (see ``RAMP_DURATION`` there). Windows
*after* the attack ends are labelled ``normal`` (no separate
``post_attack`` class) because the defender goal is early detection,
not forensic decay analysis.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import math
import shutil
import subprocess
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
    "icmp.type",
    "icmp.code",
]

META_COLUMNS = [
    "capture_id",
    "scenario_id",
    "window_start_time",
    "window_duration",
    "relative_time",
    "attack_start_time",
]

LABEL_COLUMNS = [
    "phase",
    "attack_family",
]

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "pps",
    "bps",
    "avg_packet_size",
    "tcp_packet_count",
    "udp_packet_count",
    "icmp_packet_count",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "syn_count",
    "ack_count",
    "rst_count",
    "syn_ratio",
    "ack_ratio",
    "syn_to_ack_ratio",
    "unique_src_ip_count",
    "unique_dst_ip_count",
    "unique_src_port_count",
    "unique_dst_port_count",
    "flow_count",
    "many_to_one_ratio",
    "c2_packet_count",
    "c2_flow_count",
    "bots_contacting_c2_count",
    "simultaneous_src_count",
    "burstiness_score",
    "pps_mean_5s",
    "bps_mean_5s",
    "unique_src_mean_5s",
    "flow_count_mean_5s",
    "pps_slope_5s",
    "bps_slope_5s",
    "unique_src_slope_5s",
    "flow_count_slope_5s",
    "pps_zscore",
    "bps_zscore",
    "unique_src_zscore",
    "flow_count_zscore",
]

OUTPUT_COLUMNS = META_COLUMNS + LABEL_COLUMNS + FEATURE_COLUMNS

DEFAULT_BOT_RANGES = [
    "10.0.1.21-10.0.1.34",
    "10.0.2.21-10.0.2.22",
    "10.0.3.21-10.0.3.29",
    "10.0.4.21-10.0.4.25",
    "10.0.5.21-10.0.5.35",
]


@dataclass
class IpRange:
    low: int
    high: int

    def contains(self, ip: str) -> bool:
        try:
            value = int(ipaddress.ip_address(ip))
        except ValueError:
            return False
        return self.low <= value <= self.high


@dataclass
class WindowAgg:
    packet_count: int = 0
    byte_count: int = 0
    tcp_packet_count: int = 0
    udp_packet_count: int = 0
    icmp_packet_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    c2_packet_count: int = 0
    src_ips: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    src_ports: set[str] = field(default_factory=set)
    dst_ports: set[str] = field(default_factory=set)
    flows: set[tuple[str, str, str, str, str]] = field(default_factory=set)
    c2_flows: set[tuple[str, str, str, str, str]] = field(default_factory=set)
    bots_contacting_c2: set[str] = field(default_factory=set)
    dst_to_srcs: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    subbucket_packet_counts: list[int] = field(default_factory=lambda: [0] * 10)
    subbucket_srcs: list[set[str]] = field(default_factory=lambda: [set() for _ in range(10)])


@dataclass
class CaptureAgg:
    capture_id: str
    pcap_path: Path
    windows: dict[float, WindowAgg] = field(default_factory=dict)
    first_ts: float | None = None
    last_ts: float | None = None


def _parse_ip_ranges(values: Iterable[str]) -> list[IpRange]:
    ranges: list[IpRange] = []
    for value in values:
        low_s, sep, high_s = value.partition("-")
        if not sep:
            ip = int(ipaddress.ip_address(low_s.strip()))
            ranges.append(IpRange(ip, ip))
            continue
        ranges.append(
            IpRange(
                int(ipaddress.ip_address(low_s.strip())),
                int(ipaddress.ip_address(high_s.strip())),
            )
        )
    return ranges


def _require_tshark() -> str:
    tshark = shutil.which("tshark")
    if not tshark:
        raise SystemExit(
            "tshark not found on PATH. Install it in WSL with: "
            "sudo apt-get install -y tshark"
        )
    return tshark


def _float_or_none(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _int_or_zero(value: str | None) -> int:
    if value is None or value == "":
        return 0
    try:
        return int(float(value))
    except ValueError:
        return 0


def _tcp_flags(value: str | None) -> int:
    if not value:
        return 0
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return 0


def _is_bot_ip(ip: str, bot_ranges: list[IpRange]) -> bool:
    return any(r.contains(ip) for r in bot_ranges)


def _capture_id_for(path: Path) -> str:
    parent = path.parent.name
    stem = path.stem.replace(".", "_")
    if parent and parent not in (".", ""):
        return f"{parent}__{stem}"
    return stem


def _resolve_pcaps(args: argparse.Namespace) -> list[Path]:
    pcaps: list[Path] = []
    if args.pcap:
        pcaps.extend(args.pcap)
    if args.pcap_dir:
        for pattern in args.glob:
            pcaps.extend(sorted(args.pcap_dir.glob(pattern)))
    unique = sorted({p.resolve() for p in pcaps})
    missing = [p for p in unique if not p.exists()]
    if missing:
        raise SystemExit("Missing PCAP(s): " + ", ".join(str(p) for p in missing))
    if not unique:
        raise SystemExit("No PCAP files supplied. Use --pcap or --pcap-dir.")
    return unique


def _tshark_rows(pcap_path: Path, display_filter: str) -> Iterable[dict[str, str]]:
    cmd = [
        _require_tshark(),
        "-n",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
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
    for field_name in TSHARK_FIELDS:
        cmd += ["-e", field_name]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    reader = csv.DictReader(proc.stdout)
    for row in reader:
        yield row
    _, stderr = proc.communicate()
    if proc.returncode != 0:
        raise SystemExit(
            f"tshark failed for {pcap_path} (exit {proc.returncode}):\n{stderr.strip()}"
        )


def _packet_ports(row: dict[str, str], proto: str) -> tuple[str, str]:
    if proto == "6":
        return row.get("tcp.srcport", ""), row.get("tcp.dstport", "")
    if proto == "17":
        return row.get("udp.srcport", ""), row.get("udp.dstport", "")
    return "", ""


def aggregate_pcap(
    pcap_path: Path,
    window_duration: float,
    target_ip: str,
    c2_ip: str,
    c2_port: str,
    bot_ranges: list[IpRange],
    display_filter: str,
) -> CaptureAgg:
    capture = CaptureAgg(capture_id=_capture_id_for(pcap_path), pcap_path=pcap_path)

    for row in _tshark_rows(pcap_path, display_filter):
        ts = _float_or_none(row.get("frame.time_epoch"))
        if ts is None:
            continue
        src = row.get("ip.src", "")
        dst = row.get("ip.dst", "")
        proto = row.get("ip.proto", "")
        if not src or not dst:
            continue

        capture.first_ts = ts if capture.first_ts is None else min(capture.first_ts, ts)
        capture.last_ts = ts if capture.last_ts is None else max(capture.last_ts, ts)

        win = math.floor(ts / window_duration) * window_duration
        agg = capture.windows.setdefault(win, WindowAgg())

        frame_len = _int_or_zero(row.get("frame.len"))
        src_port, dst_port = _packet_ports(row, proto)
        flow = (src, dst, proto, src_port, dst_port)
        involves_c2 = src == c2_ip or dst == c2_ip or src_port == c2_port or dst_port == c2_port

        agg.packet_count += 1
        agg.byte_count += frame_len
        agg.src_ips.add(src)
        agg.dst_ips.add(dst)
        agg.dst_to_srcs[dst].add(src)
        agg.flows.add(flow)

        if src_port:
            agg.src_ports.add(src_port)
        if dst_port:
            agg.dst_ports.add(dst_port)

        if proto == "6":
            agg.tcp_packet_count += 1
            flags = _tcp_flags(row.get("tcp.flags"))
            if flags & 0x02:
                agg.syn_count += 1
            if flags & 0x10:
                agg.ack_count += 1
            if flags & 0x04:
                agg.rst_count += 1
        elif proto == "17":
            agg.udp_packet_count += 1
        elif proto == "1":
            agg.icmp_packet_count += 1

        if involves_c2:
            agg.c2_packet_count += 1
            agg.c2_flows.add(flow)
            for ip in (src, dst):
                if ip != c2_ip and _is_bot_ip(ip, bot_ranges):
                    agg.bots_contacting_c2.add(ip)

        offset = max(0.0, min(window_duration - 0.000001, ts - win))
        bucket_count = len(agg.subbucket_packet_counts)
        bucket = min(bucket_count - 1, int((offset / window_duration) * bucket_count))
        agg.subbucket_packet_counts[bucket] += 1
        agg.subbucket_srcs[bucket].add(src)

    return capture


def _safe_ratio(num: float, den: float) -> float:
    return 0.0 if den == 0 else num / den


def _slope(values: list[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    x_mean = (n - 1) / 2
    y_mean = sum(values) / n
    den = sum((x - x_mean) ** 2 for x in range(n))
    if den == 0:
        return 0.0
    return sum((x - x_mean) * (y - y_mean) for x, y in enumerate(values)) / den


def _zscore(value: float, history: deque[float]) -> float:
    if len(history) < 5:
        return 0.0
    mean = sum(history) / len(history)
    var = sum((x - mean) ** 2 for x in history) / len(history)
    std = math.sqrt(var)
    if std == 0:
        return 0.0
    return (value - mean) / std


def _attack_family(scenario_id: str) -> str:
    scenario = scenario_id.lower()
    if scenario in ("none", "normal", "normal-only", "baseline"):
        return "none"
    for family in ("tcp", "udp", "http", "icmp", "mixed"):
        if scenario == family or scenario.startswith(f"{family}-") or f"__{family}" in scenario:
            return family
    return "c2"


def _phase(
    window_start: float,
    attack_start: float | None,
    attack_duration: float,
    forecast_horizon: float,
) -> str:
    """Three-class phase label: ``normal`` / ``pre_attack`` / ``attack``.

    The post-attack window (after ``attack_end``) is intentionally folded
    into ``normal`` -- the project goal is *early* detection (catch the
    attack during ramp-up via ``pre_attack``), not forensic decay
    analysis. Keeping a distinct ``post_attack`` class would dilute the
    ``normal`` baseline with rate-dropping windows that have no
    operational value for a defender.
    """
    if attack_start is None or attack_duration <= 0:
        return "normal"
    attack_end = attack_start + attack_duration
    if attack_start <= window_start < attack_end:
        return "attack"
    if window_start < attack_start:
        return "pre_attack" if attack_start - window_start <= forecast_horizon else "normal"
    # window_start >= attack_end  ->  back to baseline
    return "normal"


def _base_features(agg: WindowAgg, window_duration: float) -> dict[str, float | int]:
    packet_count = agg.packet_count
    byte_count = agg.byte_count
    unique_src_ip_count = len(agg.src_ips)
    unique_dst_ip_count = len(agg.dst_ips)
    max_sources_to_one_dst = max((len(srcs) for srcs in agg.dst_to_srcs.values()), default=0)
    mean_bucket_pkts = packet_count / len(agg.subbucket_packet_counts) if packet_count else 0.0

    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "pps": _safe_ratio(packet_count, window_duration),
        "bps": _safe_ratio(byte_count * 8, window_duration),
        "avg_packet_size": _safe_ratio(byte_count, packet_count),
        "tcp_packet_count": agg.tcp_packet_count,
        "udp_packet_count": agg.udp_packet_count,
        "icmp_packet_count": agg.icmp_packet_count,
        "tcp_ratio": _safe_ratio(agg.tcp_packet_count, packet_count),
        "udp_ratio": _safe_ratio(agg.udp_packet_count, packet_count),
        "icmp_ratio": _safe_ratio(agg.icmp_packet_count, packet_count),
        "syn_count": agg.syn_count,
        "ack_count": agg.ack_count,
        "rst_count": agg.rst_count,
        "syn_ratio": _safe_ratio(agg.syn_count, agg.tcp_packet_count),
        "ack_ratio": _safe_ratio(agg.ack_count, agg.tcp_packet_count),
        "syn_to_ack_ratio": _safe_ratio(agg.syn_count, agg.ack_count),
        "unique_src_ip_count": unique_src_ip_count,
        "unique_dst_ip_count": unique_dst_ip_count,
        "unique_src_port_count": len(agg.src_ports),
        "unique_dst_port_count": len(agg.dst_ports),
        "flow_count": len(agg.flows),
        "many_to_one_ratio": _safe_ratio(max_sources_to_one_dst, unique_src_ip_count),
        "c2_packet_count": agg.c2_packet_count,
        "c2_flow_count": len(agg.c2_flows),
        "bots_contacting_c2_count": len(agg.bots_contacting_c2),
        "simultaneous_src_count": max((len(srcs) for srcs in agg.subbucket_srcs), default=0),
        "burstiness_score": _safe_ratio(max(agg.subbucket_packet_counts, default=0), mean_bucket_pkts),
    }


def _format_value(value: object) -> object:
    if isinstance(value, float):
        if not math.isfinite(value):
            return 0
        return f"{value:.6f}"
    return value


def build_rows(
    captures: list[CaptureAgg],
    scenario_id: str,
    run_start: float,
    run_end: float,
    attack_start: float | None,
    attack_duration: float,
    forecast_horizon: float,
    window_duration: float,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    family = _attack_family(scenario_id)
    attack_start_value = "" if attack_start is None else attack_start
    window_count = int(math.ceil((run_end - run_start) / window_duration))

    for capture in captures:
        rolling: dict[str, deque[float]] = {
            "pps": deque(maxlen=5),
            "bps": deque(maxlen=5),
            "unique_src_ip_count": deque(maxlen=5),
            "flow_count": deque(maxlen=5),
        }
        baseline: dict[str, deque[float]] = {
            "pps": deque(maxlen=30),
            "bps": deque(maxlen=30),
            "unique_src_ip_count": deque(maxlen=30),
            "flow_count": deque(maxlen=30),
        }

        for idx in range(window_count):
            win = run_start + idx * window_duration
            key = math.floor(win / window_duration) * window_duration
            agg = capture.windows.get(key, WindowAgg())
            features = _base_features(agg, window_duration)

            pps = float(features["pps"])
            bps = float(features["bps"])
            unique_src = float(features["unique_src_ip_count"])
            flow_count = float(features["flow_count"])

            features["pps_zscore"] = _zscore(pps, baseline["pps"])
            features["bps_zscore"] = _zscore(bps, baseline["bps"])
            features["unique_src_zscore"] = _zscore(unique_src, baseline["unique_src_ip_count"])
            features["flow_count_zscore"] = _zscore(flow_count, baseline["flow_count"])

            for name, value in (
                ("pps", pps),
                ("bps", bps),
                ("unique_src_ip_count", unique_src),
                ("flow_count", flow_count),
            ):
                rolling[name].append(value)
                baseline[name].append(value)

            features["pps_mean_5s"] = sum(rolling["pps"]) / len(rolling["pps"])
            features["bps_mean_5s"] = sum(rolling["bps"]) / len(rolling["bps"])
            features["unique_src_mean_5s"] = (
                sum(rolling["unique_src_ip_count"]) / len(rolling["unique_src_ip_count"])
            )
            features["flow_count_mean_5s"] = sum(rolling["flow_count"]) / len(rolling["flow_count"])
            features["pps_slope_5s"] = _slope(list(rolling["pps"]))
            features["bps_slope_5s"] = _slope(list(rolling["bps"]))
            features["unique_src_slope_5s"] = _slope(list(rolling["unique_src_ip_count"]))
            features["flow_count_slope_5s"] = _slope(list(rolling["flow_count"]))

            row: dict[str, object] = {
                "capture_id": capture.capture_id,
                "scenario_id": scenario_id,
                "window_start_time": win,
                "window_duration": window_duration,
                "relative_time": win - run_start,
                "attack_start_time": attack_start_value,
                "phase": _phase(win, attack_start, attack_duration, forecast_horizon),
                "attack_family": family,
            }
            row.update(features)
            rows.append({col: _format_value(row.get(col, 0)) for col in OUTPUT_COLUMNS})

    return rows


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_argument_group("input")
    source.add_argument("--pcap", nargs="*", type=Path, help="One or more input PCAP/PCAPNG files.")
    source.add_argument("--pcap-dir", type=Path, help="Directory containing PCAP files.")
    source.add_argument(
        "--glob",
        nargs="+",
        default=["*.pcap", "*.pcapng"],
        help="Glob(s) used with --pcap-dir. Default: %(default)s",
    )
    source.add_argument("--out", required=True, type=Path, help="Output ML-ready CSV path.")
    source.add_argument(
        "--display-filter",
        default="ip",
        help="tshark display filter. Keep this as 'ip' for the dataset schema.",
    )

    labels = parser.add_argument_group("labels")
    labels.add_argument("--scenario-id", required=True, help="Scenario id, e.g. c2_udp-low_001.")
    labels.add_argument("--attack-start-epoch", type=float, default=None)
    labels.add_argument(
        "--attack-start-offset",
        type=float,
        default=None,
        help="Attack start in seconds relative to run start. Ignored if --attack-start-epoch is set.",
    )
    labels.add_argument("--attack-duration", type=float, default=0.0)
    labels.add_argument("--forecast-horizon", type=float, default=10.0)

    timing = parser.add_argument_group("timing")
    timing.add_argument("--window-duration", type=float, default=1.0)
    timing.add_argument("--run-start-epoch", type=float, default=None)
    timing.add_argument(
        "--run-duration",
        type=float,
        default=None,
        help="Force output length in seconds. Default: first packet through last packet.",
    )

    context = parser.add_argument_group("network context")
    context.add_argument("--target-ip", default="10.0.100.10")
    context.add_argument("--c2-ip", default="10.0.200.10")
    context.add_argument("--c2-port", default="6667")
    context.add_argument(
        "--bot-range",
        action="append",
        default=None,
        help="Allowed bot IP range, e.g. 10.0.1.21-10.0.1.34. Repeatable.",
    )
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    if args.window_duration <= 0:
        raise SystemExit("--window-duration must be positive.")

    pcaps = _resolve_pcaps(args)
    bot_ranges = _parse_ip_ranges(args.bot_range or DEFAULT_BOT_RANGES)

    captures = [
        aggregate_pcap(
            pcap_path=pcap,
            window_duration=args.window_duration,
            target_ip=args.target_ip,
            c2_ip=args.c2_ip,
            c2_port=str(args.c2_port),
            bot_ranges=bot_ranges,
            display_filter=args.display_filter,
        )
        for pcap in pcaps
    ]

    first_ts = min((c.first_ts for c in captures if c.first_ts is not None), default=None)
    last_ts = max((c.last_ts for c in captures if c.last_ts is not None), default=None)
    if first_ts is None or last_ts is None:
        raise SystemExit("No IP packets found in the supplied PCAP files.")

    run_start_raw = args.run_start_epoch if args.run_start_epoch is not None else first_ts
    run_start = math.floor(run_start_raw / args.window_duration) * args.window_duration
    if args.run_duration is not None:
        run_end_raw = run_start_raw + args.run_duration
        run_end = math.ceil(run_end_raw / args.window_duration) * args.window_duration
    else:
        run_end = math.ceil(last_ts + args.window_duration)

    attack_start = args.attack_start_epoch
    if attack_start is None and args.attack_start_offset is not None:
        attack_start = run_start + args.attack_start_offset

    rows = build_rows(
        captures=captures,
        scenario_id=args.scenario_id,
        run_start=run_start,
        run_end=run_end,
        attack_start=attack_start,
        attack_duration=args.attack_duration,
        forecast_horizon=args.forecast_horizon,
        window_duration=args.window_duration,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {len(rows)} rows from {len(captures)} capture(s) -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
