import argparse
import csv
import os
import subprocess
from typing import Dict, Iterable, List, Optional

import numpy as np
import pandas as pd
from pandas.errors import ParserError


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _tshark_cmd(pcap_path: str) -> List[str]:
    # Key flags:
    # - occurrence=f avoids multi-occurrence fields (e.g., ICMP payload IP headers)
    #   from being emitted as comma-separated lists, which breaks CSV.
    # - quote=d ensures any remaining delimiters are quoted.
    # - aggregator=| changes the join character for multi-occurrence fields.
    return [
        "tshark",
        "-r",
        pcap_path,
        "-Y",
        "ip",
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
        "-E",
        "aggregator=|",
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.len",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ip.proto",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.flags",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
        "-e",
        "udp.length",
        "-e",
        "icmp.type",
    ]


def extract_packets_csv(pcap_path: str, out_packets_csv: str, *, tolerate_truncated_tail: bool) -> None:
    cmd = _tshark_cmd(pcap_path)
    _ensure_dir(os.path.dirname(out_packets_csv))

    with open(out_packets_csv, "w", newline="") as f:
        res = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)

    if res.returncode == 0:
        return

    stderr = res.stderr or ""
    if (
        tolerate_truncated_tail
        and "cut short" in stderr
        and os.path.exists(out_packets_csv)
        and os.path.getsize(out_packets_csv) > 200
    ):
        print("  WARN: tshark reported truncated tail; continuing")
        return

    raise RuntimeError(f"tshark failed (rc={res.returncode}): {stderr.strip()[:500]}")


def packets_csv_seems_parseable(path: str) -> bool:
    if not os.path.exists(path) or os.path.getsize(path) <= 200:
        return False
    try:
        pd.read_csv(path, nrows=2000)
        return True
    except ParserError:
        return False


def packets_to_windows_1s(inp_csv: str, meta: Dict[str, str]) -> pd.DataFrame:
    df = pd.read_csv(inp_csv)
    df["t"] = df["frame.time_epoch"].astype(float)
    df["sec"] = np.floor(df["t"]).astype("int64")
    df["len"] = df["frame.len"].astype("int64")
    df["src"] = df["ip.src"].astype(str)
    df["proto"] = pd.to_numeric(df["ip.proto"], errors="coerce").fillna(-1).astype("int64")

    df["is_tcp"] = (df["proto"] == 6).astype("int64")
    df["is_udp"] = (df["proto"] == 17).astype("int64")
    df["is_icmp"] = (df["proto"] == 1).astype("int64")

    flags = df.get("tcp.flags")
    if flags is None:
        f = pd.Series(["0"] * len(df))
    else:
        f = flags.astype(str).where(flags.notna(), "0").str.replace("0x", "", regex=False)
    f = pd.to_numeric(f, errors="coerce").fillna(0).astype("int64")

    df["syn"] = ((f & 0x02) != 0).astype("int64")
    df["ack"] = ((f & 0x10) != 0).astype("int64")
    df["rst"] = ((f & 0x04) != 0).astype("int64")

    g = df.groupby("sec", as_index=False).agg(
        packets=("len", "count"),
        bytes=("len", "sum"),
        unique_src=("src", "nunique"),
        tcp_packets=("is_tcp", "sum"),
        udp_packets=("is_udp", "sum"),
        icmp_packets=("is_icmp", "sum"),
        syn_packets=("syn", "sum"),
        ack_packets=("ack", "sum"),
        rst_packets=("rst", "sum"),
    )
    g["pps"] = g["packets"]
    g["bps"] = g["bytes"] * 8
    g["syn_ratio"] = g["syn_packets"] / g["tcp_packets"].where(g["tcp_packets"] > 0, np.nan)
    g["udp_ratio"] = g["udp_packets"] / g["packets"].where(g["packets"] > 0, np.nan)

    for k, v in meta.items():
        g[k] = v
    return g


def iter_runs(runs_csv: str) -> Iterable[Dict[str, str]]:
    with open(runs_csv, newline="") as f:
        yield from csv.DictReader(f)


def build_combined(runs: List[Dict[str, str]], windows_dir: str, out_all: str) -> None:
    if os.path.exists(out_all):
        os.remove(out_all)

    written = False
    for r in runs:
        pcap = (r.get("pcap_file") or "").strip()
        if not pcap:
            continue
        base = os.path.splitext(os.path.basename(pcap))[0]
        win_csv = os.path.join(windows_dir, base + ".windows_1s.csv")
        if not os.path.exists(win_csv):
            continue

        with open(win_csv, "r", newline="") as src, open(out_all, "a", newline="") as dst:
            for i, line in enumerate(src):
                if i == 0 and written:
                    continue
                dst.write(line)
        written = True


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract packets via tshark and build 1s window features (robust to truncated pcaps and ICMP inner headers)"
    )
    parser.add_argument("--runs", default="dataset/runs.csv")
    parser.add_argument("--features", default="dataset/features")
    parser.add_argument("--force", action="store_true", help="Rebuild windows even if they exist")
    parser.add_argument("--reextract", action="store_true", help="Force tshark re-extraction even if packets CSV exists")
    parser.add_argument("--no-tolerate-truncated", action="store_true", help="Fail on truncated pcap tail warnings")
    args = parser.parse_args(argv)

    packets_dir = os.path.join(args.features, "packets")
    windows_dir = os.path.join(args.features, "windows_1s")
    out_all = os.path.join(args.features, "windows_1s_all.csv")

    _ensure_dir(packets_dir)
    _ensure_dir(windows_dir)

    # Ensure tshark is present early
    subprocess.run(["tshark", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    runs = [dict(r) for r in iter_runs(args.runs)]
    failures: List[str] = []
    tolerate_truncated = not args.no_tolerate_truncated

    for r in runs:
        pcap = (r.get("pcap_file") or "").strip()
        if not pcap:
            continue
        if not os.path.exists(pcap):
            failures.append(f"missing_pcap: {pcap}")
            continue

        base = os.path.splitext(os.path.basename(pcap))[0]
        pkt_csv = os.path.join(packets_dir, base + ".packets.csv")
        win_csv = os.path.join(windows_dir, base + ".windows_1s.csv")

        try:
            need_packets = args.reextract or not packets_csv_seems_parseable(pkt_csv)
            if need_packets:
                print(f"PCAP: {pcap}")
                print(f"  tshark -> {pkt_csv}")
                extract_packets_csv(pcap, pkt_csv, tolerate_truncated_tail=tolerate_truncated)

            if args.force or not os.path.exists(win_csv):
                meta = {
                    "label": r.get("label", ""),
                    "scenario": r.get("scenario", ""),
                    "attack_driver": r.get("attack_driver", ""),
                    "normal_traffic": r.get("normal_traffic", ""),
                    "capture_point": r.get("capture_point", ""),
                    "pcap_file": pcap,
                }
                print(f"  aggregate -> {win_csv}")
                g = packets_to_windows_1s(pkt_csv, meta)
                g.to_csv(win_csv, index=False)
        except Exception as e:
            failures.append(f"{base}: {e}")

    print(f"Rebuilding combined -> {out_all}")
    build_combined(runs, windows_dir, out_all)

    if failures:
        print("\nFAILED RUNS:")
        for f in failures:
            print("-", f)
        return 2

    print("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
