# Member 3 + Member 4 Summary (Dataset + Features)

## Goal
Build a labeled dataset from a Mininet-based simulated botnet DDoS lab (Member 3), then convert raw PCAPs into per-second, labeled feature windows suitable for detection experiments (Member 4).

## Member 3 — Dataset capture + labeling

### Environment and topology
- The lab was executed in WSL2 using Mininet + Open vSwitch.
- The provided topology creates a datacenter network (`10.0.100.0/24`) with the target server at `10.0.100.10` and a gateway interface at `Rdc-eth0`.

### Traffic generation
- Normal background traffic is produced by `traffic/normal_traffic.sh`.
- Attack traffic is produced by `traffic/attack_scripts.sh` (hping3-driven scenarios).

### Capture point and filter
- Captures were taken at the datacenter gateway interface (`Rdc-eth0`) so the dataset reflects what a defender sees at an ingress/egress point.
- Capture filter used throughout: `host 10.0.100.10`.

### Dataset structure
- Raw captures are stored under `dataset/pcap/` (ignored by git due to size).
- Each run has a metadata JSON under `dataset/meta/`.
- `dataset/runs.csv` is the manifest used to iterate runs consistently.

### Runs captured
Captured PCAPs include:
- Normal-only baseline (no attack)
- Attack SYN flood at multiple intensities (low/medium/high)
- Mixed attack (SYN + UDP + ICMP)
- Mixed + normal background traffic

### Notes
- One capture (`attack__hping3__medium__...`) was slightly truncated at the tail. It is still usable for feature extraction; the extraction script tolerates this case.

## Member 4 — Feature engineering (per-second windows)

### Outputs
- Packet-level dumps (intermediate, large): `dataset/features/packets/*.packets.csv` (ignored by git)
- Per-run per-second windows: `dataset/features/windows_1s/*.windows_1s.csv`
- Combined dataset for modeling: `dataset/features/windows_1s_all.csv`

### Feature set (1-second windows)
For each second (`sec`), the pipeline computes:
- Volume: `packets`, `bytes`, `pps`, `bps`
- Diversity: `unique_src`
- Protocol counts: `tcp_packets`, `udp_packets`, `icmp_packets`
- TCP flags: `syn_packets`, `ack_packets`, `rst_packets`
- Ratios: `syn_ratio` (SYN/TCP), `udp_ratio` (UDP/ALL)

Labels and run context are carried into every row:
- `label`, `scenario`, `attack_driver`, `normal_traffic`, `capture_point`, `pcap_file`

### Reproducible pipeline
The script `dataset/build_features.py` builds these outputs from `dataset/runs.csv`.
It uses `tshark` with settings that prevent malformed CSV rows caused by multi-occurrence fields (e.g., ICMP packets with embedded IP headers).

## Added/modified files (brief)

### Added
- `dataset/build_features.py`
  - Batch feature builder: runs `tshark` extraction and aggregates into 1-second windows.
  - Rebuilds `dataset/features/windows_1s_all.csv` from the per-run window files.

- `dataset/meta/normal_only__Rdc-eth0__20260502_0629.json`
  - Metadata for the normal-only baseline run.

- `.gitignore`
  - Prevents committing `.venv/`, `dataset/pcap/`, and large packet-dump intermediates.

- `docs/member3_member4_report.md`
  - This report.

### Modified
- `dataset/runs.csv`
  - Manifest of all runs and their metadata paths.

## What to use for Member 5
Use this as the primary input dataset:
- `dataset/features/windows_1s_all.csv`

Recommended split rule for evaluation:
- Split by `pcap_file` (grouped split) to avoid leaking near-identical adjacent seconds across train/test.
