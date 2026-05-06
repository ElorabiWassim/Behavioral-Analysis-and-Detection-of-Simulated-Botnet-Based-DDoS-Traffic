# Attack-family classifier (stage 2)

Predicts the **attack family** of a 1-second traffic window once an
upstream detector has flagged it as `phase == "attack"`. The output is
one of:

| label   | description                              |
|---------|------------------------------------------|
| `tcp`   | TCP-connect flood (3-way handshake churn)|
| `udp`   | UDP datagram flood                       |
| `icmp`  | ICMP echo flood                          |
| `http`  | HTTP `GET /` flood                       |
| `mixed` | tcp -> udp -> icmp phased run            |

The model is a `RandomForestClassifier` trained on the per-window
behavioral features produced by `pipeline/pcap_to_ml_windows.py`
(38 numeric features: protocol counts and ratios, TCP-flag ratios,
flow / source diversity, C2-channel activity, burstiness, 5 s rolling
context, past-baseline z-scores).

## Inputs

- `dataset/processed/windows_1s_all.csv` (the union of every per-scenario
  windows file, also produced by `pcap_to_ml_windows.py`).
- Only rows where `phase == "attack"` are kept; the model never sees
  benign / pre-attack / post-attack windows.

## Leakage controls

The CSV ships several columns that trivially encode the label:

- `scenario_id` is literally `"tcp-medium"`, `"http-high"`, ...
- `capture_id` embeds the same string.
- `attack_start_time`, `window_start_time`, `relative_time`,
  `window_duration` either pin a specific capture or are constant.

All of those plus the labels themselves (`phase`, `attack_family`) are
dropped before training. The 38 remaining columns are pure behavioral
features, leaving 38 numeric inputs.

## Train

From the project root:

```powershell
pip install -r analysis_and_detection/requirements.txt
python analysis_and_detection/train_attack_family.py
```

This will:

1. Load `dataset/processed/windows_1s_all.csv`, filter to attack-phase
   rows (5 280 rows on the current dataset).
2. Run 5-fold `StratifiedKFold` cross-validation (reports
   accuracy + macro-F1 per fold).
3. Fit a final model on an 80 / 20 stratified split and write artifacts
   under `analysis_and_detection/artifacts/`:
   - `attack_family_rf.joblib` — model + feature column list + class list
   - `confusion_matrix.png`
   - `feature_importances.png`
   - `report.txt`     — text classification report
   - `metrics.json`   — machine-readable summary

Common overrides:

```powershell
python analysis_and_detection/train_attack_family.py --test-size 0.25 --seed 7
python analysis_and_detection/train_attack_family.py --data path/to/other.csv
```

## Predict

Score any `windows.csv` produced by `pcap_to_ml_windows.py`:

```powershell
python analysis_and_detection/predict.py --csv dataset/processed/windows_1s_all.csv --out predictions.csv
```

The output gets two extra columns:

- `pred_attack_family` — the predicted family (only for rows the model
  was asked to score; empty otherwise).
- `pred_confidence`    — the max class probability for that prediction.

By default only rows with `phase == "attack"` are scored; pass
`--all-rows` to score everything (e.g. when stitching this stage to a
primary detector that also flags pre/post windows).

If the input CSV still has a ground-truth `attack_family` column, the
script also prints the agreement rate as a quick sanity check.

## Why Random Forest?

Each family has a near-deterministic protocol fingerprint in this
feature set (`tcp_ratio`, `udp_ratio`, `icmp_ratio`, `syn_ratio`,
`unique_dst_port_count`, `avg_packet_size`, ...), so a tree-based model
can carve them apart cleanly without feature scaling. With ~5 k attack
rows and 5 classes, training takes a few seconds and reliably reaches
> 0.99 macro-F1 with the leakage columns removed.

## Stitching to a primary detector

In production the pipeline is two stages:

1. **Primary detector** (binary or multi-phase): per-window decision of
   `attack` vs everything else.
2. **This classifier**: only invoked on windows the primary flagged as
   `attack`. Output is the family + confidence.

`predict.py` already implements that contract — by default it only
scores rows with `phase == "attack"`, so you can feed it the primary's
output unchanged.
