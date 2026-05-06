# Two-stage detector

The detector is a stacked pair of classifiers, each trained from the
same windowed CSV produced by `pipeline/pcap_to_ml_windows.py`.

| Stage          | Model file                       | Trainer                       | Predicts                                            |
|----------------|----------------------------------|-------------------------------|-----------------------------------------------------|
| **Primary**    | `phase_model.joblib`             | `train_phase.py`              | `phase in {normal, pre_attack, attack}`             |
| **Secondary**  | `attack_family_model.joblib`     | `train_attack_family.py`      | `attack_family in {tcp, udp, icmp, http, mixed}`    |

The operational value of the **primary** model is the `pre_attack`
class — it gives the SOC a few seconds of lead time before the flood
saturates the target. The 10-second pre-attack ramp emitted by
`Traffic/attack_scripts_C2.sh` (4 / 16 / 36 / 64 / 100 % of peak rate)
is what makes that label learnable.

The **secondary** model only fires on windows the primary flagged as
`attack`, and tells the operator *which* family of attack it is so the
right runbook can be triggered.

| label   | description                              |
|---------|------------------------------------------|
| `tcp`   | TCP-connect flood (3-way handshake churn)|
| `udp`   | UDP datagram flood                       |
| `icmp`  | ICMP echo flood                          |
| `http`  | HTTP `GET /` flood                       |
| `mixed` | tcp -> udp -> icmp phased run            |

There is **no** `post_attack` class: windows after `attack_end` fold
back into `normal`. The defender goal is *early* detection during
ramp-up, not forensic decay analysis.

## Inputs

`dataset/processed/windows_1s_all.csv` — the concatenated per-scenario
windows file produced by `Traffic/collect_dataset.sh`. Each row is a
1-second window with 38 behavioural features plus metadata + labels.

## Leakage controls

Both trainers drop the columns that trivially encode the label
(`scenario_id`, `capture_id`, the absolute / relative timestamps,
`window_duration`, plus `phase` / `attack_family`). The 38 remaining
columns are pure behavioural features.

The phase trainer additionally uses `GroupKFold` on `capture_id` so the
strict cross-validation never lets the model memorise a specific
capture.

## Train

From the project root:

```powershell
pip install -r analysis_and_detection/requirements.txt

# stage 1 -- phase (normal / pre_attack / attack)
python analysis_and_detection/train_phase.py

# stage 2 -- attack family (only attack rows)
python analysis_and_detection/train_attack_family.py
```

`train_phase.py` writes:

- `artifacts/phase_model.joblib` — model + feature columns + class list
- `artifacts/phase_confusion_matrix.png`
- `artifacts/phase_feature_importances.png`
- `artifacts/phase_report.txt` / `phase_metrics.json`

`train_attack_family.py` writes:

- `artifacts/attack_family_model.joblib`
- `artifacts/confusion_matrix.png`
- `artifacts/feature_importances.png`
- `artifacts/report.txt` / `metrics.json`

Common overrides on either trainer:

```powershell
python analysis_and_detection/train_phase.py --model rf --seed 7
python analysis_and_detection/train_attack_family.py --merge-tcp-http
```

## Predict (chained)

`predict.py` runs both stages by default: the primary scores every
window, and the secondary only scores rows the primary flagged as
`attack`.

```powershell
python analysis_and_detection/predict.py `
    --csv dataset/processed/windows_1s_all.csv `
    --out predictions.csv
```

Output columns added to the CSV:

| column                    | meaning                                                   |
|---------------------------|-----------------------------------------------------------|
| `pred_phase`              | primary prediction per window                             |
| `pred_phase_confidence`   | max class probability of the primary classifier           |
| `pred_attack_family`      | secondary prediction (blank on rows it didn't score)      |
| `pred_attack_confidence`  | max class probability of the secondary (0 if not scored)  |

If the input CSV still has ground-truth `phase` / `attack_family`
columns, the script also prints agreement rates as a sanity check.

Modes:

```powershell
# default: primary -> secondary on attack rows
python analysis_and_detection/predict.py --csv windows.csv

# bypass the primary; gate the secondary with the dataset's true 'phase'
python analysis_and_detection/predict.py --csv windows.csv --no-primary

# force the secondary to score every row, ignoring the primary's gate
python analysis_and_detection/predict.py --csv windows.csv --secondary-all-rows
```

## Why these models?

- **HistGradientBoosting** (default for both stages): handles the rolling
  z-score / slope features well, no scaling needed, training in seconds.
- **RandomForest** (`--model rf`): kept as an alternative for the phase
  stage and used by default for the family stage. Each attack family has
  a near-deterministic protocol fingerprint (`tcp_ratio`, `udp_ratio`,
  `syn_ratio`, `unique_dst_port_count`, ...), which a tree ensemble can
  carve apart cleanly with no scaling.
