"""Score a windows CSV with the trained attack-family classifier.

Loads the joblib bundle written by ``train_attack_family.py``, aligns the
input dataframe to the exact training feature columns, and writes a copy
with two extra columns: ``pred_attack_family`` and ``pred_confidence``
(max class probability). By default only rows with ``phase == "attack"``
are scored; pass ``--all-rows`` to score everything.

Usage
-----
    python analysis_and_detection/predict.py --csv path/to/windows.csv
    python analysis_and_detection/predict.py --csv path/to/windows.csv \
            --out path/to/predictions.csv
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL = SCRIPT_DIR / "artifacts" / "attack_family_model.joblib"


def _add_context_features(df: pd.DataFrame) -> pd.DataFrame:
    """Recreate the rolling protocol-diversity features used during training."""
    if "capture_id" not in df.columns or "window_start_time" not in df.columns:
        # Best-effort: without those, treat each row as its own group.
        df = df.copy()
        for col in ("tcp_ratio", "udp_ratio", "icmp_ratio"):
            if col in df.columns:
                df[f"{col}_std_10s"] = 0.0
        df["proto_diversity_10s"] = 0.0
        return df
    df = df.sort_values(["capture_id", "window_start_time"]).copy()
    for col in ("tcp_ratio", "udp_ratio", "icmp_ratio"):
        if col not in df.columns:
            continue
        df[f"{col}_std_10s"] = (
            df.groupby("capture_id")[col]
              .transform(lambda s: s.rolling(10, min_periods=1).std().fillna(0.0))
        )
    df["proto_diversity_10s"] = (
        df.get("tcp_ratio_std_10s", 0.0)
        + df.get("udp_ratio_std_10s", 0.0)
        + df.get("icmp_ratio_std_10s", 0.0)
    )
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True,
                        help="Windows CSV to score.")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL,
                        help="Path to the joblib bundle (default: %(default)s)")
    parser.add_argument("--out", type=Path, default=None,
                        help="Optional output CSV path. If omitted, a "
                             "summary is printed but nothing is saved.")
    parser.add_argument("--all-rows", action="store_true",
                        help="Score every row, not just phase=='attack'.")
    args = parser.parse_args()

    bundle = joblib.load(args.model)
    model = bundle["model"]
    feat_cols: list[str] = bundle["feature_columns"]
    needs_context = bundle.get("uses_context_features", False)

    df = pd.read_csv(args.csv)

    if needs_context and not all(c in df.columns for c in feat_cols):
        df = _add_context_features(df)

    if not args.all_rows and "phase" in df.columns:
        mask = df["phase"] == "attack"
    else:
        mask = pd.Series(True, index=df.index)

    if not mask.any():
        print("No rows match the selection (phase == 'attack'). Use --all-rows to override.")
        return

    missing = [c for c in feat_cols if c not in df.columns]
    if missing:
        raise SystemExit(
            "Input CSV is missing feature columns required by the model:\n  "
            + ", ".join(missing)
        )

    X = df.loc[mask, feat_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    pred = model.predict(X)
    proba = model.predict_proba(X).max(axis=1)

    df["pred_attack_family"] = ""
    df["pred_confidence"] = 0.0
    df.loc[mask, "pred_attack_family"] = pred
    df.loc[mask, "pred_confidence"] = proba

    show_cols = [c for c in
                 ("scenario_id", "phase", "attack_family",
                  "pred_attack_family", "pred_confidence")
                 if c in df.columns]
    print(f"scored {mask.sum()} row(s); preview:\n")
    print(df.loc[mask, show_cols].head(20).to_string(index=False))

    if "attack_family" in df.columns:
        agreed = (df.loc[mask, "attack_family"] == df.loc[mask, "pred_attack_family"]).mean()
        print(f"\naccuracy vs ground-truth attack_family: {agreed:.4f}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(args.out, index=False)
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
