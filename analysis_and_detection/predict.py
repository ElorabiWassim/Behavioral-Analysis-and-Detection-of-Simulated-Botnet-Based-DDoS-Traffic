"""Two-stage scorer: predict ``phase`` first, then ``attack_family`` on attack rows.

The detector is a stacked pair of models trained from the same windowed CSV:

* **Primary** -- ``phase_model.joblib`` produced by ``train_phase.py``.
  Predicts ``phase in {normal, pre_attack, attack}`` for every window.
  Operationally the value is the ``pre_attack`` class -- it gives the SOC
  a few seconds of lead time before the flood saturates the target.

* **Secondary** -- ``attack_family_model.joblib`` produced by
  ``train_attack_family.py``. Only consulted on rows the primary model
  flagged as ``attack``; predicts the family in
  ``{tcp, udp, icmp, http, mixed}`` (or ``{tcp_like, udp, icmp, mixed}``
  if the secondary was trained with ``--merge-tcp-http``).

Output columns added to the input CSV
-------------------------------------
    pred_phase             primary prediction per window
    pred_phase_confidence  max probability of the primary classifier
    pred_attack_family     secondary prediction (only on phase==attack rows)
    pred_attack_confidence max probability of the secondary classifier
                           (0 on rows the secondary did not score)

Usage
-----
    # Two-stage (default): primary -> secondary on attack rows
    python analysis_and_detection/predict.py --csv path/to/windows.csv

    # Save predictions
    python analysis_and_detection/predict.py --csv path/to/windows.csv \
            --out path/to/predictions.csv

    # Score the secondary on EVERY row, not just primary-flagged attacks
    python analysis_and_detection/predict.py --csv path/to/windows.csv \
            --secondary-all-rows

    # Use only the secondary stage with the dataset's ground-truth phase
    # (legacy mode, mirrors the old single-stage behaviour)
    python analysis_and_detection/predict.py --csv path/to/windows.csv \
            --no-primary
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PHASE_MODEL = SCRIPT_DIR / "artifacts" / "phase_model.joblib"
DEFAULT_FAMILY_MODEL = SCRIPT_DIR / "artifacts" / "attack_family_model.joblib"


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


def _load_bundle(path: Path, label: str):
    if not path.exists():
        raise SystemExit(
            f"{label} model not found at {path}. "
            f"Train it first ({'train_phase.py' if 'phase' in label else 'train_attack_family.py'})."
        )
    return joblib.load(path)


def _align_features(df: pd.DataFrame, feat_cols: list[str], label: str) -> pd.DataFrame:
    missing = [c for c in feat_cols if c not in df.columns]
    if missing:
        raise SystemExit(
            f"Input CSV is missing feature columns required by the {label} model:\n  "
            + ", ".join(missing)
        )
    return df[feat_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)


def _score_primary(df: pd.DataFrame, bundle) -> tuple[pd.Series, pd.Series]:
    """Return (predicted_phase, max_proba) aligned to df.index."""
    feat_cols: list[str] = bundle["feature_columns"]
    drops_silent = bundle.get("drops_silent_rows", True)
    model = bundle["model"]

    # Vantages with packet_count == 0 were excluded at train time. They are
    # trivially "normal" by construction (no traffic to flag), so we short-
    # circuit them with confidence 1.0 instead of asking the model to
    # extrapolate outside its training distribution.
    if drops_silent and "packet_count" in df.columns:
        scorable = df["packet_count"] > 0
    else:
        scorable = pd.Series(True, index=df.index)

    pred = pd.Series("normal", index=df.index, dtype=object)
    proba = pd.Series(1.0, index=df.index, dtype=float)

    if scorable.any():
        X = _align_features(df.loc[scorable], feat_cols, "primary phase")
        pred.loc[scorable] = model.predict(X)
        proba.loc[scorable] = model.predict_proba(X).max(axis=1)
    return pred, proba


def _score_secondary(df: pd.DataFrame, bundle, mask: pd.Series) -> tuple[pd.Series, pd.Series]:
    """Return (pred_family, max_proba); rows outside ``mask`` are blank/0."""
    feat_cols: list[str] = bundle["feature_columns"]
    needs_context = bundle.get("uses_context_features", False)
    model = bundle["model"]

    pred = pd.Series("", index=df.index, dtype=object)
    proba = pd.Series(0.0, index=df.index, dtype=float)

    if not mask.any():
        return pred, proba

    work = df
    if needs_context and not all(c in df.columns for c in feat_cols):
        work = _add_context_features(df)

    X = _align_features(work.loc[mask], feat_cols, "secondary attack-family")
    pred.loc[mask] = model.predict(X)
    proba.loc[mask] = model.predict_proba(X).max(axis=1)
    return pred, proba


def _print_phase_report(df: pd.DataFrame) -> None:
    counts = df["pred_phase"].value_counts()
    print("\nPrimary (phase) prediction counts:")
    for ph, n in counts.items():
        print(f"  {ph:<10} {n:>6}")
    if "phase" in df.columns:
        agreed = (df["phase"] == df["pred_phase"]).mean()
        print(f"  accuracy vs ground-truth phase: {agreed:.4f}")


def _print_family_report(df: pd.DataFrame, mask: pd.Series) -> None:
    if not mask.any():
        print("\nSecondary (attack_family): no rows scored.")
        return
    print(f"\nSecondary (attack_family) scored {int(mask.sum())} row(s).")
    if "attack_family" in df.columns:
        truth = df.loc[mask, "attack_family"]
        pred = df.loc[mask, "pred_attack_family"]
        agreed = (truth == pred).mean()
        print(f"  accuracy vs ground-truth attack_family (on scored rows): {agreed:.4f}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", type=Path, required=True,
                        help="Windows CSV to score.")
    parser.add_argument("--phase-model", type=Path, default=DEFAULT_PHASE_MODEL,
                        help="Primary phase-classifier joblib (default: %(default)s).")
    parser.add_argument("--family-model", type=Path, default=DEFAULT_FAMILY_MODEL,
                        help="Secondary attack-family joblib (default: %(default)s).")
    parser.add_argument("--out", type=Path, default=None,
                        help="Optional output CSV path. If omitted, only a "
                             "summary is printed.")
    parser.add_argument("--no-primary", action="store_true",
                        help="Skip the primary stage. Use the dataset's "
                             "ground-truth 'phase' column to gate the "
                             "secondary (legacy single-stage behaviour).")
    parser.add_argument("--secondary-all-rows", action="store_true",
                        help="Run the secondary classifier on EVERY row "
                             "(ignore the primary's phase prediction).")
    args = parser.parse_args()

    df = pd.read_csv(args.csv)

    # ------------------------------------------------------------------
    # Primary stage: phase
    # ------------------------------------------------------------------
    if args.no_primary:
        if "phase" not in df.columns:
            raise SystemExit(
                "--no-primary requires a 'phase' column in the input CSV."
            )
        df["pred_phase"] = df["phase"]
        df["pred_phase_confidence"] = 1.0
        print("== primary stage: SKIPPED (--no-primary, using ground-truth 'phase')")
    else:
        print(f"== primary stage: phase model {args.phase_model.name}")
        phase_bundle = _load_bundle(args.phase_model, "primary phase")
        pred_phase, pred_phase_proba = _score_primary(df, phase_bundle)
        df["pred_phase"] = pred_phase
        df["pred_phase_confidence"] = pred_phase_proba

    _print_phase_report(df)

    # ------------------------------------------------------------------
    # Secondary stage: attack_family (gated by primary unless overridden)
    # ------------------------------------------------------------------
    if args.secondary_all_rows:
        sec_mask = pd.Series(True, index=df.index)
    else:
        sec_mask = df["pred_phase"] == "attack"

    print(f"\n== secondary stage: family model {args.family_model.name}")
    family_bundle = _load_bundle(args.family_model, "secondary attack-family")
    pred_family, pred_family_proba = _score_secondary(df, family_bundle, sec_mask)
    df["pred_attack_family"] = pred_family
    df["pred_attack_confidence"] = pred_family_proba

    _print_family_report(df, sec_mask)

    # ------------------------------------------------------------------
    # Preview
    # ------------------------------------------------------------------
    show_cols = [c for c in
                 ("scenario_id", "phase", "pred_phase", "pred_phase_confidence",
                  "attack_family", "pred_attack_family", "pred_attack_confidence")
                 if c in df.columns]
    print("\nPreview (first 20 rows):\n")
    print(df[show_cols].head(20).to_string(index=False))

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(args.out, index=False)
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
