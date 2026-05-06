"""Leakage audit for the attack-family classifier.

Runs three progressively stricter cross-validation schemes on the same
feature pipeline used by ``train_attack_family.py``:

1. **StratifiedKFold** (rows shuffled, stratified on ``attack_family``).
   This is the number reported in ``metrics.json``. Rows from the same
   capture can land in both train and test, so it overestimates how well
   the model generalises to an unseen run.

2. **GroupKFold by ``capture_id``**. Every row from a given capture
   (e.g. ``c2__tcp-high__60s__..._R3_egress``) stays in a single fold.
   This measures whether the model has learned the *family signature* or
   just a per-capture fingerprint.

3. **LeaveOneGroupOut by ``scenario_id``**. Holds out an entire scenario
   (e.g. ``tcp-medium``) and trains on the others. This is the strongest
   test: for rate-varying families (tcp / udp / http with low/medium/
   high variants) it checks that the model generalises across rates; for
   ``icmp`` and ``mixed`` (only one scenario each) the family is missing
   from training when that scenario is held out, so those folds are
   expected to collapse — they're shown here only for transparency.

A substantial drop from (1) to (2) would mean capture-specific leakage.
A modest drop is normal and healthy.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import (
    GroupKFold,
    LeaveOneGroupOut,
    StratifiedKFold,
    cross_val_score,
)

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DEFAULT_DATA = PROJECT_ROOT / "dataset" / "processed" / "windows_1s_all.csv"

ATTACK_FAMILIES = ["tcp", "udp", "icmp", "http", "mixed"]
DROP = [
    "capture_id", "scenario_id", "window_start_time", "attack_start_time",
    "relative_time", "window_duration", "phase", "attack_family",
]


def load_frame(csv_path: Path, min_packets: int) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    a = df[df["phase"] == "attack"].copy()
    a = a[a["attack_family"].isin(ATTACK_FAMILIES)].reset_index(drop=True)
    a = a[a["packet_count"] >= min_packets].reset_index(drop=True)
    a = a.sort_values(["capture_id", "window_start_time"]).reset_index(drop=True)
    for col in ("tcp_ratio", "udp_ratio", "icmp_ratio"):
        a[f"{col}_std_10s"] = (
            a.groupby("capture_id")[col]
             .transform(lambda s: s.rolling(10, min_periods=1).std().fillna(0.0))
        )
    a["proto_diversity_10s"] = (
        a["tcp_ratio_std_10s"] + a["udp_ratio_std_10s"] + a["icmp_ratio_std_10s"]
    )
    return a


def run_cv(clf, X, y, cv, groups=None, label=""):
    scores = cross_val_score(
        clf, X, y, cv=cv, groups=groups, scoring="accuracy", n_jobs=1
    )
    f1s = cross_val_score(
        clf, X, y, cv=cv, groups=groups, scoring="f1_macro", n_jobs=1
    )
    print(f"   {label:<42}  acc={scores.mean():.4f} +/- {scores.std():.4f}   f1={f1s.mean():.4f}")
    return scores, f1s


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--min-packets", type=int, default=50)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    a = load_frame(args.data, args.min_packets)
    print(f"attack rows (post-filter): {len(a):,}")
    print(f"captures : {a['capture_id'].nunique()}   scenarios : {a['scenario_id'].nunique()}")
    print()

    # Columns actually consumed by the model
    X = a.drop(columns=DROP).apply(pd.to_numeric, errors="coerce").fillna(0.0)
    y = a["attack_family"].astype(str)

    print("features consumed by the model:")
    for c in X.columns:
        print(f"   - {c}")
    print()

    # Sanity: per-feature correlation with the label via mutual information
    from sklearn.feature_selection import mutual_info_classif
    mi = mutual_info_classif(X, y, random_state=args.seed, n_jobs=-1)
    mi_series = pd.Series(mi, index=X.columns).sort_values(ascending=False)
    print("top-10 mutual information with attack_family (for sanity):")
    print(mi_series.head(10).to_string())
    print()

    clf = HistGradientBoostingClassifier(
        max_iter=600, learning_rate=0.08, random_state=args.seed
    )

    print("cross-validation scores (accuracy / macro-F1):")

    # 1. StratifiedKFold (row-level shuffle, matches train_attack_family.py)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
    run_cv(clf, X, y, cv=skf, label="StratifiedKFold (row-shuffle, lax)")

    # 2. GroupKFold by capture_id (each capture in exactly one fold)
    gkf = GroupKFold(n_splits=5)
    run_cv(clf, X, y, cv=gkf, groups=a["capture_id"],
           label="GroupKFold by capture_id (strict)")

    # 3. LeaveOneGroupOut by scenario_id (hold out a whole scenario)
    #    icmp/mixed fold will be ~0 because that family is missing from training;
    #    it is reported so the user can read it critically.
    print()
    print("per-scenario leave-one-out (hold out each scenario):")
    print("   note: icmp & mixed have only 1 scenario each, so holding them")
    print("         out removes the family entirely from training -> 0%")
    print("         accuracy on that fold is *expected*, not a bug.")
    logo = LeaveOneGroupOut()
    rows = []
    for train_idx, test_idx in logo.split(X, y, groups=a["scenario_id"]):
        held = a.iloc[test_idx]["scenario_id"].iloc[0]
        clf_local = HistGradientBoostingClassifier(
            max_iter=600, learning_rate=0.08, random_state=args.seed
        )
        clf_local.fit(X.iloc[train_idx], y.iloc[train_idx])
        acc = clf_local.score(X.iloc[test_idx], y.iloc[test_idx])
        rows.append((held, len(test_idx), acc))
    rows.sort()
    print()
    print(f"   {'scenario':<14}{'rows':>6}{'accuracy':>12}")
    for name, n, acc in rows:
        flag = "  (family absent from train)" if name in ("icmp", "mixed") else ""
        print(f"   {name:<14}{n:>6}{acc:>12.4f}{flag}")

    # Focus: average excluding the two single-scenario families
    rate_aware = [acc for (name, _, acc) in rows if name not in ("icmp", "mixed")]
    print()
    print(f"mean LOSO accuracy across rate-varying scenarios only "
          f"(tcp/udp/http low/medium/high): {np.mean(rate_aware):.4f}")
    print(" -> this is the honest 'can the model generalise to an unseen *rate*' number.")


if __name__ == "__main__":
    main()
