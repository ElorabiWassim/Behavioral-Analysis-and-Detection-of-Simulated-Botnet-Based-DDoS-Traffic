"""Secondary classifier: predict ``attack_family`` for attack windows.

This is the "stage 2" model: a primary detector decides whether a window is
under attack (``phase == "attack"``); this model then says *which* family
of attack it is — one of ``tcp``, ``udp``, ``icmp``, ``http``, ``mixed``.

Inputs
------
``dataset/processed/windows_1s_all.csv`` produced by
``pipeline/pcap_to_ml_windows.py``. Only rows where ``phase == "attack"``
are used; everything else is ignored.

Leakage controls
----------------
The CSV contains several columns that trivially encode the answer:
``scenario_id`` literally is ``"tcp-medium"`` etc., and ``capture_id``
embeds the scenario name. Those are dropped before training.

Outputs (written under ``analysis_and_detection/artifacts/``)
-------------------------------------------------------------
* ``attack_family_rf.joblib`` — fitted ``RandomForestClassifier`` plus the
  exact list of feature columns it expects (so ``predict.py`` can align
  arbitrary new dataframes).
* ``confusion_matrix.png`` and ``feature_importances.png``
* ``report.txt``  — human-readable classification report
* ``metrics.json`` — machine-readable summary (CV folds + held-out test)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import (
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import (
    StratifiedKFold,
    cross_val_score,
    train_test_split,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

DEFAULT_DATA = PROJECT_ROOT / "dataset" / "processed" / "windows_1s_all.csv"
DEFAULT_OUT = SCRIPT_DIR / "artifacts"

ATTACK_FAMILIES_5 = ["tcp", "udp", "icmp", "http", "mixed"]
ATTACK_FAMILIES_4 = ["tcp_like", "udp", "icmp", "mixed"]

# Columns that either are the label or leak it (capture_id / scenario_id
# literally encode the family in their name; window/attack timestamps
# encode the capture identity).
DROP_COLUMNS = [
    "capture_id",
    "scenario_id",
    "window_start_time",
    "attack_start_time",
    "relative_time",
    "window_duration",
    "phase",
    "attack_family",
]

# Default minimum packet count for an attack window to be considered
# scorable. Vantages that see no attack traffic (e.g. ISP-F egress, the
# C2 uplink) produce attack-phase rows with packet_count near 0; a real
# primary detector would never flag those as attacks, so they are pure
# label noise for this stage.
DEFAULT_MIN_PACKETS = 50


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------
def load_attack_rows(
    csv_path: Path,
    min_packets: int,
    merge_tcp_http: bool,
) -> pd.DataFrame:
    """Load attack-phase rows, drop noise vantages, optionally merge tcp+http.

    The HTTP-flood and TCP-connect-flood are network-indistinguishable on
    the per-second feature schema once the target's accept queue saturates
    (both produce SYN -> SYN-ACK -> ACK -> RST churn at 64 B avg). Setting
    ``merge_tcp_http=True`` collapses them into a single ``tcp_like``
    class, which is appropriate when the goal is response triage rather
    than forensic family identification.
    """
    df = pd.read_csv(csv_path)
    if "phase" not in df.columns or "attack_family" not in df.columns:
        raise SystemExit(
            f"{csv_path} is missing 'phase' or 'attack_family'. "
            "Make sure it was produced by pipeline/pcap_to_ml_windows.py."
        )
    attack = df[df["phase"] == "attack"].copy()
    attack = attack[attack["attack_family"].isin(ATTACK_FAMILIES_5)].reset_index(drop=True)
    if attack.empty:
        raise SystemExit(
            "No rows with phase=='attack' in the supplied CSV. "
            "Did you point at the right file?"
        )

    # Drop vantages that produced attack-phase rows but saw no attack
    # traffic. Keeps only windows a primary detector would ever flag.
    if min_packets > 0:
        before = len(attack)
        attack = attack[attack["packet_count"] >= min_packets].reset_index(drop=True)
        print(f"   dropped {before - len(attack)} rows with packet_count<{min_packets} "
              f"(zero-traffic vantages such as ISP-F egress / C2 uplink)")

    if merge_tcp_http:
        attack["attack_family"] = attack["attack_family"].replace(
            {"tcp": "tcp_like", "http": "tcp_like"}
        )

    return attack


def add_capture_context_features(df: pd.DataFrame) -> pd.DataFrame:
    """Per-capture rolling features that help separate `mixed` from pure runs.

    A `mixed` capture cycles tcp -> udp -> icmp over its duration, so the
    *standard deviation* of the protocol ratios over the last ~10 s is
    high; a pure flood keeps the same dominant protocol throughout, so
    the std collapses to zero. Computed strictly causally with a rolling
    window grouped by ``capture_id`` so there is no leakage across
    different captures.
    """
    df = df.sort_values(["capture_id", "window_start_time"]).reset_index(drop=True)
    for col in ("tcp_ratio", "udp_ratio", "icmp_ratio"):
        df[f"{col}_std_10s"] = (
            df.groupby("capture_id")[col]
              .transform(lambda s: s.rolling(10, min_periods=1).std().fillna(0.0))
        )
    df["proto_diversity_10s"] = (
        df["tcp_ratio_std_10s"] + df["udp_ratio_std_10s"] + df["icmp_ratio_std_10s"]
    )
    return df


def build_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    y = df["attack_family"].astype(str)
    X = df.drop(columns=[c for c in DROP_COLUMNS if c in df.columns])
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0.0)
    return X, y


# ---------------------------------------------------------------------------
# Modelling
# ---------------------------------------------------------------------------
def make_classifier(model_name: str, seed: int):
    if model_name == "gbt":
        return HistGradientBoostingClassifier(
            max_iter=600,
            learning_rate=0.08,
            max_leaf_nodes=63,
            l2_regularization=0.0,
            random_state=seed,
        )
    if model_name == "rf":
        return RandomForestClassifier(
            n_estimators=500,
            max_features="sqrt",
            min_samples_leaf=1,
            n_jobs=-1,
            class_weight="balanced",
            random_state=seed,
        )
    raise ValueError(f"unknown model: {model_name!r} (choose 'gbt' or 'rf')")


def evaluate_cv(
    X: pd.DataFrame,
    y: pd.Series,
    model_name: str,
    n_splits: int,
    seed: int,
) -> tuple[list[float], list[float]]:
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    accs = cross_val_score(
        make_classifier(model_name, seed), X, y,
        cv=skf, scoring="accuracy", n_jobs=1,
    )
    f1s = cross_val_score(
        make_classifier(model_name, seed), X, y,
        cv=skf, scoring="f1_macro", n_jobs=1,
    )
    return accs.tolist(), f1s.tolist()


# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------
def save_confusion_matrix(cm, classes: list[str], acc: float, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(6, 5))
    ConfusionMatrixDisplay(cm, display_labels=classes).plot(
        ax=ax, cmap="Blues", colorbar=False, values_format="d"
    )
    ax.set_title(f"Attack-family confusion matrix  (acc = {acc:.4f})")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def save_feature_importances(importances: pd.Series, path: Path, top_n: int = 20) -> None:
    fig, ax = plt.subplots(figsize=(8, 8))
    importances.head(top_n).iloc[::-1].plot.barh(ax=ax, color="#1648a8")
    ax.set_title(f"Top-{top_n} feature importances")
    ax.set_xlabel("importance")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def compute_feature_importances(model, X_train: pd.DataFrame, y_train: pd.Series) -> pd.Series:
    """Return per-feature importance, regardless of estimator type.

    RandomForest exposes ``feature_importances_`` directly. HistGradient-
    Boosting does not (it tracks importances internally but doesn't
    surface them on multiclass), so we fall back to permutation
    importance, which works for any sklearn estimator.
    """
    if hasattr(model, "feature_importances_"):
        return pd.Series(model.feature_importances_, index=X_train.columns).sort_values(ascending=False)
    from sklearn.inspection import permutation_importance
    result = permutation_importance(
        model, X_train, y_train,
        n_repeats=5, random_state=0, n_jobs=-1, scoring="f1_macro",
    )
    return pd.Series(result.importances_mean, index=X_train.columns).sort_values(ascending=False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA,
                        help="Path to windows_1s_all.csv (default: %(default)s)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="Output directory for artifacts (default: %(default)s)")
    parser.add_argument("--model", choices=("gbt", "rf"), default="gbt",
                        help="Classifier: HistGradientBoosting (default) or RandomForest.")
    parser.add_argument("--min-packets", type=int, default=DEFAULT_MIN_PACKETS,
                        help="Drop attack rows with packet_count below this "
                             "threshold (zero-traffic vantages). Default: %(default)s.")
    parser.add_argument("--merge-tcp-http", action="store_true",
                        help="Collapse 'tcp' and 'http' into a single 'tcp_like' "
                             "class (they are network-indistinguishable when "
                             "the target's accept queue saturates).")
    parser.add_argument("--no-context-features", action="store_true",
                        help="Skip the rolling protocol-diversity features.")
    parser.add_argument("--test-size", type=float, default=0.2,
                        help="Held-out test fraction (default: %(default)s)")
    parser.add_argument("--cv-splits", type=int, default=5,
                        help="StratifiedKFold splits (default: %(default)s)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    print(f"== loading {args.data}")
    df = load_attack_rows(args.data, args.min_packets, args.merge_tcp_http)
    if not args.no_context_features:
        df = add_capture_context_features(df)
    label_set = ATTACK_FAMILIES_4 if args.merge_tcp_http else ATTACK_FAMILIES_5

    print(f"   attack rows : {len(df):,}")
    print("   class counts:")
    for fam, n in df["attack_family"].value_counts().items():
        print(f"     {fam:<8} {n:>5}")

    X, y = build_features(df)
    print(f"   features    : {X.shape[1]}")
    print(f"   model       : {args.model}")

    # --------------------------------------------------------------
    # K-fold CV (a robust headline number, no test-split variance)
    # --------------------------------------------------------------
    print(f"\n== {args.cv_splits}-fold StratifiedKFold cross-validation")
    accs, f1s = evaluate_cv(X, y, args.model, n_splits=args.cv_splits, seed=args.seed)
    cv_acc_mean = sum(accs) / len(accs)
    cv_f1_mean = sum(f1s) / len(f1s)
    cv_acc_std = pd.Series(accs).std()
    cv_f1_std = pd.Series(f1s).std()
    print(f"   accuracy : {cv_acc_mean:.4f} +/- {cv_acc_std:.4f}   folds={[round(a, 4) for a in accs]}")
    print(f"   f1_macro : {cv_f1_mean:.4f} +/- {cv_f1_std:.4f}   folds={[round(f, 4) for f in f1s]}")

    # --------------------------------------------------------------
    # Held-out test: fit on 80%, evaluate on 20%
    # --------------------------------------------------------------
    print(f"\n== train/test split ({1 - args.test_size:.0%} / {args.test_size:.0%})")
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=args.seed
    )
    clf = make_classifier(args.model, args.seed)
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)

    test_acc = accuracy_score(y_te, y_pred)
    test_f1 = f1_score(y_te, y_pred, average="macro")
    print(f"   test accuracy : {test_acc:.4f}")
    print(f"   test f1_macro : {test_f1:.4f}")
    report = classification_report(y_te, y_pred, digits=4)
    print("\n" + report)

    cm = confusion_matrix(y_te, y_pred, labels=label_set)

    # --------------------------------------------------------------
    # Artifacts
    # --------------------------------------------------------------
    cm_path = args.out / "confusion_matrix.png"
    save_confusion_matrix(cm, label_set, test_acc, cm_path)
    print(f"   wrote {cm_path}")

    importances = compute_feature_importances(clf, X_tr, y_tr)
    fi_path = args.out / "feature_importances.png"
    save_feature_importances(importances, fi_path)
    print(f"   wrote {fi_path}")

    model_path = args.out / "attack_family_model.joblib"
    joblib.dump(
        {
            "model": clf,
            "model_kind": args.model,
            "feature_columns": list(X.columns),
            "classes": list(clf.classes_),
            "drop_columns": DROP_COLUMNS,
            "min_packets": args.min_packets,
            "merged_tcp_http": args.merge_tcp_http,
            "uses_context_features": not args.no_context_features,
        },
        model_path,
    )
    print(f"   wrote {model_path}")

    txt_path = args.out / "report.txt"
    with txt_path.open("w", encoding="utf-8") as f:
        f.write("Attack-family classifier\n")
        f.write("========================\n\n")
        f.write(f"data           : {args.data}\n")
        f.write(f"model          : {args.model}\n")
        f.write(f"min_packets    : {args.min_packets}\n")
        f.write(f"merge_tcp_http : {args.merge_tcp_http}\n")
        f.write(f"context_feats  : {not args.no_context_features}\n")
        f.write(f"attack rows    : {len(df)}\n\n")
        f.write("Class counts:\n")
        f.write(df["attack_family"].value_counts().to_string() + "\n\n")
        f.write(f"{args.cv_splits}-fold StratifiedKFold:\n")
        f.write(f"  accuracy : {cv_acc_mean:.4f} +/- {cv_acc_std:.4f}\n")
        f.write(f"  f1_macro : {cv_f1_mean:.4f} +/- {cv_f1_std:.4f}\n\n")
        f.write(f"Held-out test ({1 - args.test_size:.0%} / {args.test_size:.0%}):\n")
        f.write(f"  accuracy : {test_acc:.4f}\n")
        f.write(f"  f1_macro : {test_f1:.4f}\n\n")
        f.write("Classification report:\n")
        f.write(report)
        f.write("\nConfusion matrix (rows=true, cols=pred):\n")
        f.write("           " + "  ".join(f"{c:>8}" for c in label_set) + "\n")
        for i, fam in enumerate(label_set):
            f.write(
                f"{fam:>10} "
                + "  ".join(f"{cm[i, j]:>8d}" for j in range(len(label_set)))
                + "\n"
            )
        f.write("\nTop-15 feature importances:\n")
        f.write(importances.head(15).to_string() + "\n")
    print(f"   wrote {txt_path}")

    metrics = {
        "data": str(args.data),
        "model": args.model,
        "min_packets": args.min_packets,
        "merge_tcp_http": args.merge_tcp_http,
        "context_features": not args.no_context_features,
        "n_attack_rows": int(len(df)),
        "class_counts": df["attack_family"].value_counts().to_dict(),
        "feature_columns": list(X.columns),
        "cv": {
            "n_splits": args.cv_splits,
            "accuracy_mean": cv_acc_mean,
            "accuracy_std": float(cv_acc_std),
            "accuracy_folds": accs,
            "f1_macro_mean": cv_f1_mean,
            "f1_macro_std": float(cv_f1_std),
            "f1_macro_folds": f1s,
        },
        "test": {
            "test_size": args.test_size,
            "accuracy": float(test_acc),
            "f1_macro": float(test_f1),
            "confusion_matrix": cm.tolist(),
            "labels": label_set,
        },
        "feature_importances_top10": importances.head(10).to_dict(),
    }
    metrics_path = args.out / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"   wrote {metrics_path}")


if __name__ == "__main__":
    main()
