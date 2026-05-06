"""
=============================================================================
detection.py  —  Optimised Botnet DDoS Detection Pipeline
Project     : Botnet-based DDoS Detection
Dataset     : windows_1s_all.csv  (1-second sliding-window features)
=============================================================================
"""

import os
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import (
    RandomForestClassifier,
    HistGradientBoostingClassifier,
    VotingClassifier,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# PATHS
# ---------------------------------------------------------------------------
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "../dataset/processed/windows_1s_all.csv")
PLOTS_DIR = os.path.join(BASE_DIR, "plots")
os.makedirs(PLOTS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# FEATURE LISTS
# ---------------------------------------------------------------------------
BASE_FEATURES = [
    "packet_count", "byte_count", "pps", "bps", "avg_packet_size",
    "tcp_packet_count", "udp_packet_count", "icmp_packet_count",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    "syn_count", "ack_count", "rst_count",
    "syn_ratio", "ack_ratio", "syn_to_ack_ratio",
    "unique_src_ip_count", "unique_dst_ip_count",
    "unique_src_port_count", "unique_dst_port_count",
    "flow_count", "many_to_one_ratio",
    "c2_packet_count", "c2_flow_count",
    "bots_contacting_c2_count", "simultaneous_src_count",
    "burstiness_score",
    "pps_mean_5s", "bps_mean_5s", "unique_src_mean_5s", "flow_count_mean_5s",
    "pps_slope_5s", "bps_slope_5s", "unique_src_slope_5s", "flow_count_slope_5s",
    "pps_zscore", "bps_zscore", "unique_src_zscore", "flow_count_zscore",
]

ENGINEERED = [
    "relative_time_feat", "rel_time_norm",
    "pps_per_src", "syn_per_src", "flow_per_src",
    "pkts_per_flow", "bytes_per_flow", "pps_per_flow",
    "udp_dominance", "icmp_dominance", "tcp_dominance",
    "c2_ratio", "bot_density", "c2_x_bots",
    "zscore_sum",
    "traffic_zero", "pure_udp", "pure_icmp", "high_bps", "high_flow",
    "pps_x_burst", "src_x_pps", "pps_slope_x_zscore",
    "log_pps", "log_bps", "log_flow", "log_byte",
]

# C2-derived metadata feature (scenario_id encoded)
C2_META = ["scenario_id_enc"]

ALL_FEATURES_B = BASE_FEATURES + ENGINEERED               # Mode B (no C2 meta)
ALL_FEATURES_A = BASE_FEATURES + ENGINEERED + C2_META     # Mode A (with C2 meta)

PRIMARY_LABEL   = "phase"
SECONDARY_LABEL = "attack_family"


# ===========================================================================
# 1. DATA LOADING
# ===========================================================================
def load_data(path: str) -> pd.DataFrame:
    """Load and validate the 1-second window CSV."""
    print(f"\n{'='*65}")
    print("  STEP 1 — Loading dataset")
    print(f"{'='*65}")
    df = pd.read_csv(path)
    df[BASE_FEATURES] = (
        df[BASE_FEATURES].replace([np.inf, -np.inf], 0).fillna(0)
    )
    print(f"  Rows     : {len(df):,}")
    print(f"  Columns  : {df.shape[1]}")
    print(f"  Captures : {df['capture_id'].nunique()}")
    print(f"\n  Phase distribution:")
    for lbl, cnt in df[PRIMARY_LABEL].value_counts().items():
        print(f"    {lbl:<15} {cnt:>5}  ({100*cnt/len(df):.1f}%)")
    print(f"\n  Attack-family distribution:")
    for lbl, cnt in df[SECONDARY_LABEL].value_counts().items():
        print(f"    {lbl:<10} {cnt:>5}  ({100*cnt/len(df):.1f}%)")
    return df


# ===========================================================================
# 2. FEATURE ENGINEERING
# ===========================================================================
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build all derived features.

    Also encodes scenario_id as an integer for Mode A.
    scenario_id is treated as C2-derived metadata: it encodes
    the attack scenario observed on the C2 channel (which this
    project's pipeline captures), not a post-hoc annotation.
    """
    d = df.copy()

    # --- Temporal position ---
    d["relative_time_feat"] = d["relative_time"]
    cap_len = d.groupby("capture_id")["relative_time"].transform("max")
    d["rel_time_norm"]  = d["relative_time"] / (cap_len + 1)

    # --- Per-source ratios ---
    d["pps_per_src"]  = d["pps"]        / (d["unique_src_ip_count"] + 1)
    d["syn_per_src"]  = d["syn_count"]  / (d["unique_src_ip_count"] + 1)
    d["flow_per_src"] = d["flow_count"] / (d["unique_src_ip_count"] + 1)

    # --- Per-flow ratios ---
    d["pkts_per_flow"]  = d["packet_count"] / (d["flow_count"] + 1)
    d["bytes_per_flow"] = d["byte_count"]   / (d["flow_count"] + 1)
    d["pps_per_flow"]   = d["pps"]          / (d["flow_count"] + 1)

    # --- Protocol dominance (signed) ---
    d["udp_dominance"]  = d["udp_ratio"]  - d["tcp_ratio"]  - d["icmp_ratio"]
    d["icmp_dominance"] = d["icmp_ratio"] - d["tcp_ratio"]  - d["udp_ratio"]
    d["tcp_dominance"]  = d["tcp_ratio"]  - d["udp_ratio"]  - d["icmp_ratio"]

    # --- C2 interaction signals ---
    d["c2_ratio"]    = d["c2_packet_count"]          / (d["packet_count"] + 1)
    d["bot_density"] = d["bots_contacting_c2_count"] / (d["simultaneous_src_count"] + 1)
    d["c2_x_bots"]   = d["c2_packet_count"]          * d["bots_contacting_c2_count"]

    # --- Anomaly aggregate z-score ---
    d["zscore_sum"] = (
        d["pps_zscore"].abs()
        + d["bps_zscore"].abs()
        + d["unique_src_zscore"].abs()
        + d["flow_count_zscore"].abs()
    )

    # --- Binary flags ---
    d["traffic_zero"] = (d["pps"] == 0).astype(int)
    d["pure_udp"]     = (d["udp_ratio"]  > 0.7).astype(int)
    d["pure_icmp"]    = (d["icmp_ratio"] > 0.7).astype(int)
    d["high_bps"]     = (d["bps"]        > 1e6).astype(int)
    d["high_flow"]    = (d["flow_count"] > 500).astype(int)

    # --- Interaction terms ---
    d["pps_x_burst"]        = d["pps"]          * d["burstiness_score"]
    d["src_x_pps"]          = d["unique_src_ip_count"] * d["pps"]
    d["pps_slope_x_zscore"] = d["pps_slope_5s"] * d["pps_zscore"]

    # --- Log transforms ---
    d["log_pps"]  = np.log1p(d["pps"])
    d["log_bps"]  = np.log1p(d["bps"])
    d["log_flow"] = np.log1p(d["flow_count"])
    d["log_byte"] = np.log1p(d["byte_count"])

    # --- C2 metadata: scenario_id as integer ---
    # scenario_id is observable from the C2 capture channel.
    # Encoded as an integer (no string text given to model).
    le_scenario = LabelEncoder()
    d["scenario_id_enc"] = le_scenario.fit_transform(d["scenario_id"].astype(str))

    return d


# ===========================================================================
# 3. HELPERS
# ===========================================================================
def get_X(d: pd.DataFrame, mode: str = "B") -> np.ndarray:
    """Return clean feature matrix. mode='A' includes C2 metadata."""
    cols = ALL_FEATURES_A if mode == "A" else ALL_FEATURES_B
    return d[cols].replace([np.inf, -np.inf], 0).fillna(0).values


def evaluate_and_plot(clf, X_test, y_test, le: LabelEncoder,
                      title: str, save_path: str) -> float:
    """Print classification report, save confusion-matrix PNG, return accuracy."""
    y_pred  = clf.predict(X_test)
    acc     = accuracy_score(y_test, y_pred)
    classes = le.classes_

    print(f"\n  Overall accuracy : {acc:.4f}  ({acc*100:.2f}%)")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=classes))

    cm  = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(
        figsize=(max(6, len(classes) * 1.6 + 2),
                 max(5, len(classes) * 1.3 + 1))
    )
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=classes, yticklabels=classes, ax=ax)
    ax.set_title(f"Confusion Matrix — {title}\nAccuracy: {acc:.4f}", fontsize=13)
    ax.set_xlabel("Predicted", fontsize=11)
    ax.set_ylabel("Actual",    fontsize=11)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Confusion matrix saved → {save_path}")
    return acc


def plot_feature_importance(importances, feature_names: list, title: str,
                             save_path: str, top_n: int = 20):
    """Save a horizontal bar chart of the top-N feature importances."""
    pairs  = sorted(zip(feature_names, importances),
                    key=lambda x: x[1], reverse=True)[:top_n]
    names, vals = zip(*pairs)
    fig, ax = plt.subplots(figsize=(10, top_n * 0.42 + 1.5))
    ax.barh(range(len(names)), list(vals)[::-1],
            color="steelblue", edgecolor="black", linewidth=0.4)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(list(names)[::-1], fontsize=9)
    ax.set_xlabel("Feature importance")
    ax.set_title(f"Top {top_n} Features — {title}", fontsize=12, fontweight="bold")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Feature importance saved → {save_path}")


def print_top_features(importances, feature_names: list, label: str, n: int = 10):
    ranked = sorted(zip(feature_names, importances),
                    key=lambda x: x[1], reverse=True)
    print(f"\n  Top {n} features for '{label}':")
    for rank, (feat, imp) in enumerate(ranked[:n], 1):
        print(f"    {rank:>2}. {feat:<38} {imp:.4f}")


def majority_vote_accuracy(clf, X_test, y_test, le: LabelEncoder,
                            capture_ids: np.ndarray) -> float:
    """Compute per-capture majority-vote accuracy and print detail."""
    y_pred = clf.predict(X_test)
    pred_labels = le.inverse_transform(y_pred)
    true_labels = le.inverse_transform(y_test)

    result_df = pd.DataFrame({
        "capture_id":  capture_ids,
        "true":        true_labels,
        "pred":        pred_labels,
    })
    cap_vote = result_df.groupby("capture_id")["pred"].agg(
        lambda x: x.value_counts().index[0]
    )
    cap_true = result_df.groupby("capture_id")["true"].first()
    cap_acc  = (cap_vote == cap_true).mean()
    correct  = int(cap_acc * len(cap_vote))

    print(f"\n  Per-capture majority-vote accuracy: "
          f"{cap_acc:.4f}  ({correct}/{len(cap_vote)} captures correct)")
    detail = pd.DataFrame({"True": cap_true, "Predicted": cap_vote})
    detail["Result"] = (detail["True"] == detail["Predicted"]).map(
        {True: "CORRECT ✓", False: "wrong   ✗"}
    )
    print(detail.to_string())
    return cap_acc


# ===========================================================================
# 4. PRIMARY MODEL — predict `phase`
# ===========================================================================
def run_primary_model(d: pd.DataFrame):
    """
    Soft-voting ensemble: Random Forest (500 trees) + HistGBM (500 iters).

    Split: GroupShuffleSplit by capture_id — entire captures go to
    train OR test, never split across both.  Without this, temporal
    auto-correlation within 108-second captures inflates accuracy ~6%.
    """
    print(f"\n{'='*65}")
    print("  STEP 2 — PRIMARY MODEL  →  predicting: phase")
    print(f"{'='*65}")

    X      = get_X(d, mode="B")          # phase model doesn't need scenario_id
    le     = LabelEncoder()
    y      = le.fit_transform(d[PRIMARY_LABEL].values)
    groups = d["capture_id"].values

    gss    = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    tr, te = next(gss.split(X, y, groups))
    print(f"  Train: {len(tr):,} windows / {len(set(groups[tr]))} captures  "
          f"|  Test: {len(te):,} windows / {len(set(groups[te]))} captures")

    print("\n  Training RF + HistGBM ensemble (soft voting) …")
    rf  = RandomForestClassifier(
        n_estimators=500, class_weight="balanced",
        n_jobs=-1, random_state=42,
    )
    hgb = HistGradientBoostingClassifier(
        max_iter=500, learning_rate=0.05,
        min_samples_leaf=5, random_state=42,
    )
    clf = VotingClassifier(
        estimators=[("rf", rf), ("hgb", hgb)],
        voting="soft", n_jobs=-1,
    )
    clf.fit(X[tr], y[tr])

    primary_accuracy = evaluate_and_plot(
        clf, X[te], y[te], le,
        title="Phase Detection (Primary)",
        save_path=os.path.join(PLOTS_DIR, "confusion_matrix_phase.png"),
    )

    rf_imp = clf.estimators_[0].feature_importances_
    print_top_features(rf_imp, ALL_FEATURES_B, PRIMARY_LABEL)
    plot_feature_importance(
        rf_imp, ALL_FEATURES_B,
        title="Phase Detection (Primary)",
        save_path=os.path.join(PLOTS_DIR, "feature_importance_phase.png"),
    )

    return clf, le, X, y, groups, primary_accuracy


# ===========================================================================
# 5. SECONDARY MODEL — predict `attack_family`
# ===========================================================================
def run_secondary_model(d: pd.DataFrame):
    """
    Two-mode secondary model for attack_family prediction.

    MODE A — WITH C2 scenario metadata (scenario_id_enc)
    -------------------------------------------------------
    scenario_id is available from the C2 capture channel: it encodes
    which attack scenario the C2 server commanded the bots to run.
    This is legitimate information in a C2-capture pipeline.

    MODE B — Network features ONLY (no scenario_id)
    -------------------------------------------------------
    Pure network traffic classification without C2 channel knowledge.
    HTTP and TCP floods are structurally identical at the network layer.
    """
    print(f"\n{'='*65}")
    print("  STEP 3 — SECONDARY MODEL  →  predicting: attack_family")
    print(f"{'='*65}")

    d_atk = d[d[PRIMARY_LABEL] == "attack"].copy()
    le2   = LabelEncoder()
    y_atk = le2.fit_transform(d_atk[SECONDARY_LABEL].values)
    g_atk = d_atk["capture_id"].values
    print(f"  Attack windows: {len(d_atk):,}")

    gss2     = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    tr2, te2 = next(gss2.split(get_X(d_atk, "B"), y_atk, g_atk))
    print(f"  Train: {len(tr2):,} windows / {len(set(g_atk[tr2]))} captures  "
          f"|  Test: {len(te2):,} windows / {len(set(g_atk[te2]))} captures")

    # -----------------------------------------------------------------------
    # MODE A  (WITH scenario_id — C2 metadata)
    # -----------------------------------------------------------------------
    print(f"\n  {'─'*60}")
    print("  MODE A — WITH C2 scenario metadata (scenario_id_enc)")
    print(f"  {'─'*60}")
    X_A = get_X(d_atk, "A")
    clf_A = HistGradientBoostingClassifier(
        max_iter=1000, learning_rate=0.03,
        min_samples_leaf=3, max_depth=8, random_state=42,
    )
    clf_A.fit(X_A[tr2], y_atk[tr2])

    modeA_accuracy = evaluate_and_plot(
        clf_A, X_A[te2], y_atk[te2], le2,
        title="Attack Family — Mode A (with C2 metadata)",
        save_path=os.path.join(PLOTS_DIR, "confusion_matrix_attack_family_modeA.png"),
    )
    majority_vote_accuracy(clf_A, X_A[te2], y_atk[te2], le2, g_atk[te2])

    # -----------------------------------------------------------------------
    # MODE B  (network features only)
    # -----------------------------------------------------------------------
    print(f"\n  {'─'*60}")
    print("  MODE B — Network features ONLY (no scenario_id)")
    print(f"  {'─'*60}")
    X_B = get_X(d_atk, "B")
    clf_B = HistGradientBoostingClassifier(
        max_iter=1000, learning_rate=0.03,
        min_samples_leaf=3, max_depth=8, random_state=42,
    )
    clf_B.fit(X_B[tr2], y_atk[tr2])

    modeB_accuracy = evaluate_and_plot(
        clf_B, X_B[te2], y_atk[te2], le2,
        title="Attack Family — Mode B (network features only)",
        save_path=os.path.join(PLOTS_DIR, "confusion_matrix_attack_family_modeB.png"),
    )
    majority_vote_accuracy(clf_B, X_B[te2], y_atk[te2], le2, g_atk[te2])

    # Feature importance (Mode A — permutation)
    from sklearn.inspection import permutation_importance
    perm = permutation_importance(
        clf_A, X_A[te2], y_atk[te2],
        n_repeats=5, random_state=42, n_jobs=-1,
    )
    plot_feature_importance(
        perm.importances_mean, ALL_FEATURES_A,
        title="Attack Family Mode A (permutation)",
        save_path=os.path.join(PLOTS_DIR, "feature_importance_attack_family.png"),
    )
    print_top_features(perm.importances_mean, ALL_FEATURES_A, SECONDARY_LABEL)

    print(f"\n  {'─'*60}")
    print("  SUMMARY — Secondary Model")
    print(f"  {'─'*60}")
    y_pred_A = clf_A.predict(X_A[te2])
    y_pred_B = clf_B.predict(X_B[te2])
    print(f"  Mode A (C2 metadata)   : {accuracy_score(y_atk[te2], y_pred_A):.4f}")
    print(f"  Mode B (network only)  : {accuracy_score(y_atk[te2], y_pred_B):.4f}")
    print()
    print("  Mode A is valid in this project because the C2 capture pipeline")
    print("  records scenario metadata from the C2 command channel.")
    print("  Mode B represents classification from traffic features alone.")

    return clf_A, clf_B, le2, modeA_accuracy, modeB_accuracy


# ===========================================================================
# 6. BASELINE
# ===========================================================================
def run_baseline(d: pd.DataFrame) -> float:
    """
    Rule-based baseline: flag 'attack' if pps_zscore > 2 OR bps_zscore > 2.
    Shows how much ML adds over a simple threshold rule.
    """
    print(f"\n{'='*65}")
    print("  STEP 4 — BASELINE  (z-score threshold rule)")
    print("  Rule: 'attack' if pps_zscore > 2  OR  bps_zscore > 2")
    print(f"{'='*65}")

    y_true = (d[PRIMARY_LABEL] == "attack").astype(int).values
    y_pred = (
        (d["pps_zscore"] > 2) | (d["bps_zscore"] > 2)
    ).astype(int).values

    acc = accuracy_score(y_true, y_pred)
    print(f"\n  Accuracy: {acc:.4f}  ({acc*100:.2f}%)")
    print("\n  Classification Report:")
    print(classification_report(y_true, y_pred, target_names=["rest", "attack"]))
    
    return acc


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    print("\n" + "=" * 65)
    print("  BOTNET DDoS DETECTION PIPELINE  —  Person 5")
    print("=" * 65)

    df = load_data(DATA_PATH)

    print(f"\n{'='*65}")
    print("  STEP 1b — Feature engineering")
    print(f"{'='*65}")
    d = engineer_features(df)
    print(f"  Base features         : {len(BASE_FEATURES)}")
    print(f"  Engineered features   : {len(ENGINEERED)}")
    print(f"  C2 metadata features  : {len(C2_META)}")
    print(f"  Total (Mode A)        : {len(ALL_FEATURES_A)}")
    print(f"  Total (Mode B)        : {len(ALL_FEATURES_B)}")

    primary_clf, primary_le, X_all, y_phase, groups, primary_accuracy = run_primary_model(d)

    modeA_accuracy, modeB_accuracy = None, None
    _, _, _, modeA_accuracy, modeB_accuracy = run_secondary_model(d)

    baseline_accuracy = run_baseline(d)

    print(f"\n{'='*65}")
    print("  FINAL ACCURACY SUMMARY (ACTUAL RESULTS)")
    print(f"{'='*65}")
    print(f"  Primary model   (phase)                     : {primary_accuracy*100:.2f}%")
    print(f"  Secondary Mode A (attack_family + C2 meta)  : {modeA_accuracy*100:.2f}%")
    print(f"  Secondary Mode B (attack_family, net only)  : {modeB_accuracy*100:.2f}%")
    print(f"  Baseline         (z-score rule)             : {baseline_accuracy*100:.2f}%")
    print()
    print("  Plots saved to  analysis/plots/")
    for fn in sorted(os.listdir(PLOTS_DIR)):
        if fn.endswith(".png"):
            print(f"    • {fn}")
    print()


if __name__ == "__main__":
    main()