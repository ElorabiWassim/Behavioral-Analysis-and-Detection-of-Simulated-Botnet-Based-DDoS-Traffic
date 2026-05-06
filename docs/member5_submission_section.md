## Member 5 - Detection and Visualization (Khaled)

### Objective
Build and evaluate detection models on the cleaned 1-second feature dataset produced by Members 3 and 4, then provide clear visual outputs and reproducible metrics for the final report.

### Dataset Used
- Primary dataset: `dataset/features/dataset_cleaned.csv`
- Total rows: **1797**
- Binary label distribution (`is_attack`):
  - `0` (normal): **74**
  - `1` (attack): **1723**

### Features Used for Modeling
`packets`, `bytes`, `unique_src`, `tcp_packets`, `udp_packets`, `icmp_packets`, `syn_packets`, `ack_packets`, `rst_packets`, `pps`, `bps`, `syn_ratio`, `udp_ratio`

### Modeling and Evaluation Design
Two reproducible pipelines were prepared:

1. **Dependency-free pipeline** (`detection/member5_detection.py`)
- Uses only Python standard library.
- Produces binary detection and attack-family classification baselines.
- Generates:
  - `detection/output/member5_metrics.json`
  - `detection/output/member5_report.md`
  - `detection/output/confusion_binary.csv`
  - `detection/output/confusion_family.csv`

2. **Sklearn pipeline (Kaggle/Colab)** (`detection/member5_sklearn.py`)
- Uses `pandas`, `scikit-learn`, `matplotlib`, `seaborn`.
- Trains:
  - Decision Tree (binary attack detection)
  - Random Forest (binary attack detection)
  - Random Forest (attack-family classification)
- Generates JSON + Markdown metrics and PNG visualizations:
  - Family distribution plot
  - Binary confusion matrices
  - Family confusion matrix
  - Feature importance
  - ROC curve

### Important Experimental Constraint
Grouped split by `pcap_file` is the preferred anti-leakage strategy.  
However, in this dataset there is only one normal PCAP group, so strict grouped binary splitting is not feasible while keeping both classes in train/test.  
The implemented fallback is a **stratified row split** with this limitation explicitly documented in outputs.

### Current Verified Results (from dependency-free executed pipeline)
Binary attack detection:
- Existing `predicted` column: Accuracy **87.70%**, Precision **99.93%**, Recall **87.23%**, F1 **93.15%**
- Existing `predicted_multi` column: Accuracy **87.81%**, Precision **99.93%**, Recall **87.35%**, F1 **93.22%**
- Threshold baseline (`pps > mean_normal + 3*std`): Accuracy **88.13%**, Precision **100.00%**, Recall **87.62%**, F1 **93.40%**
- GaussianNB baseline: Accuracy **88.50%**, Precision **100.00%**, Recall **88.01%**, F1 **93.62%**

Attack-family classification (7 classes):
- GaussianNB baseline: Accuracy **71.67%**, Macro-F1 **69.98%**, Weighted-F1 **71.97%**

### How to Run the Sklearn Version (Kaggle/Colab/Local with dependencies)
```bash
python detection/member5_sklearn.py
```

Optional:
```bash
python detection/member5_sklearn.py --input dataset/features/dataset_cleaned.csv --outdir detection/output_sklearn --test-size 0.30 --seed 42
```

### Outputs to Attach in Final Submission
- Metrics JSON:
  - `detection/output/member5_metrics.json`
  - `detection/output_sklearn/member5_sklearn_metrics.json` (after sklearn run)
- Human-readable reports:
  - `detection/output/member5_report.md`
  - `detection/output_sklearn/member5_sklearn_report.md` (after sklearn run)
- Confusion matrices and figures:
  - CSV files in `detection/output/` and `detection/output_sklearn/`
  - PNG files in `detection/output_sklearn/plots/`
