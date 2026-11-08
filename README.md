# MI Megoldások a Kibervédelemben — YARA Malware Classification

Machine learning pipeline for classifying Windows PE malware samples based on features extracted by YARA rules.

**Course:** MI Megoldások a Kibervédelemben (Óbudai Egyetem, 2026/27/1)  
**Team:** Gyula, Attila, József

---

## Project Overview

The instructor ran YARA rules (`peinfo2.yara`) on ~38,000 PE binaries and provided the raw extraction output. We built a pipeline that:

1. **Parses** the raw YARA output into a structured dataset (`build_dataset.py`)
2. **Explores** the data with EDA, PCA, K-Means clustering, and Isolation Forest (`eda_and_clustering.py`, `advanced_visualization.py`)
3. **Classifies** samples with Random Forest and XGBoost (`ml_pipeline_skeleton.py`)
4. **Explains** model decisions with SHAP values (`shap_explainer.py`)

### Features (10, all numeric)

| # | Feature | Type | Description |
|---|---------|------|-------------|
| 1 | FileEntropy | float | Whole-file entropy (compression/encryption indicator) |
| 2 | FileSize | int | File size in bytes |
| 3 | NumberOfSections | int | PE section count |
| 4 | SizeOfCode | int | Code section size |
| 5 | NumberOfImportedFunctions | int | Imported function count |
| 6 | ImportedDLLCount | int | Imported DLL count |
| 7 | NumberOfResources | int | Resource count |
| 8 | DllCharacteristics | int | ASLR/DEP/NX bitmask |
| 9 | MaxSectionEntropy | float | Highest section entropy (derived) |
| 10 | ChecksumMismatch | 0/1 | Checksum != CalculatedChecksum (derived) |

---

## Quick Start

### 1. Clone & install dependencies

```bash
git clone https://github.com/Janitor-tools/MI-Megoldasok-Yara.git
cd MI-Megoldasok-Yara
pip install -r requirements.txt
```

### 2. Run the EDA pipeline (no labels needed)

```bash
python eda_and_clustering.py
python advanced_visualization.py
```

This generates:
- `correlation_matrix.png` — feature correlation heatmap
- `elbow_plot.png` — optimal K selection
- `pca_kmeans_clusters.png` — PCA 2D projection with K-Means clusters
- `pca_cumulative.png` — cumulative explained variance
- `tsne_clusters.png` — t-SNE colored by K-Means clusters
- `tsne_anomalies.png` — t-SNE colored by Isolation Forest anomalies
- `dataset_v2_clustered.csv` — dataset with cluster labels

### 3. Run the ML pipeline (dummy labels)

```bash
python ml_pipeline_skeleton.py
```

This trains Random Forest and XGBoost with 5-fold cross-validation and prints Accuracy, Precision, Recall, F1, and ROC-AUC. Currently uses random dummy labels (~50% accuracy expected).

### 4. Run SHAP explainability

```bash
python shap_explainer.py
```

Generates `shap_summary_dummy.png` — a beeswarm plot showing each feature's impact on predictions.

---

## When the Real Labels Arrive

When the instructor provides the `sha256 -> label` CSV mapping, follow these steps:

### Step 1: Place the label file

Save the instructor's CSV (expected format: `sha256,label`) in the project root, e.g., `labels.csv`.

### Step 2: Update `ml_pipeline_skeleton.py`

Open `ml_pipeline_skeleton.py` and find the `load_data()` function. Replace the dummy label block:

```python
# TODO: Replace with real labels!
rng = np.random.default_rng(RANDOM_STATE)
df[LABEL_COL] = rng.integers(0, 2, size=len(df))
```

With:

```python
labels_df = pd.read_csv("labels.csv")
df = df.merge(labels_df, on="sha256", how="inner")
```

### Step 3: Re-run the pipeline

```bash
python ml_pipeline_skeleton.py    # Train & evaluate with real labels
python shap_explainer.py          # SHAP on real predictions
```

### Step 4: If multi-class labels

If the instructor provides more than 2 classes, update `evaluate_model()` in `ml_pipeline_skeleton.py`:
- Change `roc_auc_score` to use `multi_class="ovr"` and `average="weighted"`
- The XGBoost `eval_metric` may need `"mlogloss"` instead of `"logloss"`

---

## Repository Structure

```
MI-Megoldasok-Yara/
├── archive_phase1/              # Legacy pipeline (archived)
├── Instrukciók/                 # Instructor materials (.tgz in .gitignore)
├── data/raw/                    # Extracted YARA output (.gitignore)
├── build_dataset.py             # Raw YARA output -> dataset_v2.csv
├── eda_and_clustering.py        # EDA: correlation, PCA, K-Means, cluster profiling
├── advanced_visualization.py    # t-SNE + Isolation Forest
├── ml_pipeline_skeleton.py      # RF + XGBoost classification pipeline
├── shap_explainer.py            # SHAP feature importance
├── dataset_v2.csv               # Base dataset (38161 samples, 10 features)
├── dataset_v2_clustered.csv     # Dataset + K-Means cluster column
├── requirements.txt             # Python dependencies
├── claude_context.md            # Project state & architectural decisions
├── peinfo1.yara                 # YARA rules (basic)
├── peinfo2.yara                 # YARA rules (extended, used for data)
└── *.png                        # Generated visualizations
```

---

## Key Findings (Unsupervised, pre-label)

- **3 natural clusters** found by K-Means (Elbow method): a dominant group (71%), a low-entropy group (28%), and a small outlier group (0.7%)
- **Cluster 2 outliers** have 10x more sections, 28x more resources, and 10x more DLLs than average — likely packed/obfuscated binaries
- **73.2% overlap** between K-Means Cluster 2 and Isolation Forest anomalies — cross-validation of the outlier signal
- **PCA:** 8 components needed for 90% variance, 9 for 95% — features carry independent information, no dimension reduction recommended
- **Strongest correlations:** NumberOfSections - ImportedDLLCount (0.50), NumberOfImportedFunctions - ImportedDLLCount (0.49)
