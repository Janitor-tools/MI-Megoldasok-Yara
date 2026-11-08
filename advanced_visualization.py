"""
Advanced Visualization — t-SNE + Isolation Forest on YARA malware features.

Non-linear 2D projection with t-SNE, colored by K-Means clusters and
Isolation Forest anomaly labels. Provides deeper insight into data
structure than linear PCA.

Usage:
    python advanced_visualization.py

Authors: Gyula, Attila, Jozsef
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.manifold import TSNE
from sklearn.preprocessing import StandardScaler

DATASET: str = "dataset_v2_clustered.csv"
FEATURES: list[str] = [
    "FileEntropy", "FileSize", "NumberOfSections", "SizeOfCode",
    "NumberOfImportedFunctions", "ImportedDLLCount", "NumberOfResources",
    "DllCharacteristics", "MaxSectionEntropy", "ChecksumMismatch",
]
RANDOM_STATE: int = 42
TSNE_SAMPLE: int = 5000
TSNE_PERPLEXITY: float = 30.0


def load_and_scale(path: str) -> tuple[pd.DataFrame, np.ndarray]:
    """Load dataset, impute NaNs, scale features. Returns (df, X_scaled)."""
    df = pd.read_csv(path)
    df[FEATURES] = df[FEATURES].fillna(df[FEATURES].median())
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df[FEATURES].values)
    print(f"[INFO] Loaded {len(df)} samples, scaled {len(FEATURES)} features")
    return df, X_scaled


def run_isolation_forest(X: np.ndarray, contamination: float = 0.05) -> np.ndarray:
    """Isolation Forest anomaly detection. Returns labels: 1=normal, -1=anomaly."""
    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    labels = iso.fit_predict(X)
    n_anomaly = (labels == -1).sum()
    print(f"[INFO] Isolation Forest: {n_anomaly} anomalies ({n_anomaly/len(X)*100:.1f}%)")
    return labels


def run_tsne(X: np.ndarray, sample_size: int) -> tuple[np.ndarray, np.ndarray]:
    """Run t-SNE on a random subsample. Returns (embedding, sample_indices)."""
    rng = np.random.default_rng(RANDOM_STATE)
    idx = rng.choice(len(X), size=min(sample_size, len(X)), replace=False)
    idx.sort()

    print(f"[INFO] Running t-SNE on {len(idx)} samples (perplexity={TSNE_PERPLEXITY})...")
    tsne = TSNE(
        n_components=2,
        perplexity=TSNE_PERPLEXITY,
        learning_rate="auto",
        init="pca",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    embedding = tsne.fit_transform(X[idx])
    print(f"[INFO] t-SNE done. KL divergence: {tsne.kl_divergence_:.4f}")
    return embedding, idx


def plot_tsne_clusters(
    embedding: np.ndarray,
    cluster_labels: np.ndarray,
    output_path: str,
    n_samples: int,
) -> None:
    """Scatter plot of t-SNE embedding colored by K-Means cluster."""
    fig, ax = plt.subplots(figsize=(10, 8))
    scatter = ax.scatter(
        embedding[:, 0], embedding[:, 1],
        c=cluster_labels, cmap="tab10", alpha=0.6, s=8, edgecolors="none",
    )
    n_clusters = len(np.unique(cluster_labels))
    cbar = fig.colorbar(scatter, ax=ax, label="K-Means Cluster")
    cbar.set_ticks(range(n_clusters))
    ax.set_xlabel("t-SNE 1")
    ax.set_ylabel("t-SNE 2")
    ax.set_title(f"t-SNE Projection colored by K-Means Clusters (n={n_samples})")
    ax.grid(True, alpha=0.2)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"[INFO] Saved {output_path}")


def plot_tsne_anomalies(
    embedding: np.ndarray,
    anomaly_labels: np.ndarray,
    output_path: str,
    n_samples: int,
) -> None:
    """Scatter plot of t-SNE embedding colored by Isolation Forest anomaly label."""
    colors = np.where(anomaly_labels == -1, "red", "steelblue")
    alphas = np.where(anomaly_labels == -1, 0.8, 0.3)

    fig, ax = plt.subplots(figsize=(10, 8))
    for label, color, alpha, name in [
        (1, "steelblue", 0.3, "Normal"),
        (-1, "red", 0.8, "Anomaly"),
    ]:
        mask = anomaly_labels == label
        ax.scatter(
            embedding[mask, 0], embedding[mask, 1],
            c=color, alpha=alpha, s=8 if label == 1 else 20,
            edgecolors="none", label=f"{name} ({mask.sum()})",
        )
    ax.set_xlabel("t-SNE 1")
    ax.set_ylabel("t-SNE 2")
    ax.set_title(f"t-SNE Projection — Isolation Forest Anomalies (n={n_samples})")
    ax.legend(loc="upper right", framealpha=0.9)
    ax.grid(True, alpha=0.2)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"[INFO] Saved {output_path}")


def main() -> None:
    df, X_scaled = load_and_scale(DATASET)

    # Isolation Forest on full dataset
    anomaly_labels = run_isolation_forest(X_scaled)
    df["IsoForest_Anomaly"] = anomaly_labels

    # t-SNE on subsample
    embedding, idx = run_tsne(X_scaled, TSNE_SAMPLE)

    # Plot 1: t-SNE colored by K-Means clusters
    plot_tsne_clusters(embedding, df["Cluster"].values[idx], "tsne_clusters.png", len(idx))

    # Plot 2: t-SNE colored by Isolation Forest anomalies
    plot_tsne_anomalies(embedding, anomaly_labels[idx], "tsne_anomalies.png", len(idx))

    # Overlap: how many K-Means Cluster 2 samples are also IF anomalies?
    cluster2_mask = df["Cluster"] == 2
    anomaly_mask = df["IsoForest_Anomaly"] == -1
    overlap = (cluster2_mask & anomaly_mask).sum()
    print(f"\n[INFO] Cluster 2 vs Isolation Forest overlap:")
    print(f"  Cluster 2 total:    {cluster2_mask.sum()}")
    print(f"  IF anomalies total: {anomaly_mask.sum()}")
    print(f"  Overlap:            {overlap} ({overlap/cluster2_mask.sum()*100:.1f}% of Cluster 2)")

    print("\n[INFO] Advanced visualization DONE.")


if __name__ == "__main__":
    main()
