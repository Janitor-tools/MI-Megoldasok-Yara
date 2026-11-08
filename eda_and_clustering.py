"""Unsupervised EDA, PCA and K-Means clustering on YARA malware features."""

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans

DATASET = "dataset_v2.csv"
FEATURES = [
    "FileEntropy", "FileSize", "NumberOfSections", "SizeOfCode",
    "NumberOfImportedFunctions", "ImportedDLLCount", "NumberOfResources",
    "DllCharacteristics", "MaxSectionEntropy", "ChecksumMismatch",
]
K_RANGE = range(2, 11)

df = pd.read_csv(DATASET)
print(f"Loaded {len(df)} samples, {len(df.columns)} columns")

X = df[FEATURES].copy()
nan_counts = X.isnull().sum()
if nan_counts.any():
    print(f"NaN values found:\n{nan_counts[nan_counts > 0]}")
    X = X.fillna(X.median())
    print("Imputed with median.")
else:
    print("No missing values.")

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# --- Correlation heatmap ---
corr = X.corr()
fig, ax = plt.subplots(figsize=(10, 8))
sns.heatmap(corr, annot=True, fmt=".2f", cmap="coolwarm", center=0,
            square=True, linewidths=0.5, ax=ax)
ax.set_title("Feature Correlation Matrix (10 YARA PE Features)")
fig.tight_layout()
fig.savefig("correlation_matrix.png", dpi=150)
plt.close(fig)
print("Saved correlation_matrix.png")

# --- PCA (2 components) ---
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)
ev = pca.explained_variance_ratio_
print(f"\nPCA Explained Variance:")
print(f"  PC1: {ev[0]:.4f} ({ev[0]*100:.2f}%)")
print(f"  PC2: {ev[1]:.4f} ({ev[1]*100:.2f}%)")
print(f"  Total: {ev.sum():.4f} ({ev.sum()*100:.2f}%)")

# --- Elbow plot ---
inertias = []
for k in K_RANGE:
    km = KMeans(n_clusters=k, n_init=10, random_state=42)
    km.fit(X_pca)
    inertias.append(km.inertia_)

fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(list(K_RANGE), inertias, "bo-", linewidth=2, markersize=8)
ax.set_xlabel("Number of Clusters (K)")
ax.set_ylabel("Inertia (within-cluster sum of squares)")
ax.set_title("Elbow Method for Optimal K")
ax.set_xticks(list(K_RANGE))
ax.grid(True, alpha=0.3)
fig.tight_layout()
fig.savefig("elbow_plot.png", dpi=150)
plt.close(fig)
print("Saved elbow_plot.png")

# Pick K from elbow heuristic: largest second derivative
deltas = np.diff(inertias)
delta2 = np.diff(deltas)
best_k = list(K_RANGE)[np.argmax(np.abs(delta2)) + 1]
if best_k < 3:
    best_k = 5
print(f"\nElbow heuristic suggests K={best_k}")

# --- K-Means with chosen K ---
kmeans = KMeans(n_clusters=best_k, n_init=10, random_state=42)
labels = kmeans.fit_predict(X_pca)

fig, ax = plt.subplots(figsize=(10, 8))
scatter = ax.scatter(X_pca[:, 0], X_pca[:, 1], c=labels, cmap="tab10",
                     alpha=0.4, s=5, edgecolors="none")
ax.set_xlabel(f"PC1 ({ev[0]*100:.1f}% variance)")
ax.set_ylabel(f"PC2 ({ev[1]*100:.1f}% variance)")
ax.set_title(f"PCA + K-Means Clustering (K={best_k}, n={len(df)})")
cbar = fig.colorbar(scatter, ax=ax, label="Cluster")
cbar.set_ticks(range(best_k))
fig.tight_layout()
fig.savefig("pca_kmeans_clusters.png", dpi=150)
plt.close(fig)
print("Saved pca_kmeans_clusters.png")

# Cluster distribution
print(f"\nCluster distribution (K={best_k}):")
unique, counts = np.unique(labels, return_counts=True)
for c, n in zip(unique, counts):
    print(f"  Cluster {c}: {n:>6} samples ({n/len(df)*100:.1f}%)")
