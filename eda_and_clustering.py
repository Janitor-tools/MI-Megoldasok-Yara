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

# --- Cluster statistical profile ---
X_with_cluster = X.copy()
X_with_cluster["Cluster"] = labels

print("\n" + "=" * 70)
print("CLUSTER STATISTICAL PROFILE")
print("=" * 70)

cluster_mean = X_with_cluster.groupby("Cluster")[FEATURES].mean()
cluster_median = X_with_cluster.groupby("Cluster")[FEATURES].median()

print("\n--- Mean per cluster ---")
print(cluster_mean.round(2).to_string())
print("\n--- Median per cluster ---")
print(cluster_median.round(2).to_string())

overall_mean = X[FEATURES].mean()
print("\n--- Cluster 2 vs Overall (deviation factor: cluster_mean / overall_mean) ---")
smallest_cluster = counts.argmin()
deviation = cluster_mean.loc[smallest_cluster] / overall_mean
for feat in FEATURES:
    marker = " <<<" if abs(deviation[feat] - 1) > 1.0 else ""
    print(f"  {feat:>30s}: {deviation[feat]:>8.2f}x{marker}")

# --- Full PCA cumulative variance ---
pca_full = PCA(n_components=len(FEATURES))
pca_full.fit(X_scaled)
cumvar = np.cumsum(pca_full.explained_variance_ratio_)

n_90 = int(np.argmax(cumvar >= 0.90)) + 1
n_95 = int(np.argmax(cumvar >= 0.95)) + 1

print(f"\n--- Full PCA cumulative variance ---")
for i, (ev_i, cv_i) in enumerate(zip(pca_full.explained_variance_ratio_, cumvar)):
    print(f"  PC{i+1:>2d}: {ev_i:.4f}  (cumulative: {cv_i:.4f} / {cv_i*100:.1f}%)")
print(f"\nComponents for 90% variance: {n_90}")
print(f"Components for 95% variance: {n_95}")

fig, ax = plt.subplots(figsize=(8, 5))
ax.bar(range(1, len(FEATURES) + 1), pca_full.explained_variance_ratio_,
       alpha=0.6, label="Individual")
ax.step(range(1, len(FEATURES) + 1), cumvar, where="mid",
        color="red", linewidth=2, label="Cumulative")
ax.axhline(y=0.90, color="green", linestyle="--", alpha=0.7, label="90% threshold")
ax.axhline(y=0.95, color="orange", linestyle="--", alpha=0.7, label="95% threshold")
ax.set_xlabel("Principal Component")
ax.set_ylabel("Explained Variance Ratio")
ax.set_title("PCA Cumulative Explained Variance (10 Features)")
ax.set_xticks(range(1, len(FEATURES) + 1))
ax.legend(loc="center right")
ax.grid(True, alpha=0.3)
fig.tight_layout()
fig.savefig("pca_cumulative.png", dpi=150)
plt.close(fig)
print("Saved pca_cumulative.png")

# --- Save clustered dataset ---
df_out = df.copy()
df_out[FEATURES] = X
df_out["Cluster"] = labels
df_out.to_csv("dataset_v2_clustered.csv", index=False)
print(f"\nSaved dataset_v2_clustered.csv ({len(df_out)} rows)")
