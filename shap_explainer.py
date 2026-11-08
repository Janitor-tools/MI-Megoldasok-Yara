"""
SHAP Explainer — Modell értelmezhetőség (Explainable AI).

Random Forest modellt tanít a dataset_v2_clustered.csv-n, majd SHAP
értékekkel vizualizálja a feature-ök hozzájárulását a döntésekhez.
Jelenleg dummy label-ekkel fut — valódi label-re cserélés után
ugyanez a kód azonnal használható.

Használat:
    python shap_explainer.py

Szerzők: Gyula, Attila, József
"""

from __future__ import annotations

import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from ml_pipeline_skeleton import FEATURES, LABEL_COL, RANDOM_STATE, TEST_SIZE, load_data

SHAP_SAMPLE: int = 1000
OUTPUT_PNG: str = "shap_summary_dummy.png"


def train_model(
    X_train: np.ndarray, y_train: np.ndarray,
) -> RandomForestClassifier:
    """Random Forest betanítása a SHAP elemzéshez."""
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model


def compute_shap_values(
    model: RandomForestClassifier,
    X_test: np.ndarray,
    feature_names: list[str],
) -> shap.Explanation:
    """SHAP értékek kiszámítása TreeExplainer-rel (gyors, fa-alapú modellekhez)."""
    explainer = shap.TreeExplainer(model)
    sample_idx = np.random.default_rng(RANDOM_STATE).choice(
        len(X_test), size=min(SHAP_SAMPLE, len(X_test)), replace=False,
    )
    X_sample = X_test[sample_idx]
    shap_values = explainer(X_sample)

    # Bináris klasszifikáció: a pozitív osztály (1) SHAP értékeit vesszük
    if shap_values.values.ndim == 3:
        shap_values = shap_values[:, :, 1]
    shap_values.feature_names = feature_names
    return shap_values


def plot_shap_summary(shap_values: shap.Explanation, output_path: str) -> None:
    """SHAP summary plot (beeswarm) mentése PNG-be."""
    fig, ax = plt.subplots(figsize=(10, 7))
    shap.plots.beeswarm(shap_values, show=False)
    plt.title("SHAP Feature Importance (Random Forest, dummy labels)")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close("all")
    print(f"[INFO] Saved {output_path}")


def main() -> None:
    from sklearn.model_selection import train_test_split

    df = load_data("dataset_v2_clustered.csv")
    X = df[FEATURES].values
    y = df[LABEL_COL].values

    X_train, X_test, y_train, _ = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE,
    )

    # Skálázás nélkül: SHAP értékek eredeti feature skálán értelmezhetőbbek
    print("[INFO] Training Random Forest...")
    model = train_model(X_train, y_train)

    print(f"[INFO] Computing SHAP values on {min(SHAP_SAMPLE, len(X_test))} test samples...")
    shap_values = compute_shap_values(model, X_test, FEATURES)

    plot_shap_summary(shap_values, OUTPUT_PNG)

    # Top feature-ök kiírása a konzolra
    mean_abs_shap = np.abs(shap_values.values).mean(axis=0)
    ranked = sorted(zip(FEATURES, mean_abs_shap), key=lambda x: x[1], reverse=True)
    print("\n[INFO] Feature importance (mean |SHAP|):")
    for feat, val in ranked:
        print(f"  {feat:<35s}: {val:.4f}")

    print("\n[INFO] SHAP explainer DONE.")


if __name__ == "__main__":
    main()
