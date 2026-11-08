"""
ML Pipeline csontváz — YARA malware klasszifikáció.

Random Forest és XGBoost klasszifikátorok k-fold cross-validationnel.
Jelenleg dummy label-ekkel fut (random 0/1), amíg az oktatótól meg nem
kapjuk a valódi sha256 → label összerendelést.

Használat:
    python ml_pipeline_skeleton.py

Szerzők: Gyula, Attila, József
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

# ---------------------------------------------------------------------------
# Konfiguráció — egy helyen módosítható, ha változik a feladat
# ---------------------------------------------------------------------------
DATASET: str = "dataset_v2_clustered.csv"
FEATURES: list[str] = [
    "FileEntropy", "FileSize", "NumberOfSections", "SizeOfCode",
    "NumberOfImportedFunctions", "ImportedDLLCount", "NumberOfResources",
    "DllCharacteristics", "MaxSectionEntropy", "ChecksumMismatch",
]
LABEL_COL: str = "Label"
TEST_SIZE: float = 0.20
K_FOLDS: int = 5
RANDOM_STATE: int = 42


# ---------------------------------------------------------------------------
# 1. Adatbetöltés és dummy label generálás
# ---------------------------------------------------------------------------
def load_data(path: str) -> pd.DataFrame:
    """Betölti a CSV-t, hiányzó értékeket mediánnal pótol, dummy labelt generál."""
    df = pd.read_csv(path)
    df[FEATURES] = df[FEATURES].fillna(df[FEATURES].median())

    # TODO: Ezt cseréljük le a valódi label-re, amint megkapjuk az oktatótól!
    rng = np.random.default_rng(RANDOM_STATE)
    df[LABEL_COL] = rng.integers(0, 2, size=len(df))
    print(f"[INFO] Betöltve: {len(df)} minta, {len(FEATURES)} feature")
    print(f"[INFO] Label eloszlás:\n{df[LABEL_COL].value_counts().to_string()}")
    return df


# ---------------------------------------------------------------------------
# 2. Train/Test split + skálázás
# ---------------------------------------------------------------------------
def split_and_scale(
    df: pd.DataFrame,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, StandardScaler]:
    """80/20 stratified split, majd StandardScaler a feature-ökre."""
    X = df[FEATURES].values
    y = df[LABEL_COL].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print(f"[INFO] Train: {len(X_train)}, Test: {len(X_test)}")
    return X_train, X_test, y_train, y_test, scaler


# ---------------------------------------------------------------------------
# 3. Modellek definiálása
# ---------------------------------------------------------------------------
def get_models() -> dict[str, RandomForestClassifier | XGBClassifier]:
    """Visszaadja a kipróbálandó klasszifikátorokat."""
    return {
        "RandomForest": RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
        "XGBoost": XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
    }


# ---------------------------------------------------------------------------
# 4. Kiértékelés — egyetlen modell, egyetlen adathalmazon
# ---------------------------------------------------------------------------
def evaluate_model(
    name: str,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray | None = None,
) -> dict[str, float]:
    """Kiszámítja és kiírja az Accuracy, Precision, Recall, F1 és ROC-AUC metrikákat."""
    metrics: dict[str, float] = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, average="weighted", zero_division=0),
        "recall": recall_score(y_true, y_pred, average="weighted", zero_division=0),
        "f1": f1_score(y_true, y_pred, average="weighted", zero_division=0),
    }

    if y_prob is not None:
        try:
            metrics["roc_auc"] = roc_auc_score(y_true, y_prob)
        except ValueError:
            metrics["roc_auc"] = float("nan")

    print(f"\n{'='*60}")
    print(f"  {name} — Test Set Eredmények")
    print(f"{'='*60}")
    for k, v in metrics.items():
        print(f"  {k:<12s}: {v:.4f}")
    print(f"\n{classification_report(y_true, y_pred, zero_division=0)}")
    return metrics


# ---------------------------------------------------------------------------
# 5. K-Fold Cross-Validation
# ---------------------------------------------------------------------------
def cross_validate_model(
    name: str,
    model: RandomForestClassifier | XGBClassifier,
    X: np.ndarray,
    y: np.ndarray,
) -> dict[str, np.ndarray]:
    """Stratified k-fold CV, visszaadja a scoring metrikákat fold-onként."""
    cv = StratifiedKFold(n_splits=K_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    scoring = ["accuracy", "precision_weighted", "recall_weighted", "f1_weighted", "roc_auc"]

    results = cross_validate(model, X, y, cv=cv, scoring=scoring, n_jobs=-1)

    print(f"\n{'-'*60}")
    print(f"  {name} — {K_FOLDS}-Fold Cross-Validation")
    print(f"{'-'*60}")
    for metric in scoring:
        key = f"test_{metric}"
        vals = results[key]
        print(f"  {metric:<22s}: {vals.mean():.4f} ± {vals.std():.4f}")
    return results


# ---------------------------------------------------------------------------
# 6. Fő pipeline
# ---------------------------------------------------------------------------
def main() -> None:
    df = load_data(DATASET)
    X_train, X_test, y_train, y_test, scaler = split_and_scale(df)

    models = get_models()
    all_results: dict[str, dict[str, float]] = {}

    for name, model in models.items():
        # Cross-validation a train seten
        cross_validate_model(name, model, X_train, y_train)

        # Végső train + test kiértékelés
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]
        all_results[name] = evaluate_model(name, y_test, y_pred, y_prob)

    # Összehasonlító táblázat
    print(f"\n{'='*60}")
    print("  ÖSSZEHASONLÍTÁS")
    print(f"{'='*60}")
    summary = pd.DataFrame(all_results).T
    print(summary.round(4).to_string())
    print("\n[INFO] Pipeline DONE. Running on dummy labels -- replace with real labels!")


if __name__ == "__main__":
    main()
