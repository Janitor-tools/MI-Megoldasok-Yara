"""
train_models.py
----------------
Fazis 2: adat-elofeldolgozo (preprocessing) csovezetek felepitese es egy
baseline modell betanitasa a dataset.csv-n, annak bizonyitasara, hogy az
extract_features.py altal kinyert jellemzok taníthatóak.

A specifikus modellek (Random Forest / XGBoost - Gyula; SVM / KNN /
Logistic Regression - Attila) finomhangolasa kesobbi feladat - ez a
szkript a KOZOS elofeldolgozast es egy egyszeru Random Forest baseline-t
adja, amit a csapat tovabb bovithet.

Lepesek:
    1) dataset.csv betoltese, hasznalhatatlan sorok eldobasa, hianyzo
       ertekek imputalasa.
    2) Feature/label szetvalasztas, LabelEncoder a cimkere, StandardScaler
       a numerikus feature-okre.
    3) Stratifikalt train/test split (80/20).
    4) Baseline Random Forest betanitasa, accuracy kiirasa.
    5) Modell, preprocessing pipeline (imputer+scaler) es LabelEncoder
       mentese a models/ mappaba (joblib), a Fazis 3-beli ujra-betoltesehez.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler

# ---------------------------------------------------------------------------
# Oszlop-konfiguracio
# ---------------------------------------------------------------------------

# Az extract_features.py altal irt oszlopok kozul ezek a tenylegesen
# numerikus, modellezesre alkalmas jellemzok. Az EntryHash10..80 oszlopok
# hexadecimalis hash-STRING-ek (nem numerikus ertekek), ezert kimaradnak a
# baseline feature-kesletbol - kesobb pl. hash-prefix alapu kategorikus
# feature-kent hasznosithatoak lennenek, de ez tullepne a baseline celjat.
NUMERIC_FEATURES: List[str] = [
    "file_size",
    "FromBegin",
    "FromEnd",
    "InitializedData",
    "RELOCS_STRIPPED",
    "LINE_NUMS_STRIPPED",
    "LOCAL_SYMS_STRIPPED",
    "LARGE_ADDRESS_AWARE",
    "Number_of_imported_functions",
    "EntryPoint",
    "Size_of_stack_reserve",
    "Size_of_heap_reserve",
    "Number_of_signatures",
    "Machine",
    "Subsystem",
    "Type_overlay",
    "partial_console_log",
    "parse_error",
]

LABEL_COLUMN = "label"

# Ha egy sor numerikus feature-jeinek tobb mint ennyi hanyada hianyzik
# (NaN), a sort teljesen hasznalhatatlannak tekintjuk es eldobjuk, ahelyett
# hogy imputalnank - tipikusan parse_error=1 (nem ervenyes PE) vagy sulyosan
# csonka console.log (partial_console_log=1 korai megszakadassal) eseten.
MAX_MISSING_FRACTION = 0.5

logger = logging.getLogger("train_models")


def setup_logging(log_path: Path) -> None:
    """Fajlba es konzolra is logol, a Fazis 1 szkriptjeivel konzisztens modon."""
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(console_handler)


def load_dataset(csv_path: Path) -> pd.DataFrame:
    """Betolti a dataset.csv-t, es ellenorzi, hogy minden vart oszlop jelen van-e."""
    df = pd.read_csv(csv_path)

    missing_columns = [c for c in NUMERIC_FEATURES + [LABEL_COLUMN] if c not in df.columns]
    if missing_columns:
        raise ValueError(
            f"A dataset.csv hianyzo oszlopokat tartalmaz: {missing_columns}. "
            "Ellenorizd, hogy a feature_extractor.yar / extract_features.py "
            "verzioja illeszkedik-e ehhez a szkripthez."
        )

    logger.info("Betoltve: %d sor, %d oszlop (%s)", len(df), len(df.columns), csv_path)
    return df


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Eldobja a teljesen hasznalhatatlan sorokat (tul sok hianyzo numerikus
    ertek - pl. parse_error=1 miatt nem ervenyes PE, vagy a console.log
    AND-lanc nagyon korai megszakadasa), a tobbi hianyzo erteket pedig
    kesobb (a Pipeline-ban) imputaljuk, itt nem.
    """
    numeric_subset = df[NUMERIC_FEATURES].apply(pd.to_numeric, errors="coerce")
    missing_fraction = numeric_subset.isna().mean(axis=1)

    unusable_mask = missing_fraction > MAX_MISSING_FRACTION
    n_dropped = int(unusable_mask.sum())

    if n_dropped:
        dropped_parse_error = int(df.loc[unusable_mask, "parse_error"].sum())
        logger.warning(
            "%d hasznalhatatlan sor eldobva (numerikus mezok >%.0f%%-a hianyzik), "
            "ebbol %d parse_error=1 miatt: %s",
            n_dropped,
            MAX_MISSING_FRACTION * 100,
            dropped_parse_error,
            df.loc[unusable_mask, "filename"].tolist(),
        )

    cleaned = df.loc[~unusable_mask].reset_index(drop=True)

    if cleaned.empty:
        raise ValueError(
            "A tisztitas utan egyetlen hasznalhato sor sem maradt - "
            "ellenorizd a mintakonyvtarat es az extract_features.py futasat."
        )

    logger.info("Tisztitas utan: %d hasznalhato sor maradt.", len(cleaned))
    return cleaned


def split_features_and_label(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Szetvalasztja a numerikus feature-oket (X) es a cimke-oszlopot (y)."""
    X = df[NUMERIC_FEATURES].apply(pd.to_numeric, errors="coerce")
    y = df[LABEL_COLUMN]
    return X, y


def stratified_split_with_fallback(
    X: pd.DataFrame, y: np.ndarray, test_size: float, random_state: int
):
    """
    Stratifikalt train/test split, kis mintaszam eseten automatikus
    korrekcioval. Nagyon kevés mintanal (mint a jelenlegi fixture-oknel,
    6 minta / 3 osztaly) a kert 20%-os teszt-meret kisebb lehet, mint az
    osztalyok szama, amit a sklearn stratify hibaval utasit el. Ilyenkor
    a legkisebb, meg stratifikalhato teszt-meretre novelunk, es figyelmez-
    tetunk, hogy ez csak a pipeline-teszteleshez elegendo, valos (10 ezres)
    adaton a kert 80/20 arany mar zavartalanul mukodik majd.
    """
    try:
        return train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
    except ValueError as exc:
        n_classes = len(np.unique(y))
        n_samples = len(y)
        min_test_size = n_classes / n_samples
        adjusted_test_size = min(max(test_size, min_test_size), 0.5)
        logger.warning(
            "Stratifikalt split a kert test_size=%.2f mellett nem lehetseges "
            "(%s). Ez ~%d mintas fixture-adaton varhato - valos, 10 ezres "
            "korpuszon nem fog elofordulni. Ideiglenesen test_size=%.2f-re "
            "novelve, csak a pipeline mukodesenek igazolasahoz.",
            test_size,
            exc,
            n_samples,
            adjusted_test_size,
        )
        return train_test_split(
            X, y, test_size=adjusted_test_size, random_state=random_state, stratify=y
        )


def build_preprocessing_pipeline() -> Pipeline:
    """
    Hianyzoertek-imputalas (median) + StandardScaler egy kozos Pipeline-ban.
    A tavolsagalapu modellek (KNN, SVM) miatt MINDEN numerikus feature-t
    skalazunk, a fa-alapu modelleknek (Random Forest) ez nem art.
    """
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )


def train_baseline_model(X_train: np.ndarray, y_train: np.ndarray, random_state: int) -> RandomForestClassifier:
    """Betanit egy egyszeru Random Forest baseline modellt."""
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=random_state,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)
    return model


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Baseline preprocessing + Random Forest a dataset.csv-n."
    )
    parser.add_argument("--dataset-csv", type=Path, default=Path("dataset.csv"))
    parser.add_argument("--models-dir", type=Path, default=Path("models"))
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--log-file", type=Path, default=Path("train_models.log"))
    args = parser.parse_args()

    setup_logging(args.log_file)

    if not args.dataset_csv.exists():
        logger.error(
            "%s nem letezik - eloszor futtasd az extract_features.py-t.",
            args.dataset_csv,
        )
        sys.exit(1)

    args.models_dir.mkdir(parents=True, exist_ok=True)

    # --- 1) Betoltes es tisztitas ---
    df = load_dataset(args.dataset_csv)
    df = clean_dataset(df)
    X, y_raw = split_features_and_label(df)

    # --- 2) Cimke-kodolas ---
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_raw)
    logger.info(
        "Osztalyok (%d db): %s", len(label_encoder.classes_), list(label_encoder.classes_)
    )

    # --- 3) Train/test split (stratifikalt, kis-mintas fallback-kel) ---
    X_train, X_test, y_train, y_test = stratified_split_with_fallback(
        X, y, args.test_size, args.random_state
    )
    logger.info("Train/test meret: %d / %d minta.", len(X_train), len(X_test))

    # --- 4) Preprocessing: imputalas + skalazas (kizarolag a train halmazon fit-elve, adatszivargas elkerulesehez) ---
    preprocessing = build_preprocessing_pipeline()
    X_train_processed = preprocessing.fit_transform(X_train)
    X_test_processed = preprocessing.transform(X_test)

    # --- 5) Baseline modell ---
    model = train_baseline_model(X_train_processed, y_train, args.random_state)
    y_pred = model.predict(X_test_processed)
    accuracy = accuracy_score(y_test, y_pred)

    logger.info("Baseline Random Forest accuracy (teszt halmaz): %.4f", accuracy)
    print(f"\nBaseline Random Forest accuracy (teszt halmaz): {accuracy:.4f}")

    # --- 6) Mentes: modell, preprocessing pipeline, label encoder, feature-nevek ---
    joblib.dump(model, args.models_dir / "baseline_random_forest.joblib")
    joblib.dump(preprocessing, args.models_dir / "preprocessing_pipeline.joblib")
    joblib.dump(label_encoder, args.models_dir / "label_encoder.joblib")
    joblib.dump(NUMERIC_FEATURES, args.models_dir / "feature_columns.joblib")

    logger.info("Modell es preprocessing artefaktumok elmentve: %s", args.models_dir)
    print(f"Elmentve: {args.models_dir}/baseline_random_forest.joblib, "
          f"preprocessing_pipeline.joblib, label_encoder.joblib, feature_columns.joblib")


if __name__ == "__main__":
    main()
