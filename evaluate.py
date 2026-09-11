"""
evaluate.py
-----------
Fazis 3: egysegesen kiertekel BARMILYEN betanitott modellt, amit a
models/ mappaba mentettunk (train_models.py altal, vagy kesobb Gyula/Attila
tovabbi modelljei altal, ugyanazzal az artefaktum-keszlettel: preprocessing
pipeline, label encoder, feature-oszlopnevek).

A train_models.py-ban mar megirt, tesztelt logikat (adatbetoltes, tisztitas,
kis-mintas fallback-kel ellatott stratifikalt split) UJRAHASZNOSITJA import
utjan, hogy az evaluate.py PONTOSAN ugyanazt a train/test felosztast lassa,
mint amivel a modell betanult - igy a kiertekeles a valodi, sosem latott
teszt-halmazon tortenik, adatszivargas nelkul.

Kimenet:
    - Konzolra: Accuracy, Precision/Recall/F1 (macro es weighted), reszletes
      classification_report.
    - Fajlba: konfuzios matrix kep (PNG) a projekt gyokereben.
"""

import argparse
import logging
import sys
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")  # fejlec nelkuli (headless) kornyezetben is mukodjon
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)

import train_models as tm

logger = logging.getLogger("evaluate")


def setup_logging(log_path: Path) -> None:
    """Fajlba es konzolra logol, a projekt tobbi szkriptjevel konzisztens modon."""
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(console_handler)


def load_artifacts(models_dir: Path, model_filename: str):
    """Betolti a modellt es a hozza tartozo preprocessing-artefaktumokat."""
    model_path = models_dir / model_filename
    for path in [
        model_path,
        models_dir / "preprocessing_pipeline.joblib",
        models_dir / "label_encoder.joblib",
        models_dir / "feature_columns.joblib",
    ]:
        if not path.exists():
            raise FileNotFoundError(
                f"Hianyzo artefaktum: {path}. Eloszor futtasd a train_models.py-t."
            )

    model = joblib.load(model_path)
    preprocessing = joblib.load(models_dir / "preprocessing_pipeline.joblib")
    label_encoder = joblib.load(models_dir / "label_encoder.joblib")
    feature_columns = joblib.load(models_dir / "feature_columns.joblib")
    return model, preprocessing, label_encoder, feature_columns


def prepare_evaluation_set(
    df: pd.DataFrame,
    feature_columns,
    label_encoder,
    eval_set: str,
    test_size: float,
    random_state: int,
):
    """
    Elokesziti a kiertekelendo X/y-t, pontosan a feature_columns altal
    meghatarozott oszlop-sorrendben.

    eval_set == "test": ugyanazt a stratifikalt train/test split-et
        reprodukalja, mint a train_models.py (ugyanazokkal a
        test_size/random_state ertekekkel), es csak a teszt-reszt adja
        vissza - igy garantalt, hogy a modell nem lathatta ezeket a
        mintakat tanitaskor.
    eval_set == "full": a teljes (tisztitott) adathalmazon ertekel ki -
        hasznos kis fixture-adaton demonstracios celra, de FONTOS: ekkor
        a tanito mintak is a kiertekelesben vannak, tehat a metrikak
        tulzottan optimistak lehetnek.
    """
    X = df[feature_columns].apply(pd.to_numeric, errors="coerce")
    y = label_encoder.transform(df[tm.LABEL_COLUMN])

    if eval_set == "full":
        logger.warning(
            "eval-set=full: a TELJES adathalmazon ertekelunk ki, beleertve a "
            "tanito mintakat is - a metrikak igy tulzottan optimistak lehetnek. "
            "Csak demonstraciora / kis fixture-adatra ajanlott."
        )
        return X, y

    _, X_test, _, y_test = tm.stratified_split_with_fallback(
        X, y, test_size, random_state
    )
    return X_test, y_test


def print_metrics(y_true, y_pred, class_names) -> None:
    """Szepen formazott metrikakat ir a konzolra."""
    accuracy = accuracy_score(y_true, y_pred)
    precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    precision_weighted, recall_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )

    separator = "=" * 60
    lines = [
        separator,
        "MODELL KIERTEKELES",
        separator,
        f"Accuracy:              {accuracy:.4f}",
        "",
        f"{'Metrika':<12}{'Macro':>12}{'Weighted':>12}",
        f"{'Precision':<12}{precision_macro:>12.4f}{precision_weighted:>12.4f}",
        f"{'Recall':<12}{recall_macro:>12.4f}{recall_weighted:>12.4f}",
        f"{'F1-score':<12}{f1_macro:>12.4f}{f1_weighted:>12.4f}",
        "",
        "Reszletes classification report:",
        classification_report(
            y_true, y_pred, target_names=class_names, zero_division=0
        ),
        separator,
    ]
    report_text = "\n".join(lines)
    print(report_text)
    logger.info("Accuracy=%.4f | F1-macro=%.4f | F1-weighted=%.4f", accuracy, f1_macro, f1_weighted)


def save_confusion_matrix(y_true, y_pred, class_names, output_path: Path) -> None:
    """Konfuzios matrix keszitese es mentese PNG-kent."""
    all_label_indices = list(range(len(class_names)))
    cm = confusion_matrix(y_true, y_pred, labels=all_label_indices)

    plt.figure(figsize=(max(6, len(class_names) * 1.2), max(5, len(class_names) * 1.0)))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=class_names,
        yticklabels=class_names,
        cbar=True,
    )
    plt.xlabel("Predikalt osztaly")
    plt.ylabel("Valos osztaly")
    plt.title("Konfuzios matrix")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    logger.info("Konfuzios matrix elmentve: %s", output_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Betanitott modell egyseges kiertekelese a dataset.csv-n."
    )
    parser.add_argument("--dataset-csv", type=Path, default=Path("dataset.csv"))
    parser.add_argument("--models-dir", type=Path, default=Path("models"))
    parser.add_argument(
        "--model-filename",
        type=str,
        default="baseline_random_forest.joblib",
        help="A models/ mappaban levo modell-fajl neve (barmilyen elmentett modellre cserelheto).",
    )
    parser.add_argument(
        "--output-image", type=Path, default=Path("confusion_matrix_baseline.png")
    )
    parser.add_argument(
        "--eval-set",
        choices=["test", "full"],
        default="test",
        help="'test': ugyanaz a stratifikalt teszt-split, mint a training soran (ajanlott). "
        "'full': a teljes adathalmaz (csak demonstraciora).",
    )
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--log-file", type=Path, default=Path("evaluate.log"))
    args = parser.parse_args()

    setup_logging(args.log_file)

    if not args.dataset_csv.exists():
        logger.error("%s nem letezik.", args.dataset_csv)
        sys.exit(1)

    try:
        model, preprocessing, label_encoder, feature_columns = load_artifacts(
            args.models_dir, args.model_filename
        )
    except FileNotFoundError as exc:
        logger.error(str(exc))
        sys.exit(1)

    df = tm.load_dataset(args.dataset_csv)
    df = tm.clean_dataset(df)

    X_eval, y_eval = prepare_evaluation_set(
        df, feature_columns, label_encoder, args.eval_set, args.test_size, args.random_state
    )
    logger.info("Kiertekelt minta-szam (%s halmaz): %d", args.eval_set, len(X_eval))

    X_eval_processed = preprocessing.transform(X_eval)
    y_pred = model.predict(X_eval_processed)

    class_names = list(label_encoder.classes_)
    print_metrics(y_eval, y_pred, class_names)
    save_confusion_matrix(y_eval, y_pred, class_names, args.output_image)

    print(f"\nKonfuzios matrix elmentve: {args.output_image}")


if __name__ == "__main__":
    main()
