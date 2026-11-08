"""
extract_features.py
--------------------
Vegigiteral egy mintakonyvtaron (PE fajlok, alkonyvtaranként cimkezve) es
minden fajlra lefuttatja a feature_extractor.yar szabalyt (EntryPointHashLog),
ami a "console" YARA modullal kulcs-ertek parokat ir ki (console.log). Ezeket
egy console_callback fuggveny kapja el, es alakitja at egy dataset-sorra.

A CIMKE (label) forrasa: a minta szulokonyvtaranak neve, pl.
    data/samples/<CSALAD_NEV>/<minta>.exe  ->  label = <CSALAD_NEV>

KIEMELT KORLATOK / ROBUSZTUSSAGI MEGJEGYZESEK (lasd meg a .yar fajlok
fejlec-kommentjeit is):

1) A "magic" YARA modul nem resze a szabvanyos pip yara-python csomagnak.
   A szkript eloszor a feature_extractor.yar (magic-os) valtozatot probalja
   leforditani; ha ez "unknown module" hibaval elszall, automatikusan
   a feature_extractor_no_magic.yar tartalek valtozatra vált, es a
   Type_magic mezot a pefile konyvtarral potolja.

2) A YARA szabaly egyetlen nagy AND-lancban lancolja a console.log
   hivasokat (tanari specifikacio). Ha egy korabbi tag serult fajlon
   undefined erteket ad, a lanc utani log-hivasok NEM futnak le - ezert
   minden vart kulcsot explicit ellenorzunk, a hianyzokat None/NaN-nal
   toltjuk fel, es a sort "partial_console_log=1"-gyel jelezzuk.

3) Egyetlen serult/idotullepett fajl sem allithatja meg a teljes futast -
   minden fajl feldolgozasa kulon try/except-ben tortenik, a hibak
   a "parse_error" oszlopban es egy kulon log fajlban is rögzitesre kerulnek.
"""

import argparse
import csv
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pefile
import yara
from tqdm import tqdm

PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".bin", ""}

# Azok a kulcsok, amiket a EntryPointHashLog szabalynak (siker eseten) mindig
# ki kell irnia. Ez alapjan tudjuk eldonteni, hogy egy minta eseten a YARA
# AND-lanc melyik pontig futott le (partial_console_log jelzeshez).
EXPECTED_LOG_KEYS = (
    ["FromBegin", "FromEnd"]
    + [f"EntryHash{n}" for n in range(10, 81, 10)]
    + [
        "InitializedData",
        "RELOCS_STRIPPED",
        "LINE_NUMS_STRIPPED",
        "LOCAL_SYMS_STRIPPED",
        "LARGE_ADDRESS_AWARE",
        "Number of imported functions",
        "EntryPoint",
        "Size of stack reserve",
        "Size of heap reserve",
        "Number of signatures",
        "Machine",
        "Subsystem",
        "Type_overlay",
    ]
)

# A Type_magic csak a magic-os valtozatban szerepel a YARA-logban; ha a
# fallback fut, ezt kulon, pefile-lal potoljuk (lasd magic_type_from_pefile).
MAGIC_KEY = "Type_magic"

# Oszlopnevekhez hasznalt "biztonsagos" (whitespace-mentes) alak.
def sanitize_column_name(raw_key: str) -> str:
    return re.sub(r"\s+", "_", raw_key.strip())


logger = logging.getLogger("extract_features")


def setup_logging(log_path: Path) -> None:
    """Beallitja a logolast fajlba (hibak/figyelmeztetesek) es konzolra."""
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(console_handler)


def safe_get(fn, default: Any = None) -> Any:
    """Hibaturo kiertekeles: kivetel eseten a default erteket adja vissza."""
    try:
        return fn()
    except Exception:
        return default


def is_magic_module_available() -> bool:
    """
    Kulon, minimalis proba-forditassal donti el, hogy a "magic" YARA modul
    hasznalhato-e ebben a kornyezetben. Ezt KULON kell ellenorizni (nem a
    fo szabaly forditasi hibauzenetebol kikovetkeztetve), mert attol
    fuggoen, hogy a modult hogyan hasznaljuk (csupasz import vs. fuggveny-
    hivas, pl. magic.type()), YARA eltero hibaszoveget ad vissza
    ("unknown module" vs. "invalid field name") - egy string-egyezes
    tehat nem megbizhato jelzo.
    """
    try:
        yara.compile(source='import "magic" rule _magic_probe { condition: true }')
        return True
    except yara.Error:
        return False


def compile_rules(primary_path: Path, fallback_path: Path) -> Tuple["yara.Rules", bool]:
    """
    Leforditja a feature_extractor.yar-t, vagy - ha a "magic" modul nem
    elerheto ebben a kornyezetben - a magic-mentes tartalek valtozatot.

    Visszaadja: (compiled_rules, magic_module_missing: bool)
    """
    if is_magic_module_available():
        rules = yara.compile(filepath=str(primary_path))
        logger.info("Sikeresen leforditva: %s (magic modullal)", primary_path)
        return rules, False

    logger.warning(
        "A 'magic' YARA modul nem elerheto ebben a kornyezetben (a szabvanyos "
        "pip yara-python build nem tartalmazza). Atvaltas a magic-mentes "
        "tartalek szabalyra: %s",
        fallback_path,
    )
    rules = yara.compile(filepath=str(fallback_path))
    return rules, True


def parse_console_logs(logs: List[str]) -> Dict[str, Any]:
    """
    A console_callback altal osszegyujtott "kulcs: ertek" alaku uzeneteket
    szotarra alakitja. A kulcsokat a sanitize_column_name normalizalja
    (szokoz -> alahuzas), az ertekeket pedig int/float-ra probalja alakitani.
    """
    parsed: Dict[str, Any] = {}
    for message in logs:
        if ": " not in message:
            continue
        raw_key, raw_value = message.split(": ", 1)
        key = sanitize_column_name(raw_key)
        value = raw_value.strip()
        if re.fullmatch(r"-?\d+", value):
            value = int(value)
        else:
            try:
                value = float(value)
            except ValueError:
                pass  # marad string (pl. sha256 hash)
        parsed[key] = value
    return parsed


def magic_type_from_pefile(pe: Optional["pefile.PE"]) -> str:
    """
    A 'magic' YARA modul hianyaban ez potolja a Type_magic mezot a PE
    Optional Header Magic ertekebol (PE32 / PE32+ / ROM / ISMERETLEN).
    """
    if pe is None:
        return "N/A"
    magic_value = safe_get(lambda: pe.OPTIONAL_HEADER.Magic, None)
    return {
        0x10B: "PE32",
        0x20B: "PE32+",
        0x107: "ROM",
    }.get(magic_value, "UNKNOWN")


def extract_console_features(
    rules: "yara.Rules",
    filepath: Path,
    magic_missing: bool,
    pe_for_magic_fallback: Optional["pefile.PE"],
) -> Dict[str, Any]:
    """
    Lefuttatja az EntryPointHashLog YARA szabalyt console_callback-kal, es
    a kigyujtott logokbol epiti fel a feature-szotart. Robusztus: ha a YARA
    kivetelt dob (pl. timeout), vagy a szabaly egyaltalan nem talal (nem PE
    fajl), akkor is konzisztens, None-nal feltoltott szotarat ad vissza.
    """
    row: Dict[str, Any] = {sanitize_column_name(k): None for k in EXPECTED_LOG_KEYS}
    row["console_yara_error"] = ""
    row["partial_console_log"] = 0

    logs: List[str] = []

    def console_callback(message: str) -> int:
        logs.append(message)
        return yara.CALLBACK_CONTINUE

    try:
        matches = rules.match(str(filepath), console_callback=console_callback, timeout=30)
        if not matches:
            row["console_yara_error"] = "Nincs YARA talalat (feltehetoen nem ervenyes PE)"
            row["partial_console_log"] = 1
    except yara.TimeoutError:
        row["console_yara_error"] = "YARA timeout"
        row["partial_console_log"] = 1
        logger.warning("YARA timeout: %s", filepath)
    except Exception as exc:
        row["console_yara_error"] = f"YARA hiba: {exc}"
        row["partial_console_log"] = 1
        logger.warning("YARA hiba (%s): %s", filepath, exc)

    parsed = parse_console_logs(logs)
    row.update(parsed)

    # Ha az AND-lanc korabban megszakadt (rovidzar-kiertekeles), a vart
    # kulcsok egy resze hianyozni fog -> jelezzuk, de nem hibaztatjuk el
    # a teljes sort.
    missing_keys = [
        sanitize_column_name(k) for k in EXPECTED_LOG_KEYS if sanitize_column_name(k) not in parsed
    ]
    if missing_keys:
        row["partial_console_log"] = 1
        if not row["console_yara_error"]:
            row["console_yara_error"] = f"Hianyzo mezok a rovidzar-kiertekeles miatt: {missing_keys}"

    if magic_missing:
        row[MAGIC_KEY] = magic_type_from_pefile(pe_for_magic_fallback)
    else:
        row.setdefault(MAGIC_KEY, None)

    return row


def open_pe_safely(filepath: Path) -> Tuple[Optional["pefile.PE"], int, str]:
    """
    Megnyitja a fajlt pefile-lal (csak a Type_magic fallback-hez es alap
    ertelmesseg-ellenorzeshez kell, a fo numerikus feature-oket mar a YARA
    console.log adja). Hiba eseten (None, 1, hibauzenet)-et ad vissza.
    """
    try:
        pe = pefile.PE(str(filepath), fast_load=True)
        return pe, 0, ""
    except Exception as exc:
        return None, 1, str(exc)


def iter_sample_files(input_dir: Path):
    """
    Bejarja az input_dir alkonyvtarait; minden fajlhoz a kozvetlen
    szulokonyvtar neve adja a cimket (label).
    """
    for path in sorted(input_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in PE_EXTENSIONS:
            continue
        yield path, path.parent.name


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PE minták feature-kinyerese YARA console.log callback-kal."
    )
    parser.add_argument("--input-dir", type=Path, default=Path("data/samples"))
    parser.add_argument("--output-csv", type=Path, default=Path("dataset.csv"))
    parser.add_argument("--yara-rule", type=Path, default=Path("feature_extractor.yar"))
    parser.add_argument(
        "--yara-rule-fallback", type=Path, default=Path("feature_extractor_no_magic.yar")
    )
    parser.add_argument("--log-file", type=Path, default=Path("extract_features.log"))
    args = parser.parse_args()

    setup_logging(args.log_file)

    if not args.input_dir.exists():
        logger.error("Az input konyvtar nem letezik: %s", args.input_dir)
        sys.exit(1)

    try:
        rules, magic_missing = compile_rules(args.yara_rule, args.yara_rule_fallback)
    except yara.Error as exc:
        logger.error("Egyik YARA szabaly sem forditható: %s", exc)
        sys.exit(1)

    samples = list(iter_sample_files(args.input_dir))
    if not samples:
        logger.error("Nem talalhato feldolgozhato fajl a(z) %s konyvtarban.", args.input_dir)
        sys.exit(1)

    logger.info("Feldolgozando mintak szama: %d", len(samples))

    rows: List[Dict[str, Any]] = []
    error_count = 0
    partial_count = 0

    for filepath, label in tqdm(samples, desc="Feature kinyeres", unit="fajl"):
        row: Dict[str, Any] = {
            "filename": filepath.name,
            "filepath": str(filepath),
            "label": label,
        }

        pe_obj, parse_error, parse_error_msg = open_pe_safely(filepath)
        try:
            row["file_size"] = filepath.stat().st_size
        except Exception:
            row["file_size"] = None

        console_features = extract_console_features(
            rules, filepath, magic_missing, pe_obj
        )
        row.update(console_features)

        row["parse_error"] = parse_error
        row["parse_error_msg"] = parse_error_msg

        if pe_obj is not None:
            try:
                pe_obj.close()
            except Exception:
                pass

        if parse_error:
            error_count += 1
        if row.get("partial_console_log"):
            partial_count += 1

        rows.append(row)

    if rows:
        # A fieldnames-t az osszes sor kulcsainak uniojabol keszitjuk, mert
        # nem minden sorban van pontosan ugyanaz a kulcshalmaz (pl. serult
        # fajloknal hianyzo mezok, vagy magic_missing miatti Type_magic).
        fieldnames: List[str] = []
        seen = set()
        for row in rows:
            for key in row.keys():
                if key not in seen:
                    seen.add(key)
                    fieldnames.append(key)
        with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    logger.info(
        "Kesz. %d minta feldolgozva | %d parse_error | %d partial_console_log | "
        "magic modul hianyzik: %s | Kimenet: %s",
        len(rows),
        error_count,
        partial_count,
        magic_missing,
        args.output_csv,
    )
    print(
        f"\nKesz! {len(rows)} minta feldolgozva "
        f"({error_count} parse_error, {partial_count} partial_console_log). "
        f"Magic modul hianyzik: {magic_missing}. "
        f"Eredmeny: {args.output_csv} | Log: {args.log_file}"
    )


if __name__ == "__main__":
    main()
