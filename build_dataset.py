import os
import sys
import csv
from pathlib import Path

RAW_DIR = Path("data/raw")
OUTPUT_CSV = Path("dataset_v2.csv")

SCALAR_KEYS = {
    "FileEntropy": "FileEntropy",
    "FileSize": "FileSize",
    "NumberOfSections": "NumberOfSections",
    "SizeOfCode": "SizeOfCode",
    "Number of imported functions": "NumberOfImportedFunctions",
    "ImportedDLLCount": "ImportedDLLCount",
    "NumberOfResources": "NumberOfResources",
    "DllCharacteristics": "DllCharacteristics",
}

COLUMNS = [
    "sha256",
    "FileEntropy",
    "FileSize",
    "NumberOfSections",
    "SizeOfCode",
    "NumberOfImportedFunctions",
    "ImportedDLLCount",
    "NumberOfResources",
    "DllCharacteristics",
    "MaxSectionEntropy",
    "ChecksumMismatch",
]


def parse_file(filepath: Path) -> dict:
    sha256 = filepath.stem
    row = {"sha256": sha256}
    scalars = {}
    section_entropies = []
    checksum = None
    calculated_checksum = None

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()

            if key in SCALAR_KEYS:
                scalars[SCALAR_KEYS[key]] = value
            elif key == "SectionEntropy":
                try:
                    section_entropies.append(float(value))
                except ValueError:
                    pass
            elif key == "Cheksum":
                checksum = value
            elif key == "CalculatedChecksum":
                calculated_checksum = value

    for col_name in SCALAR_KEYS.values():
        raw = scalars.get(col_name, "")
        if col_name == "FileEntropy":
            try:
                row[col_name] = float(raw)
            except (ValueError, TypeError):
                row[col_name] = ""
        else:
            try:
                row[col_name] = int(raw)
            except (ValueError, TypeError):
                row[col_name] = ""

    row["MaxSectionEntropy"] = max(section_entropies) if section_entropies else ""

    if checksum is not None and calculated_checksum is not None:
        try:
            row["ChecksumMismatch"] = 0 if int(checksum) == int(calculated_checksum) else 1
        except ValueError:
            row["ChecksumMismatch"] = ""
    else:
        row["ChecksumMismatch"] = ""

    return row


def main():
    if not RAW_DIR.is_dir():
        print(f"ERROR: {RAW_DIR} does not exist. Extract data2.tgz first.", file=sys.stderr)
        sys.exit(1)

    txt_files = sorted(RAW_DIR.glob("*.txt"))
    print(f"Found {len(txt_files)} files in {RAW_DIR}")

    rows = []
    errors = 0
    for i, fp in enumerate(txt_files, 1):
        try:
            rows.append(parse_file(fp))
        except Exception as e:
            errors += 1
            print(f"  WARN: {fp.name}: {e}", file=sys.stderr)
        if i % 5000 == 0:
            print(f"  Processed {i}/{len(txt_files)}...")

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Done. Wrote {len(rows)} rows to {OUTPUT_CSV} ({errors} errors)")


if __name__ == "__main__":
    main()
