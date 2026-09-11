# MI-Megoldasok-Yara — PE Malware Classification

> ## AI Context & Project Brief
>
> **Project type:** Supervised multi-class classification of Windows PE malware, using static structural features extracted with YARA + Python.
>
> **Pipeline status:**
> - **Phase 1 (Feature Extraction) — DONE.** `feature_extractor.yar` defines a single rule, `EntryPointHashLog`, which uses the YARA `console` module (`console.log(...)`) to emit key/value pairs for each scanned PE file (entry-point offsets, a family of `hash.sha256(entry_point, N)` fingerprints for N=10..80, PE header flags, import/signature counts, etc.). `extract_features.py` compiles this rule, runs it per-file via `yara.Rules.match(..., console_callback=...)`, parses the captured log lines into a row dict, and writes everything to `dataset.csv`. A fallback rule (`feature_extractor_no_magic.yar`) and automatic runtime detection handle environments where the YARA `magic` module isn't compiled in (the standard pip wheel lacks it) — in that case `Type_magic` is filled in from `pefile`'s `OPTIONAL_HEADER.Magic` instead. Every file is processed in isolation with try/except; corrupted/truncated PEs never crash the run — they get `parse_error=1` and/or `partial_console_log=1` with the rest of the row filled with defaults.
> - **Data:** `dataset.csv` — one row per sample, `label` column = the sample's parent directory name (i.e. malware family / `benign_system` for benign controls). Numeric columns come straight from the YARA console log; a few (`file_size`, `parse_error*`, `Type_magic` fallback) come from `pefile`.
> - **Phase 2 (Modeling) — NEXT.** Needs `train_models.py`: load `dataset.csv`, build a preprocessing pipeline (missing-value imputation for `partial_console_log=1` rows, `StandardScaler` for the numeric features, label encoding for `label`), then train/compare 4 classifiers: Random Forest, XGBoost (or GradientBoosting as a no-extra-dependency fallback), SVM, KNN, Logistic Regression.
> - **Phase 3 (Evaluation) — NOT STARTED.** Needs `evaluate.py`: Precision/Recall/F1 per model, confusion matrix images saved to the repo root.
>
> If you are an AI assistant picking this up cold: read `feature_extractor.yar`'s header comment first — it documents two non-obvious YARA quirks (the `magic` module gap, and short-circuit evaluation truncating the console log on corrupted files) that shape the CSV schema.

---

## Projekt áttekintés

Ez egy Óbudai Egyetemi projekt, amelynek célja Windows PE (Portable Executable) kártevő minták **statikus, strukturális jellemzőinek** kinyerése YARA segítségével, majd ezek alapján **felügyelt, többosztályos gépi tanulásos klasszifikáció** (malware család szerinti besorolás) elvégzése.

**Csapat:** József (Fázis 1), Gyula és Attila (Fázis 2).

**Tech stack:** Python, `yara-python`, `pefile`, `pandas`, `scikit-learn`, `matplotlib`/`seaborn`.

## Lokális környezet beállítása

```powershell
# 1. Virtuális környezet létrehozása (Python 3.11+ ajánlott — a 3.14-hez
#    egyelőre nincs előre fordított yara-python wheel Windows alatt)
py -3.11 -m venv venv    # vagy py -3.12 / py -3.13

# 2. Aktiválás
venv\Scripts\activate

# 3. Függőségek telepítése
pip install -r requirements.txt
```

> Ha nincs 3.11/3.12/3.13 telepítve, ellenőrizd a `py -0p` kimenetét, vagy telepíts egyet — a `yara-python` forrásból fordítása Windowson build-eszközöket igényelne, ezt érdemes elkerülni.

## Fázisok és munkamegosztás

### Fázis 1: Adatkinyerés (József — **Kész**)

- **`feature_extractor.yar`** — egyetlen szabály (`EntryPointHashLog`), ami a `pe`, `console` és `hash` YARA modulokkal (opcionálisan `magic`-kal) **kulcs-érték párokat logol** minden vizsgált PE fájlra: entry point offset (fájl elejétől/végétől), 8 db `sha256` ujjlenyomat az entry point körüli növekvő méretű bájt-ablakokból (10–80 byte), PE header flag-ek (`RELOCS_STRIPPED`, `LARGE_ADDRESS_AWARE`, stb.), import-függvények száma, aláírás-szám, gép/subsystem típus, overlay offset.
- **`feature_extractor_no_magic.yar`** — automatikus tartalék, ha a futtató környezet `yara-python`-ja nincs `magic` (libmagic) támogatással fordítva (ez a pip-es alapértelmezett wheel esetén jellemző, ellenőrizve).
- **`extract_features.py`** — bejárja a mintakönyvtárat (címke = szülőmappa neve), lefuttatja a YARA szabályt egy `console_callback`-kal, ami elkapja a logolt sorokat és `dataset.csv` sorává alakítja őket.
- **Robusztusság:** minden fájl feldolgozása külön van védve — sérült/csonka PE fejléc, YARA timeout, vagy a `console.log` AND-lánc félbeszakadása (rövidzár-kiértékelés) esetén a hiányzó mezők `None`/alapértéket kapnak, a sor `parse_error` és/vagy `partial_console_log` flag-et kap, a hiba részletei `extract_features.log`-ba kerülnek. **Egyetlen rossz fájl sem állíthatja meg a 10 000+ mintás futást.**

Futtatás:
```powershell
python extract_features.py --input-dir data/samples --output-csv dataset.csv
```

### Fázis 2: Modellezés (Gyula és Attila — **Következő lépés**)

Célfájl: **`train_models.py`**. A hatékonyság érdekében a munka két párhuzamos szálra van osztva:

| Ki | Fókusz | Algoritmusok |
|---|---|---|
| **Gyula** | Fa-alapú együttes (ensemble) modellek — nem érzékenyek a jellemzők skálázására | Random Forest, XGBoost / GradientBoosting |
| **Attila** | Skálázást igénylő, távolság- vagy margó-alapú modellek | SVM, KNN, Logistic Regression |

Közös előfeltétel mindkettőnek: a `dataset.csv` betöltése és egy közös **preprocessing pipeline** (hiányzó értékek kezelése ott, ahol `partial_console_log=1`, `StandardScaler` a numerikus oszlopokra, `label` kódolása). Ezt érdemes egy közösen használt `preprocessing.py`-ba vagy egy `sklearn.Pipeline`-ba szervezni, hogy a két fél munkája ne térjen el az adat-előkészítésben.

### Fázis 3: Kiértékelés (Közös)

Célfájl: **`evaluate.py`** — a betanított modellek összehasonlítása Precision/Recall/F1 metrikákkal, valamint konfúziós mátrixok mentése képfájlként a gyökérkönyvtárba.

---

## 📍 TODO / Mérföldkövek

- [ ] **József:** A projekt alapstruktúrájának és a Fázis 1 kódjának feltöltése a közös Git repóba.
- [ ] **József:** Az `extract_features.py` és a YARA szabály éles futtatása a Debian SSH szerveren a 10.000+ mintán.
- [ ] **József:** A legenerált valós `dataset.csv` letöltése és megosztása a csapattal.
- [ ] **Gyula & Attila:** A repó klónozása és a lokális Python környezetek (venv) felállítása.
- [ ] **Gyula & Attila:** A Fázis 2 (Modellezés) kódjának kidolgozása a valós adathalmazon, majd commitolása.
- [ ] **Közös:** A Fázis 3 (Kiértékelés) lefuttatása az elkészült modelleken.
- [ ] **Közös:** Az eredmények (metrikák, konfúziós mátrixok) elemzése és a végső dokumentáció/prezentáció elkészítése.

---

## 💡 AI Prompt — másold be ezt a saját AI asszisztensednek

```
Csatlakoztam egy egyetemi projekthez (Óbudai Egyetem), aminek célja Windows
PE malware minták felügyelt, többosztályos gépi tanulásos klasszifikációja.
A Fázis 1 (feature extraction) MÁR KÉSZ: van egy feature_extractor.yar YARA
szabály (EntryPointHashLog), ami a YARA console modullal console.log
hívásokkal ír ki kulcs-érték párokat (entry point offsetek, 8 db sha256
hash az entry point körüli 10-80 byte-os ablakokból, PE header flag-ek,
import-szám, stb.), és egy extract_features.py szkript, ami ezt egy
console_callback-kal elkapja és dataset.csv-be exportálja (egy sor =
egy PE fájl, label oszlop = a minta szülőmappájának neve = malware
család vagy "benign_system"). A dataset.csv-ben vannak parse_error és
partial_console_log oszlopok is: ezek jelzik a sérült/csomagolt PE
fájlokat, ahol néhány numerikus mező hiányzik (None).

A feladatom most a Fázis 2 megírása: train_models.py, ami:
1. Betölti a dataset.csv-t pandas-szal.
2. Épít egy preprocessing pipeline-t: hiányzó numerikus értékek imputálása
   (pl. SimpleImputer, mediánnal vagy 0-val), StandardScaler a numerikus
   jellemzőkre, LabelEncoder a "label" célváltozóra. A nem-feature oszlopokat
   (filename, filepath, parse_error_msg, console_yara_error, hash-string
   oszlopok mint EntryHash10..EntryHash80 - ezek hex stringek, nem
   numerikus feature-ök alapból) külön kell kezelni vagy kihagyni /
   kategorikus encode-olni.
3. Train/test split-et csinál (stratified, mert több osztályunk van).
4. Felkészíti a kódvázat (scikit-learn Pipeline-nal) 4 algoritmushoz:
   Random Forest, XGBoost (vagy GradientBoostingClassifier, ha nincs
   xgboost telepítve), SVM, KNN, Logistic Regression - úgy, hogy a
   fa-alapú modellek és a skálázást igénylő modellek külön, tisztán
   elválasztható kódrészben legyenek (két csapattárs párhuzamosan dolgozik
   rajtuk).
5. Minden modellt elment a models/ mappába (joblib).

Kérlek, nézd át a dataset.csv fejlécét és feature_extractor.yar-t a
projektben, majd írd meg a train_models.py vázát ezekkel a lépésekkel,
PEP 8 szerint, jól kommentezve, moduláris függvényekkel.
```
