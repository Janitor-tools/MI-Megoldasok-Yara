# Projekt állapot — MI Megoldások a Kibervédelemben (YARA)

## Utolsó frissítés: 2026-11-08

## Specifikáció változás
A projekt iránya megváltozott: az oktató (megrendelő) már lefuttatta a YARA extrakciót a nyers malware mintákon, és átadta a kinyert adatokat. A feladat most a kinyert adatokból egy fix 10 feature-t tartalmazó adathalmaz építése a modellezéshez.

## Repó struktúra
```
MI-Megoldasok-Yara/
├── archive_phase1/          # Régi pipeline (feature_extractor.yar, extract_features.py)
├── Instrukciók/             # Tanártól kapott anyagok
│   ├── peinfo1.yara         # Alap PE header extrakció (commitolva)
│   ├── peinfo2.yara         # Bővített PE extrakció (commitolva)
│   ├── data1.tgz            # Alap adatok, 37528 fájl (.gitignore-ban)
│   └── data2.tgz            # Bővített adatok, 38161 fájl (.gitignore-ban)
├── data/
│   └── raw/                 # data2.tgz kicsomagolva (.gitignore-ban)
├── build_dataset.py         # Feature kinyerő szkript
├── dataset_v2.csv           # Végleges adathalmaz (38161 sor, 10 feature + sha256 index)
├── peinfo1.yara             # YARA szabályok másolata a gyökérben
├── peinfo2.yara
└── .gitignore
```

## Architekturális döntések
- **Adatforrás:** Kizárólag `data2.tgz` (peinfo2.yara kimenet) — teljes szuperhalmaza data1-nek
- **Label:** NINCS — az oktató még nem adta meg a sha256 → label összerendelést
- **Feature-ök (10 db, végleges):**
  1. FileEntropy (float) — tömörítés/titkosítás jelzője
  2. FileSize (int) — fájlméret
  3. NumberOfSections (int) — PE szekciók száma
  4. SizeOfCode (int) — kód szekció mérete
  5. NumberOfImportedFunctions (int) — importált függvények száma
  6. ImportedDLLCount (int) — importált DLL-ek száma
  7. NumberOfResources (int) — erőforrások száma
  8. DllCharacteristics (int) — ASLR/DEP/NX bitmask
  9. MaxSectionEntropy (float, derived) — legmagasabb szekció-entrópia
  10. ChecksumMismatch (0/1, derived) — Checksum != CalculatedChecksum
- **Imphash:** Kihagyva — szigorúan 10 numerikus feature
- **Git policy:** Raw adatok és .tgz fájlok .gitignore-ban, csak a YARA szabályok és a kód commitolva

## EDA & Unsupervised eredmények (2026-11-08)
- **Hiányzó értékek:** MaxSectionEntropy 538 NaN (1.4%) → median imputálva
- **Korrelációk:** Legerősebb: NumberOfSections↔ImportedDLLCount (0.50), NumberOfImportedFunctions↔ImportedDLLCount (0.49), FileEntropy↔MaxSectionEntropy (0.43)

### PCA dimenzióelemzés
- **2 komponens (vizualizációhoz):** PC1=20.82%, PC2=14.43%, összesen 35.25%
- **90% variancia eléréséhez:** 8 komponens kell (91.6%)
- **95% variancia eléréséhez:** 9 komponens kell (95.9%)
- **Konklúzió:** A variancia egyenletesen oszlik el a feature-ök között (nincs domináns PC), ami arra utal, hogy a 10 feature viszonylag ortogonális/független információt hordoz — a klasszifikációnál érdemes mind a 10-et megtartani, nem csökkenteni dimenzióval.

### Klaszter profil (K=3, Elbow heurisztika)
- **Cluster 1 (71.1%, 27131 minta):** "Tipikus malware" — közepes méret, magas entrópia (6.92), átlagos import komplexitás
- **Cluster 0 (28.2%, 10776 minta):** "Alacsony entrópiájú" — alacsony FileEntropy (4.85), kevés import (60 fn, 2.7 DLL), nagy kódszekció
- **Cluster 2 (0.7%, 254 minta):** "Komplex outlierek" — drasztikusan eltér:
  - NumberOfSections: **10.3x** az átlagnál (medián 89 szekció!)
  - NumberOfResources: **28.3x** (medián 401)
  - ImportedDLLCount: **10.2x** (medián 23 DLL)
  - NumberOfImportedFunctions: **5.9x** (medián 679)
  - Interpretáció: Valószínűleg erősen pakolt/obfuszkált vagy legitim komplex binárisok, amelyek kiemelkedő számú szekciót és erőforrást tartalmaznak

### Generált fájlok
- `correlation_matrix.png`, `elbow_plot.png`, `pca_kmeans_clusters.png`, `pca_cumulative.png`
- `dataset_v2_clustered.csv` — az eredeti adathalmaz + Cluster oszlop

## ML Pipeline csontváz (2026-11-08)
- **Fájl:** `ml_pipeline_skeleton.py` — teljes, futtatható pipeline
- **Modellek:** RandomForest (200 fa, max_depth=15, balanced) + XGBoost (200 iter, lr=0.1)
- **Validáció:** 5-fold Stratified Cross-Validation + 80/20 holdout test set
- **Metrikák:** Accuracy, Precision, Recall, F1 (weighted), ROC-AUC
- **Label:** Jelenleg dummy (random 0/1) — `load_data()` függvényben cserélendő
- **Dummy eredmény:** ~50% minden metrikán (elvárt random labellel)
- **Státusz:** KÉSZ, valódi label-re vár

## SHAP Explainability (2026-11-08)
- **Fájl:** `shap_explainer.py` — TreeExplainer-rel, 1000 mintás teszthalmazon
- **Módszer:** SHAP beeswarm plot (feature importance + irány)
- **Dummy eredmény (top 3):** FileEntropy (0.0074), MaxSectionEntropy (0.0072), FileSize (0.0064)
- **Megjegyzés:** Dummy label-ekkel a SHAP értékek kicsik és szimmetrikusak (~0 körül) — elvárt. Valódi label-ekkel a feature-ök differenciáló ereje ki fog rajzolódni.
- **Vizuális artifact:** `shap_summary_dummy.png`

## Következő lépések
1. **SÜRGŐS:** Oktatótól bekérni a label fájlt (sha256,label CSV formátum)
2. Label merge → `load_data()` dummy generálás cseréje valódi CSV olvasásra
3. Hiperparaméter tuning (GridSearch / RandomizedSearch)
4. Confusion matrix vizualizáció + SHAP újrafuttatás valódi label-ekkel
