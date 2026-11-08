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
- **Hiányzó értékek:** MaxSectionEntropy 538 NaN → median imputálva
- **PCA 2 komponens:** PC1=20.82%, PC2=14.43%, összesen 35.25% variancia
- **Elbow heurisztika:** K=3 a legjobb (3 természetes klaszter)
- **Klaszter eloszlás (K=3):** Cluster 0: 28.2%, Cluster 1: 71.1%, Cluster 2: 0.7%
- **Korrelációk:** Legerősebb: NumberOfSections↔ImportedDLLCount (0.50), NumberOfImportedFunctions↔ImportedDLLCount (0.49), FileEntropy↔MaxSectionEntropy (0.43)
- **Vizuális artifactek:** correlation_matrix.png, elbow_plot.png, pca_kmeans_clusters.png

## Következő lépések
1. **SÜRGŐS:** Oktatótól bekérni a label fájlt (sha256,label CSV formátum)
2. Label merge a dataset_v2.csv-be → dataset_v2_labeled.csv
3. Modell építés (klasszifikáció): train/test split, baseline modell, hiperparaméter tuning
4. Értékelés: accuracy, precision, recall, F1, confusion matrix
