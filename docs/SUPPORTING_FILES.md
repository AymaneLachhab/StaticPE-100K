# Supporting files

These accompany the nine tables of `data/`. They are what makes the
numbers of the paper checkable: the mapping with its evidence, the
audit column by column, and the reference results.

## `mapping/`

### `family_to_threat.csv`  (0.3 MB)

Family to threat category, one row per attribution, with the source, the address at which to check it and the sentence that justified it. 1,931 rows over 1,006 families.

## `audit/`

### `audit_detection_random.csv`  (1.8 MB)

Provenance audit, binary detection under the random policy: global AUC, AUC inside strata, drop, number of strata and coverage, for each of the 18,421 columns that can be judged.

## `results/`

### `text_columns.json`  (0.5 MB)

The columns of the restricted matrix, those that correspond to the fields of the readable text given to the language model.

### `lightgbm_full.json`  (49 kB)

LightGBM on the full matrix: every metric, for each task and policy.

### `random_forest_full.json`  (48 kB)

Random forest on the full matrix.

### `mlp_full.json`  (48 kB)

Multi-layer perceptron on the full matrix.

### `lightgbm_text_columns.json`  (2 kB)

LightGBM restricted to the columns of the text.

### `qwen_text.json`  (1 kB)

Qwen2.5-1.5B on the readable text.

### `pruned_detection.json`  (1 kB)

The pruned variant of both, binary detection only.
