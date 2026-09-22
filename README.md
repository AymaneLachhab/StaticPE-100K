# StaticPE

A curated static-analysis benchmark of **100,909 Windows Portable Executable
files**: 83,885 malicious and 17,024 benign, deduplicated by SHA-256 and
processed by a single extraction chain into **18,489 usable columns**.

Three things distinguish this release from existing PE corpora.

**Function names are preserved.** Imported and exported functions keep their
full names instead of being hashed into fixed-size buckets, so a feature
importance can be attributed to `imp:kernel32.dll!Sleep` rather than to
bucket 417.

**Every annotation states its origin.** A label is either *measured on the
file*, when a tool was run on that binary and returned a verdict specific to
it, or *inherited from the family*, when a category known of the family was
propagated to its members. The two support different claims, and the corpus
says which is which.

**Five splitting policies are frozen in the data.** Random, import-hash
grouped, family grouped, out-of-time and cross-type, computed once and stored
as columns. Every model reads the same partitions, so a difference between
two reported numbers is attributable to the model and not to the draw.

No executable is redistributed. Malicious binaries were deleted after
measurement and only derived measurements and content hashes are published.

---

## Repository layout

```
pipeline/
  01-collect/malware/   VirusShare acquisition, analysis, deletion
  01-collect/benign/    four channels, then external verification
  02-extract/           PE decoding and the pivot into columns
  03-label/packing/     three detectors and the aggregation rule
  03-label/capa/        capability analysis and the anti-analysis label
  03-label/family/      family attribution and the threat mapping
  04-split/             the five splitting policies
  05-evaluate/          models, provenance audit, figures
  hpc/                  tool installation and cluster job scripts
mapping/                family to threat category, with its evidence
audit/                  the provenance audit, column by column
results/                reference results of every model
docs/                   SCHEMA.md and SUPPORTING_FILES.md
```

The data themselves are **not in this repository**. GitHub refuses any file
above 100 MB, and a file that enters one commit stays in the history forever.
They are attached to the releases instead.

## Getting the data

| Asset | Size | What it holds |
|---|---|---|
| `staticpe-data.tar.gz` | ~250 MB | the nine Parquet tables |
| `staticpe-capa.jsonl.gz` | 18 MB | every capa report, one JSON per line |
| `staticpe-raw-malware.tar.gz` | ~600 MB | 83,885 per-file JSON extractions |
| `staticpe-raw-benign.tar.gz` | ~330 MB | 17,024 per-file JSON extractions |

Most users need only the first. The raw JSON is the intermediate form from
which everything else derives: whoever holds it can recompute a different
representation without ever touching a binary.

The nine tables each hold one row per file, keyed by `sha256`, and join on
that key. `docs/SCHEMA.md` documents every dense column with its type and its
number of nulls, generated from the files themselves rather than written by
hand.

---

## The pipeline

Each stage below is a directory under `pipeline/`. They run in order, and
each consumes what the previous one produced.

### 01 — Collect

The two acquisition chains stay separate until they converge on a shared
extractor. The asymmetry is deliberate: a sample published by a malware
repository is admitted on its provenance, a file downloaded from a
distribution mirror is not. A repository asserts that a file was observed
doing harm; a mirror asserts only that it distributes the file.

**Malware** — `01-collect/malware/`

`fetch_and_analyse.py` is the core. It reads the hash lists VirusShare
publishes, deduplicates them against everything already attempted, and
queries one hash at a time. Each binary is written to node-local storage,
analysed, measured, and **deleted**; no raw sample is retained beyond the
extraction step. A file the PE parser refuses is recorded as a parse failure
and never enters the corpus, because malware repositories also hold
documents, archives and executables for other operating systems.

`hpc/oar_download.sh` and `hpc/oar_analyse.sh` submit the two phases to an
OAR scheduler. Acquisition is resumable and skips whatever it already finds,
so only a definitive answer from the repository is recorded; a dropped
connection or an exhausted quota is retried on the next pass rather than
hardened into a permanent result.

**Benign** — `01-collect/benign/`

`collect_benign_multi.py` draws on four channels: the Internet Archive, the
Windows Package Manager manifest repository, PortableApps and SourceForge
release feeds. Several channels are used for the toolchains and the release
periods they span; a benign corpus drawn from a single system image would
share one toolchain and one release window, and a classifier could then
separate the classes on the linker rather than on the program.

`extract_benign.py` opens the downloaded installers and extracts the PE
images they contain, one by one, each keeping the trace of its origin.

`verify_pe_ha.py` is what makes a file benign. A file is not benign because a
mirror distributes it: each candidate is queried against Hybrid Analysis by
hash, and admitted only when no antivirus engine flagged it, the service
reported it neither malicious nor suspicious, and the service returned an
explicit acquittal. A candidate on which the service held no report is
rejected, because silence is not an acquittal.

### 02 — Extract

`cluster_all_in_one.py` decodes the PE format with LIEF and emits one JSON
document per file, preserving the hierarchy of the format. That intermediate
form is what the raw archives ship, and it is what allows a different
representation to be recomputed without re-reading a binary.

The `build_*_parquet.py` scripts then turn those documents into tables. The
difficulty is that a file imports a variable number of functions, exports a
variable number, holds a variable number of sections. Those are **pivoted**:
every distinct name observed across the corpus becomes its own binary column.
A name enters the vocabulary only if it appears in at least fifty files,
below which a column carries no generalisable information and offers a model
a disguised identifier of the file it came from.

The pivot is what carries the space to 18,489 usable columns: 17,540 named
indicators and 949 dense measurements.

### 03 — Label

Three annotations, obtained three different ways, and the difference matters.

**Packing** — `03-label/packing/`

`run_packer_detectors.py` runs three complementary tools: PyPackerDetect and
Manalyze, which reason structurally on section entropy, non-standard names,
import count and entry-point position, and PEiD, which matches entry-point
byte patterns against a signature database. A signature match names the
packer that produced a sample but says nothing about a packer absent from its
database, whereas a low import count is a consequence of packing that either
structural detector can catch on its own.

`packed_vote.py` aggregates them by an explicit rule rather than by majority.
Let `Y` be the number of detectors reporting a packer and `E` the number that
failed to run. A sample is packed when `Y >= 1`, unpacked when `Y = 0` and
`E = 0`, and carries **no usable state** otherwise. The asymmetry is
deliberate: a positive detection is evidence, a negative answer only states
that one detector did not recognise the sample. A sample with no usable state
is not counted as unpacked by default; it was removed before release.

**Capability** — `03-label/capa/`

`run_capa.py` matches capa rules against the disassembled program.
`capacites.py` and `corriger_anti_analysis.py` derive the `anti_analysis`
label from six namespaces: `anti-vm`, `anti-debugging`, `anti-forensic`,
`anti-disasm`, `anti-av` and `obfuscation`.

A seventh namespace, `packer`, sits under the same `anti-analysis` prefix and
is **deliberately excluded**, because packing is already a label of its own
and folding it in would make the two tasks partly the same question.
Selecting by prefix rather than by explicit enumeration would silently
include it, and doing so raises the positive count from 28,421 to 49,284.

**Family and threat** — `03-label/family/`

`construire_entree_avclass.py` prepares the antivirus detection names,
AVClass reduces them to a canonical family name, and `mb_fetch.py` completes
the coverage from MalwareBazaar, MetaDefender and VirusTotal. Coverage is
90.4% of the malicious subset over 3,761 distinct families.

`cartographier_familles.py` and `appliquer_cartographie.py` then map each
family to one or more of fifteen threat categories and propagate the
categories to every member. The mapping is in `mapping/`, 1,931 attributions
over 1,006 families, and **every row carries its evidence**: the source, the
address at which to check it and the sentence that justified it. An
attribution can be contested one row at a time.

This is the stage that produces inherited labels, and the consequence is the
point of the paper. A file labelled `banker` is not a file on which banking
behavior was observed; it is a file belonging to a family whose known role is
banking. The assertion holds for the lineage and is attributed to the member.

### 04 — Split

`decoupages.py` computes the five policies once and writes them as columns,
so that every model reads the same partitions.

| Column | Policy | What it forbids the model |
|---|---|---|
| `split_random` | 70/15/15, stratified | nothing: the baseline |
| `split_group` | import-hash grouped | reusing a call structure already seen |
| `split_family` | family grouped | recognizing a family already seen |
| `split_temps` | train ≤2022, test ≥2024 | knowing later techniques |
| `split_croise` | train on EXE, test on DLL | relying on the format |

`ajouter_split_temps.py` leaves the 15,784 files without a usable timestamp
**unassigned** rather than silently placing them in the training set.
`ajouter_split_croise.py` keeps validation on the executable side, since
placing it with the test would calibrate the decision threshold on the very
distribution being evaluated.

### 05 — Evaluate

`trois_modeles.py` trains the three tabular families, LightGBM, random forest
and multi-layer perceptron, on every task and every policy. Hyperparameters
are fixed once and not tuned per cell: a per-cell search would favour the
easiest policies, those whose validation set resembles its test set, and so
distort the comparison.

`colonnes_du_texte.py` builds the restricted matrix, the columns that
correspond to the fields of the readable text. `serialiser_llm.py` writes
that text, at most nine lines per file, with `na` for an unmeasured value and
no identifier of any kind. `finetune_llm.py` fully fine-tunes
Qwen2.5-1.5B-Instruct on it, with a classification head and no adapter, so
the comparison bears on the model rather than on an adaptation method.

`audit.py` is the provenance audit. For each column it compares the global
area under the ROC curve with the area measured inside strata of fixed file
type, architecture, runtime and four-year era. A column whose power collapses
once the context is held fixed was separating contexts rather than classes.
On detection it flags 59 of the 18,421 columns that can be judged, and
removing them costs at most 0.006 MCC.

`figures_papier_en.py` regenerates every figure of the paper from the result
files, without re-running a single model.

### hpc

`setup_env.sh` and the `install_*.sh` scripts build the tool chain: capa
rules, Manalyze, Detect-It-Easy dependencies, FLOSS and the YARA rules. This
is usually what is missing from a repository and what prevents people from
reproducing anything.

---

## The three states

A field is `null` when the corresponding structure is absent from the binary,
and **never** when a measurement was skipped. A `null`, a measured zero and a
measured `false` are three distinct states, and conflating them invents
measurements that were never taken.

The entropy of a section a file does not have is not zero: it is undefined.
Of the 100,909 files, 95,143 have no `.edata` section, and their
`sec_edata_entropie` is `null`.

The same discipline governs the labels, which is why the number of evaluated
files differs from one task to another:

| Task | Label origin | Files |
|---|---|---|
| Detection | measured, reputation check | 100,909 |
| Packing | measured, vote of three detectors | 100,909 |
| Anti-analysis | measured, capa | 79,832 |
| Threat categories | inherited from the family | 60,275 |

A file whose label could not be established is withdrawn from that task
rather than counted as a negative.

## Columns withheld from model input

Two families of columns are released but must not be given to a model.
**Identifiers**, namely MD5, SHA-1, SHA-256, the import hash, TLSH and
ssdeep, designate the file itself and let a model memorise it. **Era
markers**, namely the compilation timestamp, the derived year and the linker
version, place the file in time, which under the out-of-time policy hands the
model the answer it is asked to produce.

These 182 columns exist because they are what builds the partitions and what
the provenance audit stratifies on. The matrix a model receives holds 18,489
columns.

## Credentials

No key is stored in this repository. Copy `.env.example` to `.env` and fill
it in; every script reads its credentials from the environment.

## Licensing

The data are released under **CC BY 4.0**, the code under the **MIT**
licence. Benign binaries are not redistributed, their licences being those of
their publishers.

## Ethics

Malicious samples were analysed on isolated storage and deleted immediately
after measurement. Only derived measurements and content hashes are released,
so a sample can be retrieved from its original repository by whoever is
entitled to it. The released features cannot be used to reconstruct an
executable.
