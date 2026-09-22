"""Combine every packing source into one label per sample.

Two kinds of source are merged here.

**Already in the dataset**, so always available:

    unpacme        MalwareBazaar's packing_label, from an actual unpacking attempt
    yara           the packer rulesets in advanced_yara_rules, calibrated below
    section_names  .UPX0, .themida, .vmp0 and friends, from sections_full
    heuristic      section entropy and import count, from sections_full and imports_api

**From external tools**, if run_packer_detectors.py has produced a summary.csv:

    diec  peid  manalyze  pypackerdetect  reminder  unipacker  capa

Three states, and who may assert which
--------------------------------------
A signature scanner that matches nothing has not shown the file is unpacked -- only that
it recognised nothing it knows. So each source declares whether its negative counts:

    source           packed   not_packed   why
    ------------------------------------------------------------------------------
    unpacme          yes      yes          it actually unpacked; an identical output
                                           is evidence, not silence
    pypackerdetect   yes      yes          heuristics cover every file
    reminder         yes      yes          entropy over the whole file
    heuristic        yes      yes          computed for every sample, with an
                                           abstention band in the middle
    yara             yes      no           signature database
    section_names    yes      no           signature-like
    diec/peid/       yes      no           signature databases
    manalyze/capa
    unipacker        yes      no           success proves packing, failure proves
                                           only that the packer is unsupported

Consensus: any positive wins; a negative counts only from a source entitled to give one;
everything else is unknown -- the state most pipelines wrongly record as unpacked.

YARA calibration
----------------
The PEiD-derived rulesets contain generic signatures that fire on ordinary compiled code.
Benign samples are used as a negative control: a rule matching more than
`YARA_MAX_BENIGN_RATE` of them is dropped. On this corpus that keeps 224 rules of 267 and
brings the benign false-positive rate to 0.1%.

Usage
    python build_packing_consensus.py
    python build_packing_consensus.py --tools results/packers/summary.csv
    python build_packing_consensus.py --root "E:/statique vf/Dataset_Static-85k"
"""

from collections import Counter, defaultdict
from pathlib import Path
import argparse
import csv
import re
import sys

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

PACKED, NOT_PACKED, UNKNOWN = "packed", "not_packed", "unknown"

# a rule firing on more than this share of benign samples is not trustworthy
YARA_MAX_BENIGN_RATE = 0.02
YARA_MIN_MATCHES = 10

# heuristic thresholds, with a deliberate gap between them: samples in the middle
# get "unknown" rather than a guess
HEUR_PACKED_ENTROPY, HEUR_PACKED_IMPORTS = 7.20, 15
HEUR_CLEAN_ENTROPY, HEUR_CLEAN_IMPORTS = 6.50, 50

PACKER_RULE = re.compile(
    r"upx|aspack|themida|vmprotect|petite|pecompact|nspack|mpress|enigma|armadillo|"
    r"molebox|obsidium|execryptor|pespin|yoda|fsg|^mew|packman|kkrunchy|rlpack|"
    r"winupack|exestealth|pepack|neolite|shrinker|telock|dxpack|expressor", re.I)

PACKER_SECTION = [
    (r"^\.?upx|^UPX", "upx"), (r"^\.themida|^\.winlice", "themida"),
    (r"^\.vmp", "vmprotect"), (r"^\.aspack|^\.adata$", "aspack"),
    (r"^\.mpress", "mpress"), (r"^\.nsp", "nspack"), (r"^\.enigma", "enigma"),
    (r"^mew", "mew"), (r"^\.petite", "petite"), (r"^pec[12]?$", "pecompact"),
    (r"^\.rlp", "rlpack"), (r"^kkrunchy", "kkrunchy"), (r"^\.perplex", "exestealth"),
]

# source -> may it assert not_packed
MAY_NEGATE = {
    "unpacme": True, "pypackerdetect": True, "reminder": True, "heuristic": True,
    "yara": False, "section_names": False, "diec": False, "peid": False,
    "manalyze": False, "capa": False, "unipacker": False,
}


def load_unpacme(root, ids):
    """packing_label comes from an unpacking attempt: unpacme_diff means the output
    differed, unpacme_same means it did not. Both are evidence; no_unpacme is not."""
    csv.field_size_limit(10 ** 9)
    lab, src = {}, {}
    path = root / "mb_info_with_malwarebazaar_tags.csv"
    if not path.exists():
        return pd.Series(UNKNOWN, index=ids), pd.Series("", index=ids)
    with path.open(newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            lab[r["sha256"]] = (r.get("packing_label") or "").strip()
            src[r["sha256"]] = (r.get("packing_source") or "").strip()
    verdict = pd.Series([{"packed": PACKED, "unpacked": NOT_PACKED}.get(lab.get(s, ""), UNKNOWN)
                         for s in ids], index=ids)
    reason = pd.Series([src.get(s, "") or "not submitted" for s in ids], index=ids)
    return verdict, reason


def load_yara(feat, ids, benign_ids):
    """Packer rules, after dropping the ones that fire on benign software."""
    path = feat / "advanced_yara_rules.parquet"
    if not path.exists():
        return pd.Series(UNKNOWN, index=ids), pd.Series("", index=ids), {}
    total, on_benign = Counter(), Counter()
    per = defaultdict(set)
    for b in pq.ParquetFile(path).iter_batches(columns=["sha256", "rule_name"],
                                               batch_size=500_000):
        f = b.to_pandas()
        f = f[f.rule_name.notna()]
        for sha, rn in zip(f.sha256.tolist(), f.rule_name.astype(str).tolist()):
            if not PACKER_RULE.search(rn):
                continue
            total[rn] += 1
            if sha in benign_ids:
                on_benign[rn] += 1
            per[sha].add(rn)
    clean = {r for r, n in total.items()
             if n >= YARA_MIN_MATCHES and on_benign[r] / n <= YARA_MAX_BENIGN_RATE}
    verdict, reason = [], []
    for s in ids:
        hit = sorted(per.get(s, set()) & clean)
        verdict.append(PACKED if hit else UNKNOWN)
        reason.append(" | ".join(hit[:3]) if hit else "no calibrated rule matched")
    stats = {"rules_seen": len(total), "rules_kept": len(clean),
             "benign_flagged": sum(1 for s in benign_ids if per.get(s, set()) & clean)}
    return pd.Series(verdict, index=ids), pd.Series(reason, index=ids), stats


def load_sections(feat, ids):
    """Packer section names, plus the entropy and import counts the heuristic needs."""
    path = feat / "sections_full.parquet"
    t = pq.read_table(path, columns=["sha256", "sections", "sec_entropy_max"])
    sha_l = t.column("sha256").to_pylist()
    sec_l = t.column("sections").to_pylist()
    ent_l = t.column("sec_entropy_max").to_pylist()
    names, entropy = {}, {}
    for sha, secs, ent in zip(sha_l, sec_l, ent_l):
        names[sha] = [str(e.get("name") or "").strip() for e in (secs or [])]
        entropy[sha] = float(ent or 0)

    verdict, reason = [], []
    for s in ids:
        nm = names.get(s, [])
        found = [p for rx, p in PACKER_SECTION if any(re.search(rx, n, re.I) for n in nm)]
        verdict.append(PACKED if found else UNKNOWN)
        reason.append(f"section names: {', '.join(found)}" if found
                      else "no packer section name")
    return (pd.Series(verdict, index=ids), pd.Series(reason, index=ids),
            pd.Series([entropy.get(s, 0.0) for s in ids], index=ids))


def load_import_counts(feat, ids):
    path = feat / "imports_api.parquet"
    counts = Counter()
    for b in pq.ParquetFile(path).iter_batches(columns=["sha256"], batch_size=500_000):
        counts.update(b.column("sha256").to_pylist())
    return pd.Series([counts.get(s, 0) for s in ids], index=ids)


def heuristic(entropy, imports):
    """High entropy with a stripped import table is the classic packing signature; low
    entropy with a full table is the classic absence of it. In between the heuristic
    abstains rather than guessing."""
    verdict, reason = [], []
    for e, n in zip(entropy.values, imports.values):
        if e >= HEUR_PACKED_ENTROPY and n < HEUR_PACKED_IMPORTS:
            verdict.append(PACKED)
            reason.append(f"entropy {e:.2f} with only {n} imports")
        elif e <= HEUR_CLEAN_ENTROPY and n >= HEUR_CLEAN_IMPORTS:
            verdict.append(NOT_PACKED)
            reason.append(f"entropy {e:.2f} with {n} imports")
        else:
            verdict.append(UNKNOWN)
            reason.append(f"entropy {e:.2f}, {n} imports -- between thresholds")
    return (pd.Series(verdict, index=entropy.index),
            pd.Series(reason, index=entropy.index))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default="", help="Dataset_Static-85k directory")
    ap.add_argument("--tools", default="", help="summary.csv from run_packer_detectors.py")
    ap.add_argument("--out", default="", help="output directory (default: <root>/../results)")
    args = ap.parse_args()

    root = Path(args.root) if args.root else None
    if root is None:
        for cand in [Path.cwd(), Path.cwd() / "Dataset_Static-85k",
                     Path(r"E:/statique vf/Dataset_Static-85k")]:
            if (cand / "improved_features").exists():
                root = cand
                break
    if root is None or not (root / "improved_features").exists():
        sys.exit("could not locate the dataset -- pass --root")
    feat = root / "improved_features"
    out_dir = Path(args.out) if args.out else root.parent / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    print("root:", root)

    labels = pd.read_csv(root / "sample_labels.csv", low_memory=False) \
               .drop_duplicates("sha256").set_index("sha256")
    ids = labels.index.tolist()
    benign_ids = set(labels[labels.binary_label.eq("benign")].index)
    print(f"{len(ids):,} samples ({len(benign_ids):,} benign, used as negative control)\n")

    d = pd.DataFrame(index=ids)
    d["binary_label"] = labels.binary_label
    d["family"] = labels.family_norm

    print("reading unpacme...", flush=True)
    d["unpacme"], d["unpacme_reason"] = load_unpacme(root, ids)

    print("reading yara...", flush=True)
    d["yara"], d["yara_reason"], ystats = load_yara(feat, ids, benign_ids)
    if ystats:
        print(f"  kept {ystats['rules_kept']} of {ystats['rules_seen']} packer rules; "
              f"{ystats['benign_flagged']:,} benign still flagged "
              f"({100 * ystats['benign_flagged'] / max(len(benign_ids), 1):.2f}%)")

    print("reading sections...", flush=True)
    d["section_names"], d["section_names_reason"], entropy = load_sections(feat, ids)

    print("reading imports...", flush=True)
    imports = load_import_counts(feat, ids)
    d["heuristic"], d["heuristic_reason"] = heuristic(entropy, imports)
    d["entropy_max"] = entropy
    d["n_imports"] = imports

    sources = ["unpacme", "yara", "section_names", "heuristic"]

    if args.tools and Path(args.tools).exists():
        print("reading tool results...", flush=True)
        tl = pd.read_csv(args.tools, low_memory=False)
        key = "file" if "file" in tl.columns else tl.columns[0]
        tl["sha256"] = tl[key].astype(str).str.replace(r"\.\w+$", "", regex=True)
        tl = tl.drop_duplicates("sha256").set_index("sha256")
        for t in ["diec", "peid", "manalyze", "pypackerdetect", "reminder",
                  "unipacker", "capa"]:
            if t in tl.columns:
                d[t] = tl[t].reindex(ids).fillna(UNKNOWN)
                rc = f"{t}_reason"
                d[rc] = tl[rc].reindex(ids).fillna("not run") if rc in tl.columns else "not run"
                sources.append(t)
        print(f"  merged {len(sources) - 4} tools on "
              f"{tl.index.isin(ids).sum():,} samples")
    elif args.tools:
        print(f"  {args.tools} not found -- dataset sources only")

    print(f"\nsources in play: {', '.join(sources)}\n")

    pos = pd.DataFrame({s: d[s].eq(PACKED) for s in sources})
    neg = pd.DataFrame({s: d[s].eq(NOT_PACKED) & MAY_NEGATE.get(s, False)
                        for s in sources})
    d["n_packed"] = pos.sum(axis=1)
    d["n_not_packed"] = neg.sum(axis=1)
    d["sources_packed"] = pos.apply(lambda r: ";".join(r.index[r.values]), axis=1)
    d["sources_not_packed"] = neg.apply(lambda r: ";".join(r.index[r.values]), axis=1)
    d["consensus"] = np.where(d.n_packed > 0, PACKED,
                              np.where(d.n_not_packed > 0, NOT_PACKED, UNKNOWN))
    d["confidence"] = np.where(d.n_packed >= 2, "high",
                               np.where(d.n_packed == 1, "low",
                                        np.where(d.n_not_packed >= 2, "high",
                                                 np.where(d.n_not_packed == 1, "low",
                                                          "none"))))
    d["evidence"] = [" || ".join(f"{s}={d[s].iat[i]}: {d.get(f'{s}_reason', pd.Series('', index=d.index)).iat[i]}"
                                 for s in sources) for i in range(len(d))]

    d = d.reset_index().rename(columns={"index": "sha256"})
    d.to_parquet(out_dir / "packing_consensus.parquet", index=False, compression="zstd")
    keep = (["sha256", "binary_label", "family", "consensus", "confidence",
             "n_packed", "n_not_packed", "sources_packed", "sources_not_packed",
             "entropy_max", "n_imports"] + sources
            + [f"{s}_reason" for s in sources if f"{s}_reason" in d.columns])
    d[keep].to_csv(out_dir / "packing_consensus.csv", index=False)

    mal = d[d.binary_label.eq("malicious")]
    print("consensus, malware only")
    print(pd.crosstab(mal.consensus, mal.confidence).to_string())
    print("\nagreement between sources (malware only, % of pairs that match)")
    m = pd.DataFrame({s: mal[s] for s in sources})
    agree = pd.DataFrame(index=sources, columns=sources, dtype=float)
    for a in sources:
        for b_ in sources:
            both = m[(m[a] != UNKNOWN) & (m[b_] != UNKNOWN)]
            agree.loc[a, b_] = round(100 * (both[a] == both[b_]).mean(), 1) if len(both) else np.nan
    print(agree.to_string())
    print(f"\nwrote {out_dir / 'packing_consensus.parquet'}")
    print(f"wrote {out_dir / 'packing_consensus.csv'}")


if __name__ == "__main__":
    main()
