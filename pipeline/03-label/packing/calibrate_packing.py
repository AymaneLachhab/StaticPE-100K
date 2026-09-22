"""Score every plausible packing-consensus rule against a known answer key.

The question this settles is the one raised in review: how many detectors must agree
before a sample is called packed? Answering it by argument produces an opinion; answering
it here produces a precision/recall table measured on samples whose label was fixed
independently, by unpacme, before any of these tools ran.

Two things are measured, and the second matters as much as the first.

1. **Per rule: precision and recall.** A rule is a decision function over the votes --
   "at least one signature tool said yes", "a signature tool and a structural tool both
   said yes", "all of them said yes". Reading the table tells you what each threshold
   costs, instead of assuming.

2. **Between tools: agreement.** Four detectors voting is not four opinions if three of
   them consult the same signature database. The pairwise agreement matrix shows how much
   independent evidence the consensus actually rests on -- and a pair agreeing above ~95%
   is one detector with two names, however the vote is counted.

Positive class is `packed` throughout, so:

    precision = of the samples we called packed, how many really were
    recall    = of the really packed samples, how many we caught

Usage
    python calibrate_packing.py --results results/calib/results.jsonl.gz \\
        --truth hashes/calibration_truth.csv --out results/calib
"""

from pathlib import Path
import argparse
import csv
import gzip
import itertools
import json
import sys
import zlib

# How each detector decides. Three consult a signature corpus and name the packer; two
# measure the file itself. Only the second kind can flag a packer nobody has catalogued,
# and only the second kind's "no" carries information.
FAMILY = {"diec": "signature", "peid": "signature", "capa": "signature",
          "pypackerdetect": "structural", "manalyze": "structural",
          "reminder": "structural",
          # the YARA packers theme is a machine conversion of the PEiD database, so it
          # belongs to the signature family and is expected to agree with peid almost
          # perfectly -- the agreement matrix is what will confirm or refute that
          "yara_packers": "signature",
          # peid.yar is the PEiD database converted to YARA rules, so it is expected to
          # agree with the peid tool almost perfectly; packer.yar is a separate corpus.
          # The agreement matrix is what confirms or refutes that expectation
          "yara_peid": "signature", "yara_packer": "signature"}


def load_truth(path):
    truth = {}
    with Path(path).open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            truth[row["md5"].strip().lower()] = row["label"].strip()
    return truth


def load_results(path):
    """One record per sample, keyed by md5. A later line wins, so a re-run overrides.

    The file is read tolerantly on purpose: it is normally still being appended to, and
    a gzip member that the writer has not finished raises EOFError. Everything written
    before that point is valid and is kept, so the calibration can be scored on partial
    results while the run continues.
    """
    out = {}
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("md5"):
                    out[rec["md5"]] = rec
    except (EOFError, OSError, zlib.error) as exc:
        print(f"note: the results file ends mid-record ({type(exc).__name__}); "
              f"scoring the {len(out):,} complete records")
    return out


def votes_of(rec):
    """{tool: True/False/None} plus the YARA packer hit, if the rule set was run.

    YARA's `packers` theme is included as a vote but flagged, because it is a machine
    conversion of the PEiD signature database: it belongs with peid, not beside it.
    """
    v = {t: {"yes": True, "no": False}.get(e.get("answer"))
         for t, e in (rec.get("tools") or {}).items()}
    yara = rec.get("yara") or {}
    # by file when available, because the `packers` theme is three unrelated things:
    # peid.yar is the PEiD database converted to rules, packer.yar mixes real packer
    # rules with malware-family rules, and the JavaScript files are irrelevant to a PE
    by_file = yara.get("n_by_file") or {}
    if by_file:
        if "peid.yar" in by_file or yara.get("status") == "ok":
            v["yara_peid"] = by_file.get("peid.yar", 0) > 0
            v["yara_packer"] = by_file.get("packer.yar", 0) > 0
    else:
        n_pack = (yara.get("n_by_theme") or {}).get("packers")
        if n_pack is not None:
            v["yara_packers"] = n_pack > 0
    return v


def rules_table():
    """The decision functions worth comparing, as (name, description, fn)."""

    def counts(v):
        sig = sum(1 for t, a in v.items() if a is True and FAMILY.get(t) == "signature")
        struct = sum(1 for t, a in v.items() if a is True and FAMILY.get(t) == "structural")
        yes = sum(1 for a in v.values() if a is True)
        answered = sum(1 for a in v.values() if a is not None)
        return sig, struct, yes, answered

    R = []
    R.append(("any tool >= 1", "the BenchMFC CUFI rule: unpacked only if nothing fires",
              lambda v: counts(v)[2] >= 1))
    R.append(("any tool >= 2", "two detectors of any kind",
              lambda v: counts(v)[2] >= 2))
    R.append(("any tool >= 3", "three detectors of any kind",
              lambda v: counts(v)[2] >= 3))
    R.append(("unanimity", "every tool that answered said yes",
              lambda v: counts(v)[3] > 0 and counts(v)[2] == counts(v)[3]))
    R.append(("signature >= 1", "one named-packer identification is enough",
              lambda v: counts(v)[0] >= 1))
    R.append(("signature >= 2", "two independent signature corpora",
              lambda v: counts(v)[0] >= 2))
    R.append(("structural >= 1", "structure alone, no signature needed",
              lambda v: counts(v)[1] >= 1))
    R.append(("structural >= 2", "both structural detectors",
              lambda v: counts(v)[1] >= 2))
    R.append(("sig >= 1 AND struct >= 1", "two different methods converge",
              lambda v: counts(v)[0] >= 1 and counts(v)[1] >= 1))
    R.append(("sig >= 1 OR struct >= 2", "a name, or two structural opinions",
              lambda v: counts(v)[0] >= 1 or counts(v)[1] >= 2))
    return R


def score(pred, truth_label):
    tp = sum(1 for m, p in pred.items() if p and truth_label[m] == "packed")
    fp = sum(1 for m, p in pred.items() if p and truth_label[m] == "unpacked")
    fn = sum(1 for m, p in pred.items() if not p and truth_label[m] == "packed")
    tn = sum(1 for m, p in pred.items() if not p and truth_label[m] == "unpacked")
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return tp, fp, fn, tn, prec, rec, f1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", required=True, help="results.jsonl.gz from the run")
    ap.add_argument("--truth", required=True, help="calibration_truth.csv")
    ap.add_argument("--out", default="results/calib")
    args = ap.parse_args()

    truth = load_truth(args.truth)
    results = load_results(args.results)
    common = [m for m in results if m in truth and results[m].get("status") == "ok"]
    if not common:
        sys.exit("no sample is both in the results and in the answer key")

    label = {m: truth[m] for m in common}
    n_pack = sum(1 for m in common if label[m] == "packed")
    print(f"scored on {len(common):,} samples "
          f"({n_pack:,} packed, {len(common) - n_pack:,} unpacked)")
    missing = len(truth) - len(common)
    if missing:
        # never quietly: a calibration that lost most of one class would report a
        # precision that means nothing
        got = {"packed": 0, "unpacked": 0}
        for m in common:
            got[label[m]] += 1
        want = {"packed": 0, "unpacked": 0}
        for m, lab in truth.items():
            want[lab] += 1
        print(f"not scored: {missing:,} "
              f"(packed {want['packed'] - got['packed']:,}, "
              f"unpacked {want['unpacked'] - got['unpacked']:,}) "
              f"-- download failed, or the tools errored")

    all_votes = {m: votes_of(results[m]) for m in common}
    tools = sorted({t for v in all_votes.values() for t in v})
    print(f"detectors  : {', '.join(tools)}\n")

    # ---- per rule ---------------------------------------------------------------
    rows = []
    print(f"{'rule':<26}{'prec':>8}{'recall':>8}{'F1':>8}{'TP':>7}{'FP':>7}{'FN':>7}")
    print("-" * 71)
    for name, desc, fn in rules_table():
        pred = {m: bool(fn(all_votes[m])) for m in common}
        tp, fp, fnc, tn, prec, rec, f1 = score(pred, label)
        rows.append((name, desc, tp, fp, fnc, tn, round(prec, 4), round(rec, 4), round(f1, 4)))
        print(f"{name:<26}{prec:>8.3f}{rec:>8.3f}{f1:>8.3f}{tp:>7,}{fp:>7,}{fnc:>7,}")

    # ---- each tool on its own ---------------------------------------------------
    print(f"\n{'tool alone':<26}{'prec':>8}{'recall':>8}{'F1':>8}{'TP':>7}{'FP':>7}"
          f"{'FN':>7}{'errors':>8}")
    print("-" * 79)
    for t in tools:
        pred = {m: all_votes[m].get(t) is True for m in common}
        errs = sum(1 for m in common if all_votes[m].get(t) is None)
        tp, fp, fnc, tn, prec, rec, f1 = score(pred, label)
        rows.append((f"tool: {t}", FAMILY.get(t, "?"), tp, fp, fnc, tn,
                     round(prec, 4), round(rec, 4), round(f1, 4)))
        print(f"{t:<26}{prec:>8.3f}{rec:>8.3f}{f1:>8.3f}{tp:>7,}{fp:>7,}{fnc:>7,}{errs:>8,}")

    # ---- how independent are they really ----------------------------------------
    print("\npairwise agreement (share of samples where both gave the same answer)")
    print("above ~0.95 means the pair is one detector wearing two hats\n")
    pair_rows = []
    for a, b in itertools.combinations(tools, 2):
        both = [m for m in common
                if all_votes[m].get(a) is not None and all_votes[m].get(b) is not None]
        if not both:
            continue
        same = sum(1 for m in both if all_votes[m][a] == all_votes[m][b])
        agree = same / len(both)
        pair_rows.append((a, b, len(both), round(agree, 4),
                          FAMILY.get(a, "?"), FAMILY.get(b, "?")))
    for a, b, n, agree, fa, fb in sorted(pair_rows, key=lambda r: -r[3]):
        flag = "   <-- redundant" if agree >= 0.95 else ""
        print(f"  {a:<16} {b:<16} {agree:>6.3f}  n={n:>5,}  ({fa}/{fb}){flag}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "calibration_rules.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rule", "description", "tp", "fp", "fn", "tn",
                    "precision", "recall", "f1"])
        w.writerows(rows)
    with (out / "calibration_agreement.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tool_a", "tool_b", "n", "agreement", "family_a", "family_b"])
        w.writerows(pair_rows)
    print(f"\nwrote {out / 'calibration_rules.csv'}")
    print(f"wrote {out / 'calibration_agreement.csv'}")


if __name__ == "__main__":
    main()
