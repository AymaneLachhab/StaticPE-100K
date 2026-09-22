"""Turn the raw results into one tidy row per sample, without throwing anything away.

The JSONL stays the source of truth -- every tool's verdict, reason and full report is
kept there, and nothing in this script is destructive. What it produces is the flat table
you actually model on:

    packing      the votes, the consensus, and which packer was named
    anti_vm      / anti_debug / anti_sandbox / obfuscation
    encryption   plus the conjunction that distinguishes ransomware from any program
                 that happens to use AES
    behaviour    capabilities, ATT&CK and MBC read from this binary, not inherited
                 from its family

Two design points worth keeping in mind when you use the output.

**Evidence and absence of evidence are different columns.** `anti_vm` is 1 when something
fired and 0 when nothing did -- but `capa_status` tells you whether capa ran at all. A
sample capa timed out on has anti_vm = 0 for the trivial reason that nothing could look.
Filter on `capa_ok` before drawing any conclusion about absence, or you will measure your
timeout rate and call it a property of malware.

**Long tables, not wide ones, for the vocabularies.** Capabilities, ATT&CK ids and YARA
rules are open sets, so they go into companion long tables -- one row per (sample, item) --
which is the same shape as imports_api.parquet and drops straight into your existing
feature pipeline.

Usage
    python build_sample_table.py --results results/calib/results.jsonl.gz --out results/calib
    python build_sample_table.py --results ... --truth hashes/calibration_truth.csv
"""

from collections import Counter
from pathlib import Path
import argparse
import csv
import gzip
import json
import re
import zlib

# Which YARA themes and capa namespaces answer which question. Kept explicit rather than
# inferred, because "packers" in the Yara-Rules collection is not homogeneous: peid.yar
# is a compiler-identification database and fires on ordinary binaries.
PACKER_NAME = re.compile(
    r"upx|aspack|asprotect|themida|winlicense|vmprotect|petite|pecompact|nspack|mpress|"
    r"enigma|armadillo|molebox|obsidium|execryptor|pespin|yoda|fsg|mew|packman|kkrunchy|"
    r"rlpack|winupack|exestealth|neolite|shrinker|telock|acprotect|stelth|nspack|upack",
    re.I)
COMPILER_NAME = re.compile(
    r"microsoft_visual|borland|delphi|mingw|watcom|lcc|masm|tasm|dotnet|net_executable|"
    r"visual_c|visual_basic|autoit|installshield|nullsoft|inno", re.I)


def read_records(path):
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except (EOFError, OSError, zlib.error):
        return


def yara_rules(rec, theme):
    return ((rec.get("yara") or {}).get("by_theme") or {}).get(theme, [])


def flatten(rec, truth):
    tools = rec.get("tools") or {}
    capa = rec.get("capa_report") or {}
    yara = rec.get("yara") or {}
    caps = capa.get("capabilities") or []
    ns = capa.get("namespaces") or []
    caps_text = " ".join(caps).lower()
    ns_text = " ".join(ns).lower()

    # packer names, taken from whichever tool actually named one
    named = []
    for tool in ("diec", "peid", "manalyze", "pypackerdetect"):
        e = tools.get(tool) or {}
        if e.get("answer") == "yes":
            for m in PACKER_NAME.findall(str(e.get("reason") or "")):
                named.append(m.lower())
    # YARA packer rules, minus the compiler-identification ones that fire on every binary
    yara_packer = [r for r in yara_rules(rec, "packers")
                   if PACKER_NAME.search(r) and not COMPILER_NAME.search(r)]
    named += [m.lower() for r in yara_packer for m in PACKER_NAME.findall(r)]

    row = {
        "md5": rec.get("md5"),
        "status": rec.get("status"),
        "size": rec.get("size"),
        "label_source": truth.get(rec.get("md5"), ""),      # unpacme, when known
    }

    # ---- packing --------------------------------------------------------------------
    for tool in ("pypackerdetect", "peid", "manalyze", "diec", "capa"):
        e = tools.get(tool)
        row[f"pack_{tool}"] = e.get("answer") if e else ""
    row["pack_yes"] = rec.get("yes")
    row["pack_no"] = rec.get("no")
    row["pack_errors"] = rec.get("errors")
    row["pack_verdict"] = rec.get("verdict")
    row["pack_yara_rules"] = len(yara_packer)
    row["packer_named"] = ";".join(sorted(set(named)))
    row["capa_packer_ns"] = ";".join(capa.get("packer_namespaces") or [])

    # ---- anti-analysis --------------------------------------------------------------
    av = yara_rules(rec, "antidebug_antivm")
    row["anti_vm"] = int(bool([r for r in av if re.search(r"vm|virtual|sandbox|sbie", r, re.I)])
                         or "anti-vm" in ns_text or "anti-emulation" in ns_text)
    row["anti_debug"] = int(bool([r for r in av if re.search(r"dbg|debug|seh|threadcontrol", r, re.I)])
                            or "anti-debugging" in ns_text)
    row["anti_sandbox"] = int(bool([r for r in av if re.search(r"sandbox|sbie|threatexpert|cuckoo", r, re.I)])
                              or "anti-emulation" in ns_text)
    row["obfuscation"] = int("obfuscation" in ns_text
                             or bool(re.search(r"obfusc|encoded", caps_text)))
    row["anti_rules"] = ";".join(sorted(av))
    row["n_anti_rules"] = len(av)

    # ---- encryption / ransomware ----------------------------------------------------
    row["yara_crypto"] = (yara.get("n_by_theme") or {}).get("crypto", 0)
    row["capa_encryption"] = int("encryption" in ns_text)
    row["enumerates_files"] = int("enumerate files" in caps_text)
    row["deletes_shadow_copies"] = int("shadow" in caps_text or "vssadmin" in caps_text)
    # encryption alone means nothing -- plenty of benign software encrypts. The pattern
    # that characterises ransomware is encryption together with walking the filesystem
    # and destroying the means of recovery.
    row["ransomware_pattern"] = int(row["capa_encryption"] and
                                    (row["enumerates_files"] or row["deletes_shadow_copies"]))

    # ---- behaviour ------------------------------------------------------------------
    row["capa_status"] = capa.get("status", "")
    row["capa_mode"] = capa.get("mode", "")
    row["capa_ok"] = int(capa.get("status") == "ok")
    row["capa_has_attack"] = int(bool(capa.get("attack")))
    row["n_capabilities"] = capa.get("n_capabilities") or 0
    row["capa_seconds"] = capa.get("seconds")
    row["attack"] = ";".join(capa.get("attack") or [])
    row["mbc"] = ";".join(capa.get("mbc") or [])
    row["capa_namespaces"] = ";".join(sorted(set(ns)))

    # ---- FLOSS, when a second pass has added it -------------------------------------
    floss = rec.get("floss") or {}
    row["floss_status"] = floss.get("status", "")
    row["n_decoded_strings"] = floss.get("n_decoded", "")
    row["floss_vm_artifacts"] = ";".join(floss.get("vm_artifacts") or [])
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", required=True)
    ap.add_argument("--truth", default="", help="calibration_truth.csv, if it applies")
    ap.add_argument("--out", default="results/tables")
    args = ap.parse_args()

    truth = {}
    if args.truth and Path(args.truth).exists():
        with open(args.truth, encoding="utf-8") as fh:
            truth = {r["md5"]: r["label"] for r in csv.DictReader(fh)}

    rows, long_caps, long_attack, long_yara = [], [], [], []
    for rec in read_records(args.results):
        rows.append(flatten(rec, truth))
        md5 = rec.get("md5")
        capa = rec.get("capa_report") or {}
        for cap in capa.get("capabilities") or []:
            long_caps.append({"md5": md5, "capability": cap})
        for a in capa.get("attack") or []:
            long_attack.append({"md5": md5, "attack": a})
        for theme, names in ((rec.get("yara") or {}).get("by_theme") or {}).items():
            for name in names:
                long_yara.append({"md5": md5, "theme": theme, "rule": name})

    if not rows:
        raise SystemExit("no record read")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    def write(name, data):
        if not data:
            return
        path = out / f"{name}.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(data[0].keys()))
            w.writeheader()
            w.writerows(data)
        print(f"wrote {path}  ({len(data):,} rows)")
        try:
            import pandas as pd
            pd.DataFrame(data).to_parquet(out / f"{name}.parquet", index=False)
            print(f"wrote {out / (name + '.parquet')}")
        except Exception:
            pass

    write("samples", rows)
    write("long_capabilities", long_caps)
    write("long_attack", long_attack)
    write("long_yara", long_yara)

    ok = [r for r in rows if r["status"] == "ok"]
    print(f"\nsamples analysed        : {len(ok):,} / {len(rows):,}")
    print(f"capa produced a report  : {sum(r['capa_ok'] for r in ok):,}"
          f"   <-- absence columns are only meaningful on these")
    for col in ("anti_vm", "anti_debug", "anti_sandbox", "obfuscation",
                "capa_encryption", "ransomware_pattern"):
        n = sum(r[col] for r in ok)
        print(f"  {col:<22} {n:>6,}  ({n / max(len(ok), 1):.1%})")
    named = Counter(p for r in ok for p in r["packer_named"].split(";") if p)
    print("\ntop named packers:")
    for name, n in named.most_common(10):
        print(f"  {n:>5,}  {name}")


if __name__ == "__main__":
    main()
