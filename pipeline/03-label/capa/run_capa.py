"""Run capa over a directory of PE files and keep everything it produces.

Nothing is discarded. capa's full JSON report is written verbatim to a gzipped JSONL,
one line per sample, so any field this script does not parse today can still be read
later without re-running the analysis -- which matters, because capa is the slowest step
in the pipeline at roughly a second per file.

Three outputs, in increasing order of convenience and decreasing order of completeness:

    capa_full.jsonl.gz   the untouched report for every sample
    capa_long.parquet    one row per (sha256, capability), matching the shape of
                         imports_api.parquet so it drops straight into the existing
                         feature pipeline
    capa_index.parquet   one row per sample: counts, the analysis metadata capa
                         reports, and the semicolon-joined label sets

Why the long table is the useful one. A capa capability is a per-sample observation of
what the code does, read from its disassembly. That is a different kind of label from the
behaviour tags derived from a family table, where every Dridex sample carries the same
four behaviours whether or not that particular binary implements them. Feeding the long
table through the same vocabulary machinery as imports gives behaviour labels that
describe the file rather than its relatives.

Install
    pip install flare-capa
    capa --version

Usage
    python run_capa.py --input DIR_OF_BINARIES --out results/capa
    python run_capa.py --input DIR --hashes hashes/sample_20.txt --workers 8
    python run_capa.py --input DIR --workers 16 --timeout 300
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import argparse
import gzip
import json
import shutil
import subprocess
import sys
import time


def run_capa(path, timeout, extra_args):
    """Return capa's parsed report, or a record describing why it failed."""
    cmd = ["capa", "-j", *extra_args, str(path)]
    started = time.perf_counter()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"_status": "timeout", "_seconds": timeout}
    except Exception as exc:
        return {"_status": "error", "_error": str(exc)}
    seconds = round(time.perf_counter() - started, 2)
    if not (p.stdout or "").strip():
        # capa exits non-zero on unsupported formats and on files it cannot disassemble
        return {"_status": "empty", "_seconds": seconds,
                "_returncode": p.returncode, "_stderr": (p.stderr or "")[:4000]}
    try:
        data = json.loads(p.stdout)
    except Exception as exc:
        return {"_status": "unparsable", "_seconds": seconds,
                "_error": str(exc), "_stdout": p.stdout[:8000]}
    data["_status"] = "ok"
    data["_seconds"] = seconds
    return data


def flatten(sha, report):
    """Split one report into an index row and one row per capability."""
    meta = report.get("meta") or {}
    analysis = meta.get("analysis") or {}
    sample = meta.get("sample") or {}
    index = {
        "sha256": sha,
        "status": report.get("_status", "ok"),
        "seconds": report.get("_seconds"),
        "capa_version": (meta.get("version") or ""),
        "format": analysis.get("format") or "",
        "arch": analysis.get("arch") or "",
        "os": analysis.get("os") or "",
        "extractor": analysis.get("extractor") or "",
        "base_address": str((analysis.get("base_address") or {}).get("value", "")),
        "n_functions": len((analysis.get("feature_counts") or {}).get("functions") or []),
        "sample_md5": sample.get("md5") or "",
        "sample_sha1": sample.get("sha1") or "",
    }

    rows, caps, namespaces, attack, mbc = [], [], set(), set(), set()
    for rule_name, v in (report.get("rules") or {}).items():
        rmeta = v.get("meta") or {}
        name = rmeta.get("name") or rule_name
        ns = rmeta.get("namespace") or ""
        lib = bool(rmeta.get("lib"))
        scopes = rmeta.get("scopes") or {}
        # how many places in the binary matched -- a rough strength signal
        n_matches = len(v.get("matches") or [])

        att_ids, att_labels = [], []
        for a in rmeta.get("attack") or []:
            if a.get("id"):
                att_ids.append(a["id"])
            lab = "::".join(x for x in [a.get("tactic"), a.get("technique"),
                                        a.get("subtechnique")] if x)
            if lab:
                att_labels.append(lab)
        mbc_ids, mbc_labels = [], []
        for b in rmeta.get("mbc") or []:
            if b.get("id"):
                mbc_ids.append(b["id"])
            lab = "::".join(x for x in [b.get("objective"), b.get("behavior"),
                                        b.get("method")] if x)
            if lab:
                mbc_labels.append(lab)

        rows.append({
            "sha256": sha, "capability": name, "namespace": ns,
            "top_namespace": ns.split("/")[0] if ns else "",
            "is_lib": int(lib), "n_matches": n_matches,
            "scope_static": (scopes.get("static") or ""),
            "scope_dynamic": (scopes.get("dynamic") or ""),
            "attack_ids": ";".join(att_ids), "attack": ";".join(att_labels),
            "mbc_ids": ";".join(mbc_ids), "mbc": ";".join(mbc_labels),
            "references": ";".join(rmeta.get("references") or []),
            "authors": ";".join(rmeta.get("authors") or []),
        })
        if not lib:                       # library rules describe the compiler, not intent
            caps.append(name)
            if ns:
                namespaces.add(ns)
            attack.update(att_ids)
            mbc.update(mbc_ids)

    index.update({
        "n_rules_matched": len(rows),
        "n_capabilities": len(caps),
        "capabilities": ";".join(sorted(set(caps))),
        "namespaces": ";".join(sorted(namespaces)),
        "attack_ids": ";".join(sorted(attack)),
        "mbc_ids": ";".join(sorted(mbc)),
        "has_packer_namespace": int(any("packer" in n.lower() for n in namespaces)),
        "has_anti_analysis": int(any(n.lower().startswith("anti-analysis")
                                     for n in namespaces)),
    })
    return index, rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, help="directory holding the PE files")
    ap.add_argument("--out", default="results/capa")
    ap.add_argument("--hashes", default="", help="restrict to names listed in this file")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=300, help="seconds per sample")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--capa-args", default="",
                    help="extra flags passed through, e.g. '--backend vivisect'")
    args = ap.parse_args()

    if not shutil.which("capa"):
        sys.exit("capa is not on PATH -- pip install flare-capa")
    extra = args.capa_args.split() if args.capa_args else []

    out_dir = Path(args.out); out_dir.mkdir(parents=True, exist_ok=True)
    full_path = out_dir / "capa_full.jsonl.gz"

    done = set()
    if full_path.exists():
        with gzip.open(full_path, "rt", encoding="utf-8") as fh:
            for line in fh:
                try:
                    done.add(json.loads(line)["_sha256"])
                except Exception:
                    pass
        print(f"resuming: {len(done):,} samples already analysed")

    files = sorted(p for p in Path(args.input).iterdir() if p.is_file())
    if args.hashes:
        keep = {l.strip() for l in Path(args.hashes).read_text().splitlines() if l.strip()}
        files = [p for p in files if p.name in keep or p.stem in keep]
    files = [p for p in files if p.stem not in done and p.name not in done]
    if args.limit:
        files = files[:args.limit]
    print(f"to process: {len(files):,}  |  workers {args.workers}  |  "
          f"timeout {args.timeout}s\n")
    if not files:
        print("nothing to do")
        return

    index_rows, long_rows = [], []
    tally = {}
    t0 = time.perf_counter()
    with gzip.open(full_path, "at", encoding="utf-8") as full, \
         ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(run_capa, p, args.timeout, extra): p for p in files}
        for i, fut in enumerate(as_completed(futures), 1):
            path = futures[fut]
            sha = path.stem
            try:
                report = fut.result()
            except Exception as exc:
                report = {"_status": "error", "_error": str(exc)}
            report["_sha256"] = sha
            report["_file"] = path.name
            # the untouched report, so nothing this script fails to parse is lost
            full.write(json.dumps(report, ensure_ascii=False) + "\n")
            full.flush()

            idx, rows = flatten(sha, report)
            index_rows.append(idx)
            long_rows.extend(rows)
            tally[idx["status"]] = tally.get(idx["status"], 0) + 1

            if i % 25 == 0 or i == len(files):
                rate = i / max(time.perf_counter() - t0, 1e-9)
                left = (len(files) - i) / max(rate, 1e-9) / 60
                state = "  ".join(f"{k} {v:,}" for k, v in sorted(tally.items()))
                print(f"  {i:>7,}/{len(files):,}  {state}  "
                      f"{rate:.2f}/s  ~{left:.0f} min left", flush=True)

    import pandas as pd
    idx_df = pd.DataFrame(index_rows)
    long_df = pd.DataFrame(long_rows)
    idx_df.to_parquet(out_dir / "capa_index.parquet", index=False, compression="zstd")
    if len(long_df):
        long_df.to_parquet(out_dir / "capa_long.parquet", index=False, compression="zstd")

    print(f"\nwrote {full_path}")
    print(f"wrote {out_dir / 'capa_index.parquet'}  ({len(idx_df):,} rows)")
    print(f"wrote {out_dir / 'capa_long.parquet'}   ({len(long_df):,} rows)")
    ok = idx_df[idx_df.status.eq("ok")]
    if len(ok):
        print(f"\nanalysed successfully : {len(ok):,} / {len(idx_df):,}")
        print(f"distinct capabilities : {long_df.capability.nunique():,}")
        print(f"distinct ATT&CK ids   : "
              f"{long_df.attack_ids.str.split(';').explode().replace('', None).nunique():,}")
        print(f"mean capabilities/sample : {ok.n_capabilities.mean():.1f}")
    print(f"total {(time.perf_counter() - t0) / 60:.1f} min")


if __name__ == "__main__":
    main()
