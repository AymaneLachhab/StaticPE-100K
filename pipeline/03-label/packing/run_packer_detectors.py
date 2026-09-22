"""Run several static packer detectors over a directory of PE files.

Why several tools, and why three states rather than two
-------------------------------------------------------
BenchMFC (Computers & Security 2024) reports that PEiD and DIE together reach 99.50%
recall but only 81.90% precision against ground truth, and that signature-based
detection misses an unknown share of packed samples outright. One tool is not enough.

More importantly, the tools do not answer the same question. A signature scanner that
finds nothing has not established that the file is unpacked -- only that it recognised
no packer it knows about. Recording that as "not packed" is the mistake this script
exists to avoid, so every verdict is one of three states:

    packed      a packer was named, or a whole-file heuristic fired
    not_packed  a tool whose heuristic covers every file says no
    unknown     no signature matched, or the tool could not answer

What each tool can assert, and on what basis
--------------------------------------------
    tool             result                              meaning              negative?
    ---------------------------------------------------------------------------------
    diec             "Packer: UPX 3.x" / "Protector:"    packed               no
    diec             no Packer or Protector line         no known packer      no
    pypackerdetect   packed, with reasons: known          packed / suspected   yes
                     sections, few imports, odd EP
    pypackerdetect   not-packed verdict                  no packing detected  yes
    manalyze         "appears to be packed" + reasons    suspected packed     no
    manalyze         PEiD signature: UPX / ASPack        packed               no
    reminder         packed                              entropy heuristic    yes
    reminder         not packed                          heuristic says no    yes
    peid             packer name / signature             packed               no
    peid             no signature                        unknown              no
    unipacker        produced an unpacked file           confirmed packed     no
    unipacker        unpacking failed                    packer unsupported   no
    capa             packer namespace matched            packed               no

Only pypackerdetect and reminder examine every file, so only their negatives count.
Consensus follows: any positive settles it; a negative is credible only from a tool
entitled to give one; everything else stays unknown.

Three columns per tool
----------------------
    <tool>           the verdict
    <tool>_reason    the evidence, in one readable line: the packer name, the structural
                     reasons, the entropy figure -- whatever the tool based itself on
    <tool>_raw       its untouched output, so a wrong reading can be re-parsed from
                     results.jsonl instead of re-running the analysis

Install
    pip install pypackerdetect reminder-detector peid flare-capa unipacker
    DIE      github.com/horsicq/Detect-It-Easy   (build, put diec on PATH)
    Manalyze github.com/JusticeRage/Manalyze     (build, put manalyze on PATH)

Usage
    python run_packer_detectors.py --input DIR_OF_BINARIES --out results/packers
    python run_packer_detectors.py --input DIR --hashes hashes/sample_20.txt
    python run_packer_detectors.py --input DIR --tools diec,peid,reminder --workers 8
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time

PACKED, NOT_PACKED, UNKNOWN = "packed", "not_packed", "unknown"
TIMEOUT = 120
SLOW_FACTOR = 4                     # capa and unipacker need longer

PACKER_NAME = re.compile(
    r"upx|aspack|themida|vmprotect|petite|pecompact|nspack|mpress|enigma|armadillo|"
    r"molebox|obsidium|execryptor|pespin|yoda|fsg|packman|kkrunchy|rlpack|winupack|"
    r"exestealth|neolite|shrinker|telock|dxpack|expressor|confuser|netreactor|"
    r"pklite|mew|beropacker|packer|protector|crypter", re.I)

# phrases pypackerdetect and manalyze use to justify a positive
REASON_HINTS = re.compile(
    r"(known packer section[^\n.;]*|packer section[^\n.;]*|"
    r"(?:few|low number of|no) imports?[^\n.;]*|import table[^\n.;]*|"
    r"entry ?point[^\n.;]*|entropy[^\n.;]*|"
    r"unusual[^\n.;]*|suspicious[^\n.;]*|non-?standard[^\n.;]*|"
    r"self-?modif[^\n.;]*|appears to be packed[^\n.;]*|packed or obfuscated[^\n.;]*)",
    re.I)


def _run(cmd, timeout=TIMEOUT):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as exc:
        return f"[error] {exc}"


def _dead(out):
    return out.startswith(("[timeout]", "[error]"))


def _reasons(text, limit=4):
    """Collect the justification phrases a tool prints, deduplicated and trimmed."""
    seen, out = set(), []
    for m in REASON_HINTS.findall(text or ""):
        r = " ".join(m.split())[:120]
        k = r.lower()
        if k not in seen:
            seen.add(k)
            out.append(r)
        if len(out) >= limit:
            break
    return " | ".join(out)


def _names(text, limit=4):
    """Collect the packer names a tool mentions."""
    seen, out = set(), []
    for m in PACKER_NAME.finditer(text or ""):
        start = max(0, m.start() - 24)
        frag = " ".join((text[start:m.end() + 24]).split())
        k = m.group(0).lower()
        if k not in seen:
            seen.add(k)
            out.append(frag[:80])
        if len(out) >= limit:
            break
    return " | ".join(out)


# ---------------------------------------------------------------------------
# Signature scanners: a hit means packed, a miss means unknown.
# ---------------------------------------------------------------------------

def tool_diec(path):
    """Detect It Easy. A Packer or Protector entry means packed; its absence means no
    known signature matched, which is not the same as unpacked."""
    out = _run(["diec", "--json", str(path)])
    if _dead(out):
        return UNKNOWN, "tool did not answer", out
    try:
        data = json.loads(out)
    except Exception:
        # the docker wrapper and plain diec print a flat listing instead:
        #     PE32
        #         Compiler: Borland Delphi
        #         Packer: UPX(3.08)[LZMA, brute]
        lines = re.findall(r"^\s*(Packer|Protector)\s*:\s*(.+)$", out, re.I | re.M)
        if lines:
            return PACKED, " | ".join(f"{k}: {v.strip()}" for k, v in lines[:4]), out
        return UNKNOWN, "no packer or protector line", out
    named = []
    for d in data.get("detects", []):
        for v in d.get("values", []):
            kind = (v.get("type") or "").lower()
            if kind in ("packer", "protector"):
                named.append(f"{kind.capitalize()}: "
                             f"{v.get('name','')} {v.get('version','')}".strip())
    detail = json.dumps({"packers": named, "raw": data})
    if named:
        return PACKED, " | ".join(named[:4]), detail
    return UNKNOWN, "no packer or protector line", detail


def tool_peid(path):
    """PEiD signature database. A signature name means packed; 'no signature' means the
    database did not recognise it."""
    out = _run(["peid", str(path)])
    if _dead(out):
        return UNKNOWN, "tool did not answer", out
    if re.search(r"no\s+signature|nothing\s+(found|matched)", out, re.I):
        return UNKNOWN, "no signature matched", out
    if out.strip() and PACKER_NAME.search(out):
        return PACKED, f"signature: {_peid_lines(out)}", out
    return UNKNOWN, "no signature matched", out


def _peid_lines(text, limit=5):
    """PEiD prints one signature per line and repeats variants of the same packer:

        UPX
        UPX (LZMA) ASL sign
        UPX (LZMA)

    so the lines are deduplicated rather than concatenated.
    """
    seen, out = set(), []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        if line.lower() not in seen:
            seen.add(line.lower())
            out.append(line[:80])
        if len(out) >= limit:
            break
    return " | ".join(out)


def tool_manalyze(path):
    """Manalyze packer + peid plugins: a PEiD signature, or structural reasons such as
    unusual section names, a tiny import table, or an entry point outside .text."""
    out = _run(["manalyze", "--plugins=packer,peid", "--output=json", str(path)])
    if _dead(out):
        return UNKNOWN, "tool did not answer", out
    try:
        blob = json.dumps(json.loads(out))
    except Exception:
        blob = out
    structural = re.search(r"appears\s+to\s+be\s+packed|packed\s+or\s+obfuscated", blob, re.I)
    named = PACKER_NAME.search(blob)
    if named:
        return PACKED, f"PEiD signature: {_names(blob)}", blob
    if structural:
        why = _reasons(blob) or "structural indicators"
        return PACKED, f"appears packed: {why}", blob
    return UNKNOWN, "no signature, no structural indicator", blob


def parse_capa(data):
    """Pull the parts of a capa report worth keeping as labels: every matched rule is a
    capability, with a namespace and often a MITRE ATT&CK technique and an MBC behaviour."""
    caps, namespaces, attack, mbc = [], set(), set(), set()
    for v in (data.get("rules") or {}).values():
        meta = v.get("meta") or {}
        name = meta.get("name", "")
        if not name:
            continue
        caps.append(name)
        if meta.get("namespace"):
            namespaces.add(meta["namespace"])
        for a in meta.get("attack") or []:
            lab = "::".join(x for x in [a.get("tactic"), a.get("technique"),
                                        a.get("subtechnique")] if x)
            if a.get("id") or lab:
                attack.add(f"{a.get('id','')} {lab}".strip())
        for b in meta.get("mbc") or []:
            lab = "::".join(x for x in [b.get("objective"), b.get("behavior"),
                                        b.get("method")] if x)
            if b.get("id") or lab:
                mbc.add(f"{b.get('id','')} {lab}".strip())
    return {"capabilities": sorted(set(caps)), "namespaces": sorted(namespaces),
            "attack": sorted(attack), "mbc": sorted(mbc)}


def tool_capa(path):
    """capa capability rules. The packer namespace is the reliable signal: a rule name
    that merely contains the word 'packer' may only be mentioning one."""
    out = _run(["capa", "-j", str(path)], timeout=TIMEOUT * SLOW_FACTOR)
    if _dead(out):
        return UNKNOWN, "tool did not answer", out
    try:
        data = json.loads(out)
    except Exception:
        return UNKNOWN, "output could not be parsed", out[:20000]
    parsed = parse_capa(data)
    ns = [n for n in parsed["namespaces"] if "packer" in n.lower()]
    parsed["packing"] = ns
    detail = json.dumps(parsed)
    if ns:
        return PACKED, "namespace: " + " | ".join(ns[:4]), detail
    return UNKNOWN, f"no packer namespace ({len(parsed['capabilities'])} capabilities)", detail


def tool_unipacker(path):
    """Emulation-based unpacking. Producing an output file proves the sample was packed;
    a failure proves only that the packer is unsupported."""
    with tempfile.TemporaryDirectory() as tmp:
        out = _run(["unipacker", "-d", tmp, str(path)], timeout=TIMEOUT * SLOW_FACTOR)
        produced = [p.name for p in Path(tmp).iterdir()] if Path(tmp).exists() else []
    if produced:
        return (PACKED, f"unpacked file produced: {', '.join(produced[:3])}",
                json.dumps({"unpacked_files": produced, "log": out[:8000]}))
    return UNKNOWN, "unpacking failed; packer may be unsupported", out[:20000]


# ---------------------------------------------------------------------------
# Whole-file heuristics: these may assert a negative.
# ---------------------------------------------------------------------------

def tool_pypackerdetect(path):
    """Signatures plus PE heuristics -- known packer sections, too few imports, an entry
    point outside the usual section.

    Its report is counted rather than worded:

        Packer report for: <file>
                Detections: 0
                Suspicions: 0

    Detections are signature hits, suspicions are heuristic ones. Both at zero is an
    explicit negative covering the whole file, which is why this tool may assert
    not_packed where a pure signature scanner may not.
    """
    out = _run(["pypackerdetect", str(path)])
    if _dead(out):
        return UNKNOWN, "tool did not answer", out
    det = re.search(r"Detections?\s*:\s*(\d+)", out, re.I)
    sus = re.search(r"Suspicions?\s*:\s*(\d+)", out, re.I)
    if det or sus:
        n_det = int(det.group(1)) if det else 0
        n_sus = int(sus.group(1)) if sus else 0
        if n_det == 0 and n_sus == 0:
            return NOT_PACKED, "0 detections, 0 suspicions", out
        label = f"{n_det} detection(s), {n_sus} suspicion(s)"
        # each finding is printed on its own tagged line -- take them verbatim
        # rather than guessing at the phrasing:
        #     [DETECTION] Section name 'UPX0' matches known packer: [UPX packer]
        found = re.findall(r"\[(?:DETECTION|SUSPICION)\]\s*(.+)", out)
        why = " | ".join(" ".join(f.split())[:110] for f in found[:5])
        why = why or _reasons(out) or _names(out)
        return PACKED, (f"{label}: {why}" if why else label), out
    # older builds print prose instead of counts
    if re.search(r"not\s+packed|no\s+packer|nothing\s+detected", out, re.I):
        return NOT_PACKED, "no packing detected", out
    if PACKER_NAME.search(out) or re.search(r"\bpacked\b|suspicion|detection", out, re.I):
        return PACKED, (_reasons(out) or _names(out) or "detection reported"), out
    return UNKNOWN, "no clear verdict", out


def tool_reminder(path):
    """Entry-point section permissions plus entropy -- a whole-file heuristic, so its
    negative counts."""
    out = _run(["reminder", str(path)])
    if _dead(out):
        return UNKNOWN, "tool did not answer", out
    ent = re.search(r"entropy[^0-9]{0,12}([0-9]+\.[0-9]+)", out, re.I)
    tail = f" (entropy {ent.group(1)})" if ent else ""
    if re.search(r"not\s+packed|\bfalse\b", out, re.I):
        return NOT_PACKED, f"heuristic says not packed{tail}", out
    if re.search(r"\bpacked\b|\btrue\b", out, re.I):
        return PACKED, f"entropy / entry-point heuristic fired{tail}", out
    return UNKNOWN, "no clear verdict", out


# name -> (runner, executable, may_assert_negative)
TOOLS = {
    "diec":           (tool_diec,           "diec",           False),
    "peid":           (tool_peid,           "peid",           False),
    "manalyze":       (tool_manalyze,       "manalyze",       False),
    "capa":           (tool_capa,           "capa",           False),
    "unipacker":      (tool_unipacker,      "unipacker",      False),
    "pypackerdetect": (tool_pypackerdetect, "pypackerdetect", True),
    "reminder":       (tool_reminder,       "reminder",       True),
}


def analyse(path, tools):
    rec = {"file": path.name, "path": str(path), "size": path.stat().st_size}
    verdicts, reasons = {}, {}
    for name in tools:
        fn, _, _ = TOOLS[name]
        t0 = time.perf_counter()
        verdict, reason, detail = fn(path)
        verdicts[name] = verdict
        reasons[name] = reason
        rec[name] = verdict
        rec[f"{name}_reason"] = reason
        rec[f"{name}_raw"] = detail[:20000]
        rec[f"{name}_seconds"] = round(time.perf_counter() - t0, 2)

    if "capa" in verdicts:
        try:
            parsed = json.loads(rec.get("capa_raw") or "{}")
        except Exception:
            parsed = {}
        rec["capa_n_capabilities"] = len(parsed.get("capabilities") or [])
        rec["capa_capabilities"] = ";".join(parsed.get("capabilities") or [])
        rec["capa_namespaces"] = ";".join(parsed.get("namespaces") or [])
        rec["capa_attack"] = ";".join(parsed.get("attack") or [])
        rec["capa_mbc"] = ";".join(parsed.get("mbc") or [])

    positives = [t for t, v in verdicts.items() if v == PACKED]
    negatives = [t for t, v in verdicts.items() if v == NOT_PACKED and TOOLS[t][2]]
    rec["tools_saying_packed"] = ";".join(positives)
    rec["tools_saying_not_packed"] = ";".join(negatives)
    rec["n_packed"] = len(positives)
    rec["n_not_packed"] = len(negatives)
    rec["n_unknown"] = sum(1 for v in verdicts.values() if v == UNKNOWN)
    # one line saying which tool concluded what, and why
    rec["evidence"] = " || ".join(f"{t}={verdicts[t]}: {reasons[t]}" for t in tools)

    if positives:
        rec["consensus"] = PACKED
    elif negatives:
        rec["consensus"] = NOT_PACKED
    else:
        rec["consensus"] = UNKNOWN
    rec["confidence"] = ("high" if len(positives) >= 2 or len(negatives) >= 2
                         else "low" if rec["consensus"] != UNKNOWN else "none")
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", default="results/packers")
    ap.add_argument("--tools", default="")
    ap.add_argument("--hashes", default="")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    wanted = [t.strip() for t in args.tools.split(",") if t.strip()] or list(TOOLS)
    tools = [t for t in wanted if shutil.which(TOOLS[t][1])]
    missing = [t for t in wanted if t not in tools]
    if not tools:
        sys.exit("none of the requested tools are on PATH: " + ", ".join(wanted))
    can_negate = [t for t in tools if TOOLS[t][2]]
    print("using   :", ", ".join(tools))
    if missing:
        print("missing :", ", ".join(missing), "(skipped)")
    if not can_negate:
        print("warning : no tool present can assert 'not packed'.\n"
              "          every non-detection becomes unknown -- correct, but you will\n"
              "          get no negatives. Add pypackerdetect or reminder.")

    out_dir = Path(args.out); out_dir.mkdir(parents=True, exist_ok=True)
    results = out_dir / "results.jsonl"

    done = set()
    if results.exists():
        with results.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    done.add(json.loads(line)["file"])
                except Exception:
                    pass
        print(f"resuming: {len(done):,} already done")

    files = sorted(p for p in Path(args.input).iterdir() if p.is_file())
    if args.hashes:
        keep = {l.strip() for l in Path(args.hashes).read_text().splitlines() if l.strip()}
        files = [p for p in files if p.name in keep or p.stem in keep]
    files = [p for p in files if p.name not in done]
    if args.limit:
        files = files[:args.limit]
    print(f"to process: {len(files):,}\n")

    t0 = time.perf_counter()
    tally = {PACKED: 0, NOT_PACKED: 0, UNKNOWN: 0}
    with results.open("a", encoding="utf-8") as fh, \
         ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(analyse, p, tools): p for p in files}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                rec = fut.result()
            except Exception as exc:
                print(f"  failed {futures[fut].name}: {exc}", flush=True)
                continue
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            tally[rec["consensus"]] += 1
            if i % 50 == 0 or i == len(files):
                rate = i / max(time.perf_counter() - t0, 1e-9)
                left = (len(files) - i) / max(rate, 1e-9) / 60
                print(f"  {i:>7,}/{len(files):,}  packed {tally[PACKED]:,}  "
                      f"not_packed {tally[NOT_PACKED]:,}  unknown {tally[UNKNOWN]:,}  "
                      f"{rate:.1f}/s  ~{left:.0f} min left", flush=True)

    cols = ["file", "size", "consensus", "confidence", "n_packed", "n_not_packed",
            "n_unknown", "tools_saying_packed", "tools_saying_not_packed"]
    for t in tools:
        cols += [t, f"{t}_reason"]
    cols.append("evidence")
    if "capa" in tools:
        cols += ["capa_n_capabilities", "capa_namespaces", "capa_attack", "capa_mbc"]
    with results.open(encoding="utf-8") as fh, \
         (out_dir / "summary.csv").open("w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for line in fh:
            try:
                w.writerow(json.loads(line))
            except Exception:
                pass
    print(f"\nwrote {results}")
    print(f"wrote {out_dir / 'summary.csv'}")
    print(f"total {(time.perf_counter() - t0) / 60:.1f} min")


if __name__ == "__main__":
    main()
