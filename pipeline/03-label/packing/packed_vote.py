"""Ask several packer detectors, count the votes.

    all say yes    ->  packed
    none say yes   ->  not packed
    anything else  ->  not sure

The vote is always out of however many tools actually ran, so dropping one with --tools
or having one missing simply changes the denominator.

Tools used, in this order:

    diec             Detect It Easy      names the packer
    reminder         REMINDer            entropy + entry-point heuristic
    pypackerdetect   PyPackerDetect      signatures + PE heuristics
    peid             PEiD signatures     5,500+ signature database
    capa             capa (Mandiant)     anti-analysis/packer/* capability namespaces

Each tool answers yes or no, and its reason is printed next to it. A tool that fails to
run counts as no, and is marked so in the output -- check `n_answered` before trusting a
"not packed" verdict built on tools that never replied.

Usage
    python packed_vote.py sample.exe
    python packed_vote.py DIR_OF_SAMPLES
    python packed_vote.py DIR --csv results/vote.csv --workers 8
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
import time

TIMEOUT = 120

PACKER_WORD = re.compile(
    r"upx|aspack|themida|vmprotect|petite|pecompact|nspack|mpress|enigma|armadillo|"
    r"molebox|obsidium|execryptor|pespin|yoda|fsg|mew|packman|kkrunchy|rlpack|"
    r"winupack|exestealth|neolite|shrinker|telock|packer|protector|crypter", re.I)


def sh(cmd):
    """Run a tool and return its output with line endings normalised.

    The normalisation is not cosmetic. Detect It Easy, when invoked through its docker
    wrapper, separates lines with a bare carriage return. Python's re.MULTILINE only
    treats \\n as a line boundary, so a pattern anchored with ^ silently matches nothing
    against such output -- the packer line is right there and the parser reports finding
    none.
    """
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        out = (p.stdout or "") + (p.stderr or "")
        return out.replace("\r\n", "\n").replace("\r", "\n")
    except subprocess.TimeoutExpired:
        return "\x00timeout"
    except Exception as exc:
        return f"\x00{exc}"


DIEC_CMD = ["diec"]          # overridden by --diec, e.g. ./Detect-It-Easy/docker/diec.sh
DEBUG = False                # --debug prints each tool's untouched output


def ask_diec(path):
    # absolute: the docker wrapper mounts a volume, so a relative path does not point
    # at the same file inside the container
    out = sh(DIEC_CMD + [str(Path(path).resolve())])
    if out.startswith("\x00"):
        return None, "did not run"
    if DEBUG:
        print(f"\n[diec raw]\n{out}", flush=True)
    # Packer: UPX(3.08)[LZMA, brute]   /   Protector: VMProtect
    hits = re.findall(r"^\s*(Packer|Protector)\s*:\s*(.+)$", out, re.I | re.M)
    if hits:
        return True, " | ".join(f"{k}: {v.strip()}" for k, v in hits[:3])
    try:                                    # some builds only speak JSON
        data = json.loads(out)
        named = [f"{v.get('name','')} {v.get('version','')}".strip()
                 for d in data.get("detects", []) for v in d.get("values", [])
                 if (v.get("type") or "").lower() in ("packer", "protector")]
        if named:
            return True, " | ".join(named[:3])
    except Exception:
        pass
    first = " ".join(out.split())[:70]
    return False, f"no packer or protector line (output: {first})"


def ask_reminder(path):
    out = sh(["reminder", str(Path(path).resolve())])
    if out.startswith("\x00"):
        return None, "did not run"
    if DEBUG:
        print(f"\n[reminder raw]\n{out}", flush=True)
    ent = re.search(r"([0-9]+\.[0-9]{2,})", out)
    tail = f" (entropy {ent.group(1)})" if ent else ""
    if re.search(r"\btrue\b|\bpacked\b", out, re.I) and not re.search(r"\bfalse\b|not packed", out, re.I):
        return True, f"heuristic fired{tail}"
    if re.search(r"\bfalse\b|not packed", out, re.I):
        return False, f"heuristic clear{tail}"
    return None, f"unclear output: {' '.join(out.split())[:60]}"


def ask_pypackerdetect(path):
    out = sh(["pypackerdetect", str(Path(path).resolve())])
    if out.startswith("\x00"):
        return None, "did not run"
    if DEBUG:
        print(f"\n[pypackerdetect raw]\n{out}", flush=True)
    det = re.search(r"Detections?\s*:\s*(\d+)", out, re.I)
    sus = re.search(r"Suspicions?\s*:\s*(\d+)", out, re.I)
    if not (det or sus):
        return None, f"unclear output: {' '.join(out.split())[:60]}"
    n_det = int(det.group(1)) if det else 0
    n_sus = int(sus.group(1)) if sus else 0
    if n_det == 0 and n_sus == 0:
        return False, "0 detections, 0 suspicions"
    found = re.findall(r"\[(?:DETECTION|SUSPICION)\]\s*(.+)", out)
    why = " | ".join(" ".join(f.split())[:80] for f in found[:3])
    return True, f"{n_det} detection(s), {n_sus} suspicion(s)" + (f": {why}" if why else "")


def ask_peid(path):
    out = sh(["peid", str(Path(path).resolve())])
    if out.startswith("\x00"):
        return None, "did not run"
    if DEBUG:
        print(f"\n[peid raw]\n{out}", flush=True)
    if re.search(r"no\s+signature|nothing", out, re.I):
        return False, "no signature matched"
    lines, seen = [], set()
    for line in out.splitlines():
        line = line.strip()
        if line and line.lower() not in seen:
            seen.add(line.lower())
            lines.append(line[:60])
    if lines and PACKER_WORD.search(out):
        return True, "signature: " + " | ".join(lines[:3])
    return False, "no signature matched"


CAPA_CMD = ["capa"]          # overridden by --capa-cmd, e.g. ./capa-tool/capa


def parse_capa_text(out):
    """Read capa's -v listing into (capabilities, namespaces).

    The blocks look like:

        packed with UPX
        namespace  anti-analysis/packer/upx
        scope      file

        encode data using XOR
        namespace  data-manipulation/encoding/xor
        scope      basic block
        matches    0x546FC7

    so a line that is neither a key/value pair nor part of the header block is a
    capability name, and the namespace follows it.
    """
    header = {"md5", "sha1", "sha256", "path", "timestamp", "capa version", "os",
              "format", "arch", "analysis", "extractor", "base address", "rules",
              "function count", "library function count", "total feature count"}
    caps, namespaces, pending = [], [], None
    for line in out.splitlines():
        raw = line.rstrip()
        if not raw.strip() or raw.startswith("WARNING") or raw.startswith(" "):
            continue
        low = raw.strip().lower()
        if any(low.startswith(h) for h in header):
            pending = None
            continue
        m = re.match(r"^(namespace|scope|matches|author|att&ck|mbc)\s+(.*)$",
                     raw.strip(), re.I)
        if m:
            if m.group(1).lower() == "namespace" and pending:
                namespaces.append(m.group(2).strip())
            continue
        pending = raw.strip()
        caps.append(pending)
    return caps, namespaces


def ask_capa(path):
    """capa. Two independent packing signals: the warning it prints when its internal
    packer rule fires, and any capability in an anti-analysis/packer namespace.

    -v matters: without it capa refuses to report on a packed sample, and -j alone
    raises a RuntimeError on exactly those files.
    """
    out = sh(CAPA_CMD + ["-v", "--color", "never", str(Path(path).resolve())])
    if out.startswith("\x00"):
        return None, "did not run", out
    if DEBUG:
        print(f"\n[capa raw]\n{out}", flush=True)
    caps, namespaces = parse_capa_text(out)
    packer_ns = [n for n in namespaces if "anti-analysis/packer" in n.lower()]
    warned = "appears to be packed" in out.lower()
    if packer_ns or warned:
        why = " | ".join(sorted(set(packer_ns))[:3]) or "internal packer rule fired"
        return True, f"{why} ({len(caps)} capabilities)", out
    if caps or "total feature count" in out:
        return False, f"no packer namespace ({len(caps)} capabilities)", out
    return None, "no usable output", out


TOOLS = [("diec", ask_diec, "diec"),
         ("reminder", ask_reminder, "reminder"),
         ("pypackerdetect", ask_pypackerdetect, "pypackerdetect"),
         ("peid", ask_peid, "peid"),
         ("capa", ask_capa, "capa")]


def vote(path, tools):
    rec = {"file": path.name, "size": path.stat().st_size}
    yes = no = failed = 0
    for name, fn, _ in tools:
        answer, why = fn(path)
        if answer is None:
            rec[name] = "error"
            failed += 1
        elif answer:
            rec[name] = "yes"
            yes += 1
        else:
            rec[name] = "no"
            no += 1
        rec[f"{name}_reason"] = why

    n = len(tools)
    rec["yes"] = yes
    rec["no"] = no
    rec["errors"] = failed
    rec["n_answered"] = yes + no
    rec["score"] = f"{yes}/{n}"
    if yes == n:
        rec["verdict"] = "packed"
    elif yes == 0 and failed == 0:
        rec["verdict"] = "not packed"
    else:
        rec["verdict"] = "not sure"
    return rec


def show(rec, tools):
    print(f"\n{rec['file']}   ({rec['size']:,} bytes)")
    print("-" * 78)
    for name, _, _ in tools:
        mark = {"yes": "YES", "no": "no ", "error": "ERR"}[rec[name]]
        print(f"  {name:<16} {mark}   {rec[f'{name}_reason']}")
    print("-" * 78)
    print(f"  {rec['score']} say packed  ->  {rec['verdict'].upper()}")
    if rec["errors"]:
        print(f"  warning: {rec['errors']} tool(s) failed to run")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="a PE file, or a directory of them")
    ap.add_argument("--csv", default="", help="also write the results here")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--quiet", action="store_true", help="totals only, no per-file block")
    ap.add_argument("--debug", action="store_true",
                    help="print each tool's raw output -- use when a verdict surprises you")
    ap.add_argument("--tools", default="",
                    help="comma-separated subset to use, e.g. diec,reminder,pypackerdetect. "
                         "Default: every tool found. The vote is always out of however "
                         "many actually run.")
    ap.add_argument("--diec", default="",
                    help="how to invoke Detect It Easy when it is not on PATH, "
                         "e.g. ./Detect-It-Easy/docker/diec.sh")
    ap.add_argument("--capa-cmd", default="",
                    help="how to invoke capa when it is not on PATH, "
                         "e.g. ./capa-tool/capa")
    args = ap.parse_args()

    global DIEC_CMD, CAPA_CMD, DEBUG
    DEBUG = args.debug

    def resolve(flag, current, label):
        if not flag:
            return current, bool(shutil.which(current[0]))
        cmd = flag.split()
        if not (Path(cmd[0]).exists() or shutil.which(cmd[0])):
            sys.exit(f"--{label}: {cmd[0]} does not exist")
        return cmd, True

    DIEC_CMD, diec_ok = resolve(args.diec, DIEC_CMD, "diec")
    CAPA_CMD, capa_ok = resolve(args.capa_cmd, CAPA_CMD, "capa-cmd")

    known = [n for n, _, _ in TOOLS]
    if args.tools:
        wanted = [t.strip() for t in args.tools.split(",") if t.strip()]
        unknown = [t for t in wanted if t not in known]
        if unknown:
            sys.exit(f"--tools: unknown {', '.join(unknown)}; "
                     f"choose from {', '.join(known)}")
    else:
        wanted = known

    def available(name, exe):
        if name == "diec":
            return diec_ok
        if name == "capa":
            return capa_ok
        return bool(shutil.which(exe))

    tools = [(n, f, exe) for n, f, exe in TOOLS if n in wanted and available(n, exe)]
    missing = [n for n, _, exe in TOOLS if n in wanted and not available(n, exe)]
    skipped = [n for n in known if n not in wanted]
    if not tools:
        sys.exit("none of the requested tools are available")
    print(f"tools: {', '.join(n for n, _, _ in tools)}   (vote out of {len(tools)})")
    if skipped:
        print("excluded by --tools:", ", ".join(skipped))
    if missing:
        print("missing:", ", ".join(missing), "-- not installed or not on PATH")
        if "diec" in missing:
            print("         DIE is often run through a wrapper rather than installed;")
            print("         point at it with --diec ./Detect-It-Easy/docker/diec.sh")

    target = Path(args.target)
    if not target.exists():
        sys.exit(f"{target} does not exist "
                 f"(current directory is {Path.cwd()})")
    files = [target] if target.is_file() else sorted(p for p in target.iterdir() if p.is_file())
    if not files:
        sys.exit(f"{target} holds no files")
    print(f"files: {len(files):,}")

    results = []
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(vote, p, tools): p for p in files}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                rec = fut.result()
            except Exception as exc:
                print(f"  failed {futures[fut].name}: {exc}")
                continue
            results.append(rec)
            if not args.quiet:
                show(rec, tools)
            elif i % 100 == 0:
                print(f"  {i:,}/{len(files):,}", flush=True)

    print("\n" + "=" * 78)
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    for v in ("packed", "not packed", "not sure"):
        n = counts.get(v, 0)
        print(f"  {v:<12} {n:>7,}  {100 * n / max(len(results), 1):>5.1f}%")
    print(f"  {'total':<12} {len(results):>7,}   in {time.perf_counter() - t0:.0f}s")

    if args.csv:
        out = Path(args.csv)
        out.parent.mkdir(parents=True, exist_ok=True)
        cols = (["file", "size", "verdict", "score", "yes", "no", "errors", "n_answered"]
                + [n for n, _, _ in tools] + [f"{n}_reason" for n, _, _ in tools])
        with out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(results)
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
