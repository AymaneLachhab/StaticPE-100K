"""Check the packing pipeline can actually run here, and say what is missing.

Run it on the login node after setup_env.sh, then again inside a job -- a compute node
sees a different PATH and, importantly, usually no internet. The network check is the
one that decides whether the run has to be split into two stages.

    python Code/hpc/check_env.py
    python Code/hpc/check_env.py --sample path/to/a.exe    # also runs each tool once
"""

from pathlib import Path
import argparse
import importlib
import os
import shutil
import subprocess
import sys

MODULES = [("requests", "VirusShare API"), ("pyzipper", "AES zips"),
           ("pefile", "PE parsing"), ("capa", "capa library"),
           ("pandas", "tables"), ("pyarrow", "parquet")]

TOOLS = [("capa", "pip install flare-capa"),
         ("pypackerdetect", "pip install pypackerdetect"),
         ("peid", "pip install peid"),
         ("diec", "setup_env.sh unpacks it, or set --diec to the full path"),
         ("reminder", "not on PyPI under this name -- install it the way you did on "
                      "your VM, or drop it with --tools")]

OK, BAD, WARN = "  ok  ", " MISS ", " warn "


def line(state, name, note=""):
    print(f"[{state}] {name:<16} {note}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default="", help="a PE file to try every tool on")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()

    print(f"python   : {sys.version.split()[0]}  {sys.executable}")
    print(f"node     : {os.uname().nodename if hasattr(os, 'uname') else 'n/a'}")
    print(f"cwd      : {Path.cwd()}\n")

    missing = []
    for mod, why in MODULES:
        try:
            m = importlib.import_module(mod)
            line(OK, mod, getattr(m, "__version__", why))
        except Exception as exc:
            line(BAD, mod, f"{why} -- {exc}")
            missing.append(mod)

    print()
    found = {}
    for tool, how in TOOLS:
        path = shutil.which(tool) or (os.environ.get("DIEC_CMD", "")
                                      if tool == "diec" else "")
        if path and Path(path.split()[0]).exists():
            found[tool] = path
            line(OK, tool, path)
        else:
            line(WARN, tool, how)

    # Internet from this node. If this fails on a compute node -- which is normal --
    # the download has to happen on the login node: stage1_download.slurm, then
    # stage2_analyse.slurm with --offline.
    print()
    try:
        import requests
        requests.get("https://virusshare.com/apiv2/file",
                     params={"apikey": "x", "hash": "0" * 32}, timeout=15)
        line(OK, "network", "virusshare.com reachable from this node")
    except Exception as exc:
        line(WARN, "network", f"no internet here -- split the run in two stages ({exc})"[:110])

    if args.sample:
        print(f"\nrunning each tool once on {args.sample}")
        for tool, cmd in [("capa", ["capa", "--color", "never"]),
                          ("pypackerdetect", ["pypackerdetect"]),
                          ("peid", ["peid"]),
                          ("diec", (os.environ.get("DIEC_CMD") or "diec").split()),
                          ("reminder", ["reminder"])]:
            if tool not in found:
                continue
            try:
                p = subprocess.run(cmd + [args.sample], capture_output=True,
                                   text=True, timeout=args.timeout)
                out = " ".join(((p.stdout or "") + (p.stderr or "")).split())[:90]
                line(OK if out else WARN, tool, out or "no output")
            except subprocess.TimeoutExpired:
                line(WARN, tool, f"timed out after {args.timeout}s")
            except Exception as exc:
                line(BAD, tool, str(exc)[:90])

    print()
    if missing:
        print(f"blocking: {', '.join(missing)} -- pip install -r Code/hpc/requirements.txt")
        sys.exit(1)
    if not found:
        print("no detector available: the vote would have no voters")
        sys.exit(1)
    print(f"usable detectors: {', '.join(found)}  (vote out of {len(found)})")


if __name__ == "__main__":
    main()
