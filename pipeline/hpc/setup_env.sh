#!/usr/bin/env bash
# Build the packing-analysis environment on an HPC account, with no root.
#
# Run this ON THE LOGIN NODE: it needs internet, and compute nodes usually have none.
#
#   export PROJECT=$HOME/malware_pipeline/env
#   bash Code/hpc/setup_env.sh
#   source $PROJECT/env.sh
#
# What it does
#   1. finds a Python >= 3.9 (module system first, then whatever is on PATH)
#   2. creates an environment and installs requirements.txt
#   3. downloads Detect It Easy and unpacks it without root (no .deb install, no docker)
#   4. writes env.sh, then checks every tool and prints what is missing
#
# Nothing here needs root, and nothing assumes a particular download tool: clusters
# routinely ship without curl, so every fetch falls back to wget and then to Python.

set -uo pipefail

# An explicitly exported PROJECT is used as given; otherwise a sensible default is built.
PROJECT="${PROJECT:-${WORK:-${SCRATCH:-$HOME}}/packing}"
VENV="$PROJECT/venv"
OPT="$PROJECT/opt"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$OPT"
echo "installing into $PROJECT"
echo

# ---------------------------------------------------------------------------
# 1. Python
# ---------------------------------------------------------------------------
if command -v module >/dev/null 2>&1; then
  # Module names differ from one cluster to the next, so try a few and keep the first
  # that works. If none do, run `module avail python` and set PYTHON_MODULE yourself.
  for m in ${PYTHON_MODULE:-python/3.11 python/3.10 python3/3.11 python 3.11 Python/3.11}; do
    module load "$m" >/dev/null 2>&1 && { echo "module loaded: $m"; break; }
  done
fi

PY=""
for c in python3.12 python3.11 python3.10 python3.9 python3; do
  command -v "$c" >/dev/null 2>&1 || continue
  "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null \
    && { PY="$c"; break; }
done
[ -n "$PY" ] || { echo "no Python >= 3.9 found. Run: module avail python"; exit 1; }
echo "python     : $($PY --version) at $(command -v "$PY")"

# ---------------------------------------------------------------------------
# 1b. One download helper for the whole script
# ---------------------------------------------------------------------------
# curl is not a given on a compute cluster, wget is not either, but a Python was just
# located above -- so urllib is the floor this can always fall back to.
fetch() {           # fetch URL DEST  ->  0 on success
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 300 -o "$dest" "$url" && [ -s "$dest" ] && return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q --timeout=300 -O "$dest" "$url" && [ -s "$dest" ] && return 0
  fi
  "$PY" - "$url" "$dest" <<'PYFETCH' && [ -s "$dest" ] && return 0
import sys, urllib.request
url, dest = sys.argv[1], sys.argv[2]
try:
    with urllib.request.urlopen(url, timeout=300) as r, open(dest, "wb") as fh:
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            fh.write(chunk)
except Exception as exc:
    sys.stderr.write(f"download failed: {exc}\n")
    sys.exit(1)
PYFETCH
  return 1
}

for t in curl wget; do command -v $t >/dev/null 2>&1 && DL="${DL:-$t}"; done
echo "downloads  : ${DL:-python urllib}"

# ---------------------------------------------------------------------------
# 2. The Python environment, by whichever of three routes works here
# ---------------------------------------------------------------------------
# Debian ships the venv module but puts ensurepip in a separate python3-venv package,
# which cannot be installed without root. So:
#
#   a. plain `venv`               -- works wherever python3-venv is present
#   b. `venv --without-pip`       -- creates the environment anyway, then pip is
#                                    bootstrapped with get-pip.py. Same result, no root
#   c. micromamba                 -- a static binary bringing its own Python. The
#                                    fallback when the system Python is unusable, and
#                                    the way to pin a version: MAMBA_PY=3.11
#
# Force route c with:  USE_MICROMAMBA=1 bash Code/hpc/setup_env.sh

have_venv() {
  [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -m pip --version >/dev/null 2>&1
}

if [ "${USE_MICROMAMBA:-0}" != "1" ]; then
  if ! have_venv; then
    rm -rf "$VENV"
    echo "environment: trying route a (venv)"
    "$PY" -m venv "$VENV" >/dev/null 2>&1 || true
  fi
  if ! have_venv; then
    rm -rf "$VENV"
    echo "environment: ensurepip missing, trying route b (venv --without-pip + get-pip)"
    "$PY" -m venv --without-pip "$VENV" >/dev/null 2>&1 || true
    if [ -x "$VENV/bin/python" ]; then
      fetch https://bootstrap.pypa.io/get-pip.py "$OPT/get-pip.py" \
        && "$VENV/bin/python" "$OPT/get-pip.py" --quiet
    fi
  fi
fi

if ! have_venv; then
  echo "environment: trying route c (micromamba, about 100 MB)"
  MAMBA="$OPT/bin/micromamba"
  if [ ! -x "$MAMBA" ]; then
    mkdir -p "$OPT/bin"
    # download to a file first: piping into tar hides which of the two steps failed
    if fetch https://micro.mamba.pm/api/micromamba/linux-64/latest "$OPT/micromamba.tar.bz2"; then
      tar -xjf "$OPT/micromamba.tar.bz2" -C "$OPT" bin/micromamba \
        && rm -f "$OPT/micromamba.tar.bz2"
    fi
  fi
  if [ -x "$MAMBA" ]; then
    rm -rf "$VENV"
    export MAMBA_ROOT_PREFIX="$OPT/mamba"
    "$MAMBA" create -y -q -p "$VENV" -c conda-forge \
        "python=${MAMBA_PY:-3.11}" pip >/dev/null \
      || echo "micromamba could not create the environment"
  else
    echo "micromamba could not be downloaded"
  fi
fi

have_venv || {
  echo
  echo "no working Python environment could be built."
  echo "Check that this node has internet:"
  echo "  $PY -c \"import urllib.request as u; print(u.urlopen('https://pypi.org', timeout=15).status)\""
  echo "If that fails, the cluster is behind a proxy -- export https_proxy and retry."
  exit 1
}

# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install --quiet --upgrade pip wheel
echo "venv python: $(python --version)"
echo "installing Python packages (a few minutes)..."
python -m pip install -r "$HERE/requirements.txt" || {
  echo
  echo "pip failed. The usual cause is a Python too new for one of the wheels."
  echo "Retry on a version that has wheels for everything:"
  echo "  USE_MICROMAMBA=1 MAMBA_PY=3.11 bash $HERE/setup_env.sh"
  exit 1
}
echo "venv       : $VENV"

# ---------------------------------------------------------------------------
# 3. Detect It Easy, without root
# ---------------------------------------------------------------------------
# DIE ships .deb builds, which do not need installing: a .deb is an ar archive that
# dpkg-deb -- or ar plus tar -- can unpack anywhere. The asset name changes with every
# release, so the release is queried rather than guessed.
DIEC="$(command -v diec || true)"
if [ -z "$DIEC" ] && [ ! -x "$OPT/die/usr/bin/diec" ]; then
  echo "fetching Detect It Easy..."
  if fetch "https://api.github.com/repos/horsicq/DIE-engine/releases/latest" "$OPT/die.json"; then
    url="$(grep -o '"browser_download_url": *"[^"]*"' "$OPT/die.json" \
           | cut -d'"' -f4 | grep -Ei 'x86_64\.deb$|amd64\.deb$' | head -1)"
    rm -f "$OPT/die.json"
    if [ -z "$url" ]; then
      echo "  no .deb asset found -- see https://github.com/horsicq/DIE-engine/releases"
    else
      echo "  $url"
      if fetch "$url" "$OPT/die.deb"; then
        mkdir -p "$OPT/die"
        if command -v dpkg-deb >/dev/null 2>&1; then
          dpkg-deb -x "$OPT/die.deb" "$OPT/die"
        elif command -v ar >/dev/null 2>&1; then
          ( cd "$OPT/die" && ar x "$OPT/die.deb" && tar xf data.tar.* )
        else
          echo "  neither dpkg-deb nor ar is available -- cannot unpack the .deb"
        fi
        rm -f "$OPT/die.deb"
      fi
    fi
  else
    echo "  could not reach github.com"
  fi
fi
[ -x "$OPT/die/usr/bin/diec" ] && DIEC="$OPT/die/usr/bin/diec"
[ -n "$DIEC" ] && echo "diec       : $DIEC" || echo "diec       : missing (the vote runs without it)"

# ---------------------------------------------------------------------------
# 4. an env file every job sources
# ---------------------------------------------------------------------------
cat > "$PROJECT/env.sh" <<ENV
# generated by setup_env.sh -- source this in every job and every new shell
export PROJECT="$PROJECT"
source "$VENV/bin/activate"
export PATH="$OPT/die/usr/bin:\$PATH"
export DIEC_CMD="${DIEC:-diec}"
# vivisect and capa write caches; keep them off \$HOME, whose quota counts inodes
export XDG_CACHE_HOME="\$PROJECT/cache"
mkdir -p "\$XDG_CACHE_HOME"
ENV
echo "env file   : $PROJECT/env.sh"

echo
python "$HERE/check_env.py"
echo
echo "next:  source $PROJECT/env.sh"
