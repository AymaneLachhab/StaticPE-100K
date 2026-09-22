#!/usr/bin/env bash
# Install FLOSS from Mandiant's prebuilt Linux binary.
#
#   cd ~/malware_pipeline && source env/env.sh
#   bash Code/hpc/install_floss.sh
#
# pip cannot install FLOSS here. Not because of FLOSS -- which is pure Python -- but
# because of one dependency, binary2strings, a C++ extension with no wheel for Python
# 3.13. Cloning the repository changes nothing: the same dependency has to be built.
#
# Mandiant also publishes a standalone Linux executable per release, produced with
# PyInstaller: one file, its own interpreter and every dependency inside, nothing to
# compile and nothing to resolve. That is what this fetches.
#
# The asset name changes with each release, so the release is queried rather than
# guessed, and the version is not pinned to capa's -- they are separate projects.

set -uo pipefail

PROJECT="${PROJECT:-$HOME/malware_pipeline/env}"
OPT="$PROJECT/opt"
DEST="$OPT/floss"

mkdir -p "$DEST"

fetch() {           # fetch URL DEST
  local url="$1" dest="$2"
  command -v curl >/dev/null 2>&1 && curl -fsSL -o "$dest" "$url" && [ -s "$dest" ] && return 0
  command -v wget >/dev/null 2>&1 && wget -q -O "$dest" "$url" && [ -s "$dest" ] && return 0
  python - "$url" "$dest" <<'PYFETCH' && [ -s "$dest" ] && return 0
import sys, urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=300) as r, open(sys.argv[2], "wb") as fh:
    fh.write(r.read())
PYFETCH
  return 1
}

if [ ! -x "$DEST/floss" ]; then
  echo "querying the latest FLOSS release..."
  fetch "https://api.github.com/repos/mandiant/flare-floss/releases/latest" "$OPT/floss.json" \
    || { echo "could not reach github.com"; exit 1; }
  url="$(grep -o '"browser_download_url": *"[^"]*"' "$OPT/floss.json" \
         | cut -d'"' -f4 | grep -Ei 'linux' | grep -Ei '\.zip$' | head -1)"
  rm -f "$OPT/floss.json"
  [ -n "$url" ] || { echo "no Linux asset in the latest release -- see"
                     echo "  https://github.com/mandiant/flare-floss/releases"; exit 1; }
  echo "  $url"
  fetch "$url" "$OPT/floss.zip" || { echo "download failed"; exit 1; }

  # python's zipfile rather than unzip, which is not installed on every cluster
  python - "$OPT/floss.zip" "$DEST" <<'PYUNZIP'
import sys, zipfile, os, stat
from pathlib import Path
with zipfile.ZipFile(sys.argv[1]) as z:
    z.extractall(sys.argv[2])
for p in Path(sys.argv[2]).rglob("floss*"):
    if p.is_file():
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
PYUNZIP
  rm -f "$OPT/floss.zip"
fi

BIN="$(find "$DEST" -maxdepth 2 -type f -name 'floss*' -perm -u+x | head -1)"
[ -n "$BIN" ] || { echo "the archive unpacked but no executable was found:"; ls -R "$DEST" | head -20; exit 1; }

echo "floss      : $BIN"
"$BIN" --version 2>&1 | head -3

if [ -f "$PROJECT/env.sh" ] && ! grep -q "FLOSS_CMD" "$PROJECT/env.sh"; then
  cat >> "$PROJECT/env.sh" <<ENV

# added by install_floss.sh -- the standalone build, since binary2strings cannot compile
export FLOSS_CMD="$BIN"
ENV
  echo "env file   : updated $PROJECT/env.sh"
fi

echo
echo "next:  source $PROJECT/env.sh  &&  \$FLOSS_CMD --help | head"
