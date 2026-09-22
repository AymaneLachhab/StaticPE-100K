#!/usr/bin/env bash
# Install yara-python and a curated anti-analysis rule set, without blowing the quota.
#
#   cd ~/malware_pipeline && source env/env.sh
#   bash Code/hpc/install_yara_rules.sh
#
# The Yara-Rules repository holds a few thousand files across a dozen themes. Cloning it
# would cost several thousand inodes for the handful of rule files actually wanted, so it
# is downloaded as a tarball -- no .git, no working copy -- and only the relevant folders
# are extracted. The archive is deleted afterwards.
#
# Themes kept, and why:
#   antidebug_antivm   the point of the exercise: VM, sandbox and debugger detection
#   capabilities       what the binary can do -- keylogging, screenshots, persistence
#   crypto             crypto constants and algorithm signatures, for the ransomware question
#   packers            a fifth opinion on packing, from a different rule corpus
#
# Rules are then compiled ONE FILE AT A TIME. This matters: the collection is community
# maintained, so some files reference undeclared external variables or duplicate a rule
# name defined elsewhere, and a single bad file aborts a whole-directory compile. Compiling
# separately keeps every file that works and reports the ones that do not.

set -uo pipefail

PROJECT="${PROJECT:-$HOME/malware_pipeline/env}"
OPT="$PROJECT/opt"
YARA_DIR="$OPT/yara"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THEMES="${THEMES:-antidebug_antivm capabilities crypto packers}"

mkdir -p "$YARA_DIR"

# ---------------------------------------------------------------------------
# 1. yara-python
# ---------------------------------------------------------------------------
if ! python -c "import yara" 2>/dev/null; then
  echo "installing yara-python..."
  python -m pip install --quiet yara-python || {
    echo "yara-python failed to install. It ships manylinux wheels, so this usually"
    echo "means an unusual Python version. Check: python --version"
    exit 1; }
fi
echo "yara-python: $(python -c 'import yara; print(yara.__version__)')"

# ---------------------------------------------------------------------------
# 2. the rules
# ---------------------------------------------------------------------------
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

SRC="$YARA_DIR/src"
# An earlier run that flattened the themes must be discarded rather than reused: the
# rules would compile identically but every one of them would be labelled "src".
if [ -d "$SRC" ] && [ -z "$(find "$SRC" -mindepth 2 -name '*.yar' -print -quit)" ]; then
  echo "discarding a previous flat extraction"
  rm -rf "$SRC"
fi
if [ ! -d "$SRC" ] || [ -z "$(ls -A "$SRC" 2>/dev/null)" ]; then
  echo "fetching the Yara-Rules collection..."
  TAR="$OPT/yara-rules.tar.gz"
  fetch "https://github.com/Yara-Rules/rules/archive/refs/heads/master.tar.gz" "$TAR" || {
    echo "download failed -- does this node reach github.com?"; exit 1; }

  mkdir -p "$SRC"
  for theme in $THEMES; do
    # --strip-components=1 removes the version-named top directory GitHub adds, and
    # nothing more: the theme directory must survive, because a rule's theme is read
    # from its parent directory name and that grouping is the whole point
    tar -xzf "$TAR" -C "$SRC" --strip-components=1 --wildcards "*/$theme/*.yar" 2>/dev/null \
      || echo "  (nothing extracted for theme '$theme')"
  done
  rm -f "$TAR"
fi

n_files=$(find "$SRC" -name '*.yar' | wc -l)
echo "rule files : $n_files in $SRC"
[ "$n_files" -gt 0 ] || { echo "no rule file was extracted -- stopping"; exit 1; }

# ---------------------------------------------------------------------------
# 3. compile, and say what did not compile
# ---------------------------------------------------------------------------
python "$HERE/../compile_yara_rules.py" --src "$SRC" --out "$YARA_DIR" || exit 1

# ---------------------------------------------------------------------------
# 4. make it findable
# ---------------------------------------------------------------------------
if [ -f "$PROJECT/env.sh" ] && ! grep -q "YARA_RULES_DIR" "$PROJECT/env.sh"; then
  cat >> "$PROJECT/env.sh" <<ENV

# added by install_yara_rules.sh
export YARA_RULES_DIR="$YARA_DIR"
ENV
  echo "env file   : updated $PROJECT/env.sh"
fi

echo
echo "files in home now: $(find "$HOME" -xdev -type f 2>/dev/null | wc -l)"
