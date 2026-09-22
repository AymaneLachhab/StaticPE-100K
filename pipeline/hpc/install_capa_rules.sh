#!/usr/bin/env bash
# Give capa its rule set and its FLIRT signatures.
#
#   cd ~/malware_pipeline && source env/env.sh
#   bash Code/hpc/install_capa_rules.sh
#
# The flare-capa wheel on PyPI does not ship the rules. Run without them, capa prints
#
#   ERROR  capa: default embedded rules not found!
#   ERROR  capa: provide your own rule set via the `-r` option.
#
# and exits -- so every sample comes back with no capabilities, no ATT&CK and no MBC.
# The rules live in a separate repository, versioned in step with capa itself, and the
# FLIRT signatures used to recognise statically linked library code live in the capa
# repository under sigs/. Both are fetched here at the version of the installed capa,
# because a rule set from a different release can fail to parse.

set -uo pipefail

PROJECT="${PROJECT:-$HOME/malware_pipeline/env}"
OPT="$PROJECT/opt"
CAPA_DIR="$OPT/capa"

mkdir -p "$CAPA_DIR"

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

VERSION="$(capa --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
[ -n "$VERSION" ] || { echo "capa is not on PATH -- source env.sh first"; exit 1; }
echo "capa version : $VERSION"

# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------
if [ ! -d "$CAPA_DIR/rules" ] || [ -z "$(ls -A "$CAPA_DIR/rules" 2>/dev/null)" ]; then
  echo "fetching capa-rules..."
  ok=0
  # the matching tag first; master only as a fallback, since a mismatched rule set can
  # fail to parse against an older capa
  for ref in "v$VERSION" "master"; do
    if [ "$ref" = "master" ]; then
      url="https://github.com/mandiant/capa-rules/archive/refs/heads/master.tar.gz"
    else
      url="https://github.com/mandiant/capa-rules/archive/refs/tags/$ref.tar.gz"
    fi
    if fetch "$url" "$OPT/capa-rules.tar.gz"; then
      rm -rf "$CAPA_DIR/rules"; mkdir -p "$CAPA_DIR/rules"
      tar -xzf "$OPT/capa-rules.tar.gz" -C "$CAPA_DIR/rules" --strip-components=1 \
        && rm -f "$OPT/capa-rules.tar.gz" && { echo "  from $ref"; ok=1; break; }
    fi
  done
  [ "$ok" = 1 ] || { echo "could not download capa-rules"; exit 1; }
fi
n_rules="$(find "$CAPA_DIR/rules" -name '*.yml' | wc -l)"
echo "rules        : $n_rules in $CAPA_DIR/rules"

# ---------------------------------------------------------------------------
# FLIRT signatures -- optional, but without them capa mistakes library code for the
# program's own and reports capabilities the author never wrote
# ---------------------------------------------------------------------------
if [ ! -d "$CAPA_DIR/sigs" ] || [ -z "$(ls -A "$CAPA_DIR/sigs" 2>/dev/null)" ]; then
  echo "fetching FLIRT signatures..."
  for ref in "v$VERSION" "master"; do
    if [ "$ref" = "master" ]; then
      url="https://github.com/mandiant/capa/archive/refs/heads/master.tar.gz"
    else
      url="https://github.com/mandiant/capa/archive/refs/tags/$ref.tar.gz"
    fi
    if fetch "$url" "$OPT/capa-src.tar.gz"; then
      mkdir -p "$CAPA_DIR/sigs"
      tar -xzf "$OPT/capa-src.tar.gz" -C "$CAPA_DIR/sigs" --strip-components=2 \
          --wildcards "*/sigs/*" 2>/dev/null
      rm -f "$OPT/capa-src.tar.gz"
      [ -n "$(ls -A "$CAPA_DIR/sigs" 2>/dev/null)" ] && { echo "  from $ref"; break; }
    fi
  done
fi
n_sigs="$(ls -1 "$CAPA_DIR/sigs" 2>/dev/null | wc -l)"
echo "signatures   : $n_sigs in $CAPA_DIR/sigs"

# ---------------------------------------------------------------------------
# check it actually analyses something
# ---------------------------------------------------------------------------
echo
echo "test run:"
SIGS_ARG=""
[ "$n_sigs" -gt 0 ] && SIGS_ARG="-s $CAPA_DIR/sigs"
# capa on its own binary is not a meaningful sample, but it proves the rules load
capa -r "$CAPA_DIR/rules" $SIGS_ARG --color never "$(command -v capa)" 2>&1 | head -5

if [ -f "$PROJECT/env.sh" ] && ! grep -q "CAPA_RULES" "$PROJECT/env.sh"; then
  cat >> "$PROJECT/env.sh" <<ENV

# added by install_capa_rules.sh -- the pip wheel ships no rules
export CAPA_RULES="$CAPA_DIR/rules"
export CAPA_SIGS="$CAPA_DIR/sigs"
ENV
  echo
  echo "env file   : updated $PROJECT/env.sh"
fi

echo
echo "next:  source $PROJECT/env.sh"
