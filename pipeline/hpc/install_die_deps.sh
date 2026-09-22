#!/usr/bin/env bash
# Give Detect It Easy the Qt5 libraries it needs, without root.
#
#   cd ~/malware_pipeline && source env/env.sh
#   bash Code/hpc/install_die_deps.sh
#
# DIE ships as a .deb linked against Qt5, and this cluster has no Qt at all:
#
#   libQt5Core.so.5        not found
#   libQt5Concurrent.so.5  not found
#   libQt5Script.so.5      not found
#
# conda-forge cannot help here -- Qt dropped QtScript from the core distribution after
# 5.5, so `qt-main` has no libQt5Script. Debian still packages it, and `apt-get download`
# fetches a .deb without installing it and without asking for privileges. A .deb is an ar
# archive, so its contents can simply be unpacked into a directory of our own and put on
# LD_LIBRARY_PATH.
#
# Debian 13 renamed several of these in the 64-bit time_t transition, which is why the
# obvious names fail: libqt5core5a became libqt5core5t64. Both spellings are attempted.

set -uo pipefail

PROJECT="${PROJECT:-$HOME/malware_pipeline/env}"
OPT="$PROJECT/opt"
QT="$OPT/qt5"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

DIEC="${DIEC_CMD:-$OPT/die/usr/bin/diec}"
[ -x "$DIEC" ] || { echo "diec not found at $DIEC -- run setup_env.sh first"; exit 1; }

mkdir -p "$QT"

# The three DIE asks for, plus what Qt5Core itself pulls in. Listing the dependencies up
# front is faster than discovering them one failed launch at a time; anything not in the
# archive is skipped rather than treated as fatal.
PACKAGES="
libqt5core5t64 libqt5core5a
libqt5concurrent5t64 libqt5concurrent5
libqt5script5
libdouble-conversion3 libpcre2-16-0 libb2-1 libmd4c0 libzstd1
libicu76 libicu72 libicu74
libglib2.0-0t64 libglib2.0-0
"

echo "downloading Qt5 packages into $WORK"
cd "$WORK"
got=0
for pkg in $PACKAGES; do
  if apt-get download "$pkg" >/dev/null 2>&1; then
    echo "  ok      $pkg"
    got=$((got + 1))
  fi
done
[ "$got" -gt 0 ] || { echo "not one package could be downloaded -- is apt configured?"; exit 1; }

echo "unpacking $got packages"
for deb in "$WORK"/*.deb; do
  if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb -x "$deb" "$QT"
  else
    ( cd "$QT" && ar x "$deb" && tar xf data.tar.* && rm -f data.tar.* control.tar.* debian-binary )
  fi
done

# Debian spreads libraries over usr/lib/x86_64-linux-gnu and a few other places, so every
# directory that actually contains a .so is added rather than guessing one path.
LIBDIRS="$(find "$QT" -name '*.so*' -printf '%h\n' 2>/dev/null | sort -u | tr '\n' ':')"
[ -n "$LIBDIRS" ] || { echo "the packages unpacked but contain no shared library"; exit 1; }
export LD_LIBRARY_PATH="${LIBDIRS}${LD_LIBRARY_PATH:-}"

echo
echo "still missing:"
missing="$(ldd "$DIEC" 2>/dev/null | grep 'not found' || true)"
if [ -n "$missing" ]; then
  echo "$missing"
  echo
  echo "Add the packages providing those to PACKAGES above and re-run. To find one:"
  echo "  apt-cache search libNAME"
  exit 1
fi
echo "  (nothing)"

echo
echo "diec now says:"
"$DIEC" --version 2>&1 | head -3

# ---------------------------------------------------------------------------
# make it permanent
# ---------------------------------------------------------------------------
if [ -f "$PROJECT/env.sh" ] && ! grep -q "QT5_LIBS" "$PROJECT/env.sh"; then
  cat >> "$PROJECT/env.sh" <<ENV

# added by install_die_deps.sh -- Qt5 for Detect It Easy, unpacked from Debian .debs
export QT5_LIBS="$LIBDIRS"
export LD_LIBRARY_PATH="\$QT5_LIBS\${LD_LIBRARY_PATH:-}"
ENV
  echo
  echo "env file   : updated $PROJECT/env.sh"
fi

echo
echo "next:  source $PROJECT/env.sh  &&  \$DIEC_CMD --version"
