#!/usr/bin/env bash
# Build Manalyze on an HPC account with no compiler, no CMake, no Boost and no root.
#
#   export PROJECT=$HOME/malware_pipeline/env
#   bash Code/hpc/install_manalyze.sh
#
# Manalyze is the one detector in this pipeline that is not a Python package: it is C++
# and has to be compiled. On a cluster account that normally stops you dead, because
# Boost is not installed and you cannot apt-get it. conda-forge solves it -- it ships a
# complete toolchain as ordinary user-space files, which micromamba can unpack anywhere.
#
# Why bother, when PyPackerDetect already covers the structural heuristics: because two
# independent implementations agreeing is evidence, while one implementation run twice
# is not. Manalyze is a separate codebase with its own thresholds, so its agreement with
# PyPackerDetect carries information that a second signature database would not.
#
# Roughly 400 MB of toolchain and ten minutes of compiling. Both are one-offs.

set -uo pipefail

PROJECT="${PROJECT:-$HOME/malware_pipeline/env}"
OPT="$PROJECT/opt"
BUILD_ENV="$OPT/buildenv"          # the toolchain, only needed to compile
SRC="$OPT/Manalyze"
MAMBA="$OPT/bin/micromamba"

mkdir -p "$OPT/bin"
echo "building Manalyze under $OPT"

# ---------------------------------------------------------------------------
# 0. a download helper -- this cluster has wget but not curl
# ---------------------------------------------------------------------------
fetch() {           # fetch URL DEST
  local url="$1" dest="$2"
  command -v curl >/dev/null 2>&1 && curl -fsSL -o "$dest" "$url" && [ -s "$dest" ] && return 0
  command -v wget >/dev/null 2>&1 && wget -q -O "$dest" "$url" && [ -s "$dest" ] && return 0
  python3 - "$url" "$dest" <<'PYFETCH' && [ -s "$dest" ] && return 0
import sys, urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=300) as r, open(sys.argv[2], "wb") as fh:
    fh.write(r.read())
PYFETCH
  return 1
}

# ---------------------------------------------------------------------------
# 1. micromamba
# ---------------------------------------------------------------------------
if [ ! -x "$MAMBA" ]; then
  echo "fetching micromamba..."
  fetch https://micro.mamba.pm/api/micromamba/linux-64/latest "$OPT/micromamba.tar.bz2" \
    && tar -xjf "$OPT/micromamba.tar.bz2" -C "$OPT" bin/micromamba \
    && rm -f "$OPT/micromamba.tar.bz2"
fi
[ -x "$MAMBA" ] || { echo "micromamba could not be installed -- stopping"; exit 1; }
export MAMBA_ROOT_PREFIX="$OPT/mamba"

# ---------------------------------------------------------------------------
# 2. the toolchain
# ---------------------------------------------------------------------------
# libboost-devel is the current conda-forge name; boost-cpp was the old one. Which is
# available depends on when the channel snapshot was taken, so both are tried.
if [ ! -x "$BUILD_ENV/bin/cmake" ]; then
  echo "installing compiler, cmake and boost (about 400 MB)..."
  "$MAMBA" create -y -q -p "$BUILD_ENV" -c conda-forge \
      cxx-compiler c-compiler cmake make libboost-devel openssl \
    || "$MAMBA" create -y -q -p "$BUILD_ENV" -c conda-forge \
      cxx-compiler c-compiler cmake make boost-cpp openssl \
    || { echo "conda-forge toolchain could not be installed"; exit 1; }
fi

export PATH="$BUILD_ENV/bin:$PATH"
export CC="$(ls "$BUILD_ENV"/bin/*-linux-gnu-gcc 2>/dev/null | head -1)"
export CXX="$(ls "$BUILD_ENV"/bin/*-linux-gnu-g++ 2>/dev/null | head -1)"
[ -x "${CC:-}" ] || CC="$BUILD_ENV/bin/gcc"
[ -x "${CXX:-}" ] || CXX="$BUILD_ENV/bin/g++"
echo "compiler   : $($CXX --version 2>/dev/null | head -1)"
echo "cmake      : $(cmake --version 2>/dev/null | head -1)"

# ---------------------------------------------------------------------------
# 3. source
# ---------------------------------------------------------------------------
if [ ! -d "$SRC/.git" ]; then
  echo "cloning Manalyze..."
  git clone --quiet --recursive https://github.com/JusticeRage/Manalyze.git "$SRC" \
    || { echo "clone failed -- does this node reach github.com?"; exit 1; }
else
  ( cd "$SRC" && git pull --quiet --recurse-submodules ) || true
fi

# ---------------------------------------------------------------------------
# 4. build
# ---------------------------------------------------------------------------
# BOOST_ROOT is not optional here: CMake looks in the system paths first and there is
# no Boost there at all, so without the hint it fails with a message about a missing
# system package that you have no way of installing.
# Manalyze clones its own submodules (yara, hash-library) during configuration and puts
# them relative to the working directory. Configuring from a build/ subdirectory drops
# them one level too deep, and add_subdirectory then cannot find them. So this is an
# in-source build -- which is what upstream documents anyway.
cd "$SRC"
rm -rf build
cmake . \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DBOOST_ROOT="$BUILD_ENV" \
  -DBoost_NO_SYSTEM_PATHS=ON \
  -DOPENSSL_ROOT_DIR="$BUILD_ENV" \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  > "$OPT/manalyze_cmake.log" 2>&1 || {
    echo "cmake failed -- last 25 lines:"; tail -25 "$OPT/manalyze_cmake.log"; exit 1; }

echo "compiling (several minutes)..."
make -j"$(nproc 2>/dev/null || echo 4)" > "$OPT/manalyze_make.log" 2>&1 || {
    echo "make failed -- last 30 lines:"; tail -30 "$OPT/manalyze_make.log"; exit 1; }

BIN="$(find "$SRC" -maxdepth 3 -type f -name manalyze -perm -u+x | head -1)"
[ -n "$BIN" ] || { echo "built, but the manalyze binary was not found"; exit 1; }

# The binary was linked against conda's libstdc++, which the system does not have, so
# its directory has to be on LD_LIBRARY_PATH at run time as well as at build time.
mkdir -p "$OPT/bin"
cat > "$OPT/bin/manalyze" <<WRAP
#!/usr/bin/env bash
# generated by install_manalyze.sh -- keeps the conda runtime libraries reachable
export LD_LIBRARY_PATH="$BUILD_ENV/lib:\${LD_LIBRARY_PATH:-}"
exec "$BIN" "\$@"
WRAP
chmod +x "$OPT/bin/manalyze"

echo
echo "manalyze   : $OPT/bin/manalyze"
"$OPT/bin/manalyze" --version 2>&1 | head -3

# ---------------------------------------------------------------------------
# 5. make it visible to every job
# ---------------------------------------------------------------------------
if [ -f "$PROJECT/env.sh" ] && ! grep -q "MANALYZE_CMD" "$PROJECT/env.sh"; then
  cat >> "$PROJECT/env.sh" <<ENV

# added by install_manalyze.sh
export MANALYZE_CMD="$OPT/bin/manalyze"
export MANALYZE_HOME="$SRC"
ENV
  echo "env file   : updated $PROJECT/env.sh"
fi

echo
echo "next:  source $PROJECT/env.sh"
