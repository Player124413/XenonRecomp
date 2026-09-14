#!/usr/bin/env bash
#
# Sonic Generations recompilation script (Linux/macOS).
#
# Place your decrypted "default.xex" next to this script, then run it.
# Output: generated C++ sources in ./ppc/
#
set -e
cd "$(dirname "$0")"

ROOT=..
BUILD="$ROOT/build"

# --- Build the tools if they are missing ------------------------------------
if [ ! -x "$BUILD/XenonRecomp/XenonRecomp" ] || [ ! -x "$BUILD/XenonAnalyse/XenonAnalyse" ]; then
    echo "XenonRecomp binaries not found, building them (requires CMake + Clang)..."
    if ! command -v cmake > /dev/null 2>&1; then
        echo "ERROR: cmake is not installed."
        exit 1
    fi
    GENERATOR=()
    if command -v ninja > /dev/null 2>&1; then
        GENERATOR=(-G Ninja)
    fi
    JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    cmake -S "$ROOT" -B "$BUILD" "${GENERATOR[@]}" -DCMAKE_BUILD_TYPE=Release
    cmake --build "$BUILD" -j"$JOBS"
fi

# --- Input check -------------------------------------------------------------
XEX=default.xex
if [ ! -f "$XEX" ]; then
    echo "ERROR: Place your decrypted Sonic Generations 'default.xex' into this folder first."
    echo "       See README.md in this folder for details (the file must be DECRYPTED)."
    exit 1
fi

# --- Step 1: jump table detection -------------------------------------------
echo ""
echo "=== Step 1/2: Detecting jump tables (XenonAnalyse) ==="
"$BUILD/XenonAnalyse/XenonAnalyse" "$XEX" switch_tables.toml

# --- Step 2: recompilation ---------------------------------------------------
echo ""
echo "=== Step 2/2: Recompiling to C++ (XenonRecomp) ==="
"$BUILD/XenonRecomp/XenonRecomp" config.toml "$ROOT/XenonUtils/ppc_context.h"

echo ""
echo "Done! The generated C++ sources are in SonicGenerations/ppc/"
echo "See README.md for what to do next (you need a runtime to actually play)."
