#!/usr/bin/env bash
#
# Synthetic regression suite for the XenonRecomp hardening fixes.
#
# Generates pathological-but-valid XEX images with gen_xex.py and verifies
# that every case either:
#   * completes successfully, or
#   * exits non-zero with a clear ERROR message.
# Nothing may segfault, abort, terminate (std::bad_alloc) or hang.
#
# Usage: tests/synthetic/run_tests.sh
# Requires the project to be built (build/XenonRecomp, build/XenonAnalyse).

set -u
cd "$(dirname "$0")"

ROOT=../..
RECOMP="$ROOT/build/XenonRecomp/XenonRecomp"
ANALYSE="$ROOT/build/XenonAnalyse/XenonAnalyse"
HEADER="$ROOT/XenonUtils/ppc_context.h"
ZIG_CXX="${ZIG_CXX:-zig-clang++}"
TIMEOUT_SECS="${TIMEOUT_SECS:-120}"

PASS=0
FAIL=0
FAILED=()

note() { echo "$@"; }

check() { # check <name> <condition-result(0/1)> <detail>
    local name="$1" cond="$2" detail="$3"
    if [ "$cond" -eq 0 ]; then
        PASS=$((PASS + 1))
        note "  [PASS] $name"
    else
        FAIL=$((FAIL + 1))
        FAILED+=("$name: $detail")
        note "  [FAIL] $name ($detail)"
    fi
}

crash_scan() { # crash_scan <log> -> echoes 0 if clean, 1 if crash markers found
    if grep -qE "Segmentation fault|core dumped|terminate called|std::bad_alloc|Aborted" "$1"; then
        echo 1
    else
        echo 0
    fi
}

if [ ! -x "$RECOMP" ] || [ ! -x "$ANALYSE" ]; then
    echo "ERROR: Build the project first (build/XenonRecomp/XenonRecomp and build/XenonAnalyse/XenonAnalyse must exist)."
    exit 1
fi

# Regenerate test cases so the suite always matches gen_xex.py.
note "=== Regenerating synthetic XEX cases ==="
mkdir -p out
: > out/gen.log
gen() { python3 gen_xex.py "$@" >> out/gen.log 2>&1; }
gen cases/valid.xex --symbols out/symbols.txt &&
gen cases/no_pdata.xex --no-pdata &&
gen cases/zero_fnlen.xex --zero-fnlen &&
gen cases/huge_imagesize.xex --huge-imagesize &&
gen cases/truncated_encrypted.xex --truncated --encrypted &&
gen cases/delta.xex --delta &&
gen cases/basic.xex --basic
check "gen_xex.py cases" $? "see out/gen.log"

if [ ! -f cases/garbage.bin ]; then
    head -c 65536 /dev/urandom > cases/garbage.bin
fi

rm -rf out/ppc_* out/switch_tables.toml out/*.case.log

# ---------------------------------------------------------------------------
note ""
note "=== XenonAnalyse on valid.xex ==="
timeout "$TIMEOUT_SECS" "$ANALYSE" cases/valid.xex out/switch_tables.toml > out/analyse.log 2>&1
rc=$?
check "XenonAnalyse exits 0" $([ $rc -eq 0 ]; echo $?) "exit code $rc"
check "XenonAnalyse no crash" "$(crash_scan out/analyse.log)" "crash markers in out/analyse.log"
if grep -q "Found 1 jump table" out/analyse.log; then tables=0; else tables=1; fi
check "XenonAnalyse found the jump table" $tables "output: $(tail -1 out/analyse.log)"

note ""
note "=== XenonAnalyse on garbage.bin ==="
timeout "$TIMEOUT_SECS" "$ANALYSE" cases/garbage.bin out/garbage_tables.toml > out/analyse_garbage.log 2>&1
rc=$?
check "XenonAnalyse rejects garbage" $([ $rc -ne 0 ] && [ $rc -lt 128 ]; echo $?) "exit code $rc"
check "XenonAnalyse garbage no crash" "$(crash_scan out/analyse_garbage.log)" "crash markers in log"
rm -f out/garbage_tables.toml

# ---------------------------------------------------------------------------
run_ok_case() { # run_ok_case <name> <config> [extra grep pattern] [tolerate_switch]
    local name="$1" config="$2" pattern="${3:-}" tolerate="${4:-}"
    local log="out/${name}.case.log"
    note ""
    note "=== $name (expect: success) ==="
    timeout "$TIMEOUT_SECS" "$RECOMP" "$config" "$HEADER" > "$log" 2>&1
    local rc=$?
    check "$name exits 0" $([ $rc -eq 0 ]; echo $?) "exit code $rc (see $log)"
    check "$name no crash" "$(crash_scan "$log")" "crash markers in $log"
    if [ "$tolerate" = "tolerate_switch" ]; then
        # Images without .pdata derive function boundaries from static
        # analysis, which cannot know that jump table case bodies belong to
        # the switching function. That diagnostic is expected there.
        local bad_err
        bad_err=$(grep "ERROR" "$log" | grep -vc "trying to jump outside function")
        check "$name no unexpected ERROR" $([ "$bad_err" -eq 0 ]; echo $?) "$bad_err unexpected ERROR lines in $log"
    else
        check "$name no ERROR" $(! grep -q "ERROR" "$log"; echo $?) "ERROR lines in $log"
    fi
    if [ -n "$pattern" ]; then
        check "$name expected message" $(grep -q "$pattern" "$log"; echo $?) "missing pattern '$pattern' in $log"
    fi
}

run_err_case() { # run_err_case <name> <config>
    local name="$1" config="$2"
    local log="out/${name}.case.log"
    note ""
    note "=== $name (expect: clean error) ==="
    timeout "$TIMEOUT_SECS" "$RECOMP" "$config" "$HEADER" > "$log" 2>&1
    local rc=$?
    check "$name exits non-zero" $([ $rc -ne 0 ]; echo $?) "exit code $rc (see $log)"
    check "$name no crash" "$(crash_scan "$log")" "crash markers in $log"
    check "$name no hang" $([ $rc -ne 124 ]; echo $?) "timed out after ${TIMEOUT_SECS}s"
    check "$name prints ERROR" $(grep -q "ERROR" "$log"; echo $?) "no ERROR message in $log"
}

run_ok_case valid          configs/valid.toml
run_ok_case autodetect     configs/autodetect.toml      "Auto-detected"
run_ok_case no_pdata       configs/no_pdata.toml        "No .pdata"           tolerate_switch
run_ok_case zero_fnlen     configs/zero_fnlen.toml
run_ok_case basic          configs/basic.toml
run_ok_case out_dir_missing configs/out_dir_missing.toml

run_err_case delta              configs/delta.toml
run_err_case huge_imagesize     configs/huge_imagesize.toml
run_err_case truncated          configs/truncated.toml
run_err_case garbage            configs/garbage.toml
run_err_case missing            configs/missing.toml

# ---------------------------------------------------------------------------
# Auto-detection must find all 8 CRT helpers without config addresses.
note ""
note "=== CRT helper auto-detection ==="
detected=$(grep -c "Auto-detected" out/autodetect.case.log || true)
check "all 8 helpers auto-detected" $([ "$detected" -eq 8 ]; echo $?) "found $detected/8 in out/autodetect.case.log"
for h in __restgprlr_14 __savegprlr_14 __restfpr_14 __savefpr_14 __restvmx_14 __savevmx_14 __restvmx_64 __savevmx_64; do
    check "auto-detected $h" $(grep -q "$h" out/autodetect.case.log; echo $?) "not detected"
done

# Detected addresses must match the ones from the explicit config.
missing_addr=0
while read -r addr; do
    grep -qi "$addr" out/autodetect.case.log || missing_addr=1
done < <(grep -oE "0x[0-9A-Fa-f]+" configs/valid.toml | sort -u)
check "detected addresses match config" $missing_addr "some config addresses were not auto-detected"

# ---------------------------------------------------------------------------
# The generated C++ must compile (valid + autodetect outputs).
note ""
note "=== Compile generated C++ ==="
: > out/compile.log
if command -v "$ZIG_CXX" > /dev/null 2>&1; then
    for dir in out/ppc_valid out/ppc_autodetect out/ppc_no_pdata; do
        [ -d "$dir" ] || { check "compile $dir" 1 "directory missing"; continue; }
        compiled=1
        for f in "$dir"/ppc_recomp.*.cpp "$dir"/ppc_func_mapping.cpp; do
            [ -f "$f" ] || continue
            if ! "$ZIG_CXX" -std=c++17 -c "$f" -o /tmp/xenon_recomp_compile_test.o \
                -I "$dir" -I "$ROOT/XenonUtils" -I "$ROOT/thirdparty/simde" \
                -msse4.1 >> out/compile.log 2>&1; then
                compiled=0
            fi
        done
        rm -f /tmp/xenon_recomp_compile_test.o
        check "compile $dir" $((1 - compiled)) "see out/compile.log"
    done
else
    note "  [SKIP] $ZIG_CXX not found, skipping compile checks"
fi

# ---------------------------------------------------------------------------
note ""
note "========================================"
note " PASSED: $PASS   FAILED: $FAIL"
if [ "$FAIL" -ne 0 ]; then
    note ""
    note " Failed checks:"
    for f in "${FAILED[@]}"; do note "  - $f"; done
    exit 1
fi
note " All checks passed."
exit 0
