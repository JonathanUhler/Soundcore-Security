#!/usr/bin/env bash
# Strategy 2 driver. Connects host gdb to the emulator's QEMU gdbstub and traps
# the app's suicide syscalls (kill, tkill, tgkill, and optionally exit_group),
# neutering the signal ones so the app stays alive for a /proc/mem dump.
#
# Addresses are auto-resolved from kallsyms.txt (run find-kill-symbol.sh first).
# KILL_ADDR etc. can be overridden from the environment. KASLR moves these every
# boot, so re-pull kallsyms after each emulator restart.
#
# Usage: ./freeze.sh                          (neuter, app_pid unset)
#        APP_PID=1234 ./freeze.sh             (only act on the app)
#        MODE=freeze ./freeze.sh              (halt the VM at the kill instead)
#        TRAP_EXITGROUP=1 ./freeze.sh         (also trap exit_group; noisy)
set -uo pipefail
cd "$(dirname "$0")"

export GDB_REMOTE="${GDB_REMOTE:-127.0.0.1:${GDB_PORT:-1234}}"
export MODE="${MODE:-neuter}"
export ARCH="${ARCH:-x86_64}"
[ -n "${APP_PID:-}" ] && export APP_PID

KALLSYMS="${KALLSYMS:-kallsyms.txt}"
case "$ARCH" in aarch64) P=__arm64_sys_ ;; *) P=__x64_sys_ ;; esac
kaddr() { awk -v s="${P}$1" '$3==s{print "0x"$1; exit}' "$KALLSYMS" 2>/dev/null; }

: "${KILL_ADDR:=$(kaddr kill)}"
: "${TGKILL_ADDR:=$(kaddr tgkill)}"
: "${TKILL_ADDR:=$(kaddr tkill)}"
: "${RTSIG_ADDR:=$(kaddr rt_sigqueueinfo)}"
: "${RTTGSIG_ADDR:=$(kaddr rt_tgsigqueueinfo)}"
: "${EXITGROUP_ADDR:=$(kaddr exit_group)}"
: "${EXIT_ADDR:=$(kaddr exit)}"
export KILL_ADDR TGKILL_ADDR TKILL_ADDR RTSIG_ADDR RTTGSIG_ADDR EXITGROUP_ADDR EXIT_ADDR

if [ -z "${KILL_ADDR}${TGKILL_ADDR}${TKILL_ADDR}" ]; then
  echo "no syscall addresses found. Run ./find-kill-symbol.sh (writes $KALLSYMS) first,"
  echo "or pass KILL_ADDR=0x... explicitly."
  exit 1
fi

GDB_BIN="$(command -v gdb-multiarch || command -v gdb || true)"
[ -n "$GDB_BIN" ] || { echo "install gdb (or gdb-multiarch for a cross-arch guest)"; exit 1; }

echo "[*] $GDB_BIN -> $GDB_REMOTE  mode=$MODE"
echo "    kill=$KILL_ADDR tgkill=$TGKILL_ADDR tkill=$TKILL_ADDR"
echo "    rt_sigqueueinfo=$RTSIG_ADDR rt_tgsigqueueinfo=$RTTGSIG_ADDR"
echo "    exit_group=$EXITGROUP_ADDR exit=$EXIT_ADDR"
exec "$GDB_BIN" -q -nx -ex "source freeze_gdb.py"
