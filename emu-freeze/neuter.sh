#!/usr/bin/env bash
# One-command "keep the app alive past its emulator suicide" experiment.
#
# The prior neuter (freeze.sh MODE=neuter) rewrote the signal of kill/tkill/
# tgkill to 0, yet the app still died. This driver widens the intercept to every
# process-death path -- pidfd_send_signal and voluntary exit_group as well as the
# signal syscalls -- and adds a do_group_exit tripwire that reports HOW the app
# died when something still gets through. All of it runs on QEMU's gdbstub, below
# the guest, so no in-guest anti-tamper layer can see it.
#
# It drives the whole flow itself: pulls a fresh kallsyms (KASLR moves the
# addresses every boot), resolves the kernel symbols, arms gdb, then (re)launches
# the app so it walks into the already-armed traps.
#
# Prereq: ./launch-emulator.sh <avd> is running (gdbstub + monitor exposed) and
#         the AVD is rooted (needed only to read kallsyms).
#
# Usage:
#   ./neuter.sh                 # neuter mode, auto-relaunch the app
#   MODE=diagnose ./neuter.sh   # block nothing; just report the death vector used
#   APP_PIDS=1234,1240 ./neuter.sh   # scope the neuter to these pids
#   ALL=1 ./neuter.sh           # neuter every process but init (most robust vs re-exec)
#   NO_LAUNCH=1 ./neuter.sh     # do not touch the app; arm and wait
#   NEUTER_EXIT=1 ./neuter.sh   # also skip single-thread exit()
#
# Recommended first run when the app keeps dying: MODE=diagnose ./neuter.sh
# It prints the exact vector (e.g. "killed by SIGNAL 11" = a deliberate fault, or
# "clean exit" = an exit_group path), which tells you what to neuter next.
set -uo pipefail
cd "$(dirname "$0")"
source ./common.sh

export GDB_REMOTE="${GDB_REMOTE:-127.0.0.1:${GDB_PORT:-1234}}"
export ARCH="${ARCH:-x86_64}"
export MODE="${MODE:-neuter}"
export WINDOW="${WINDOW:-30}"
[ -n "${APP_PIDS:-}" ] && export APP_PIDS
[ -n "${ALL:-}" ] && export ALL
[ -n "${NEUTER_EXIT:-}" ] && export NEUTER_EXIT
[ -n "${EXITGROUP_ALWAYS:-}" ] && export EXITGROUP_ALWAYS
[ -n "${DEBUG:-}" ] && export DEBUG

KALLSYMS="${KALLSYMS:-kallsyms.txt}"
LAUNCH_DELAY="${LAUNCH_DELAY:-3}"

# --- 1. Fresh kallsyms. KASLR relocates every boot, so a stale table silently
#        breakpoints the wrong addresses. Re-pull unless REUSE_KALLSYMS is set.
if [ -z "${REUSE_KALLSYMS:-}" ] || [ ! -s "$KALLSYMS" ]; then
  echo "[*] pulling fresh kallsyms (relaxing kptr_restrict first)"
  sh_root "echo 0 > /proc/sys/kernel/kptr_restrict" >/dev/null 2>&1 || true
  sh_root "cat /proc/kallsyms" | tr -d '\r' > "$KALLSYMS"
  echo "[*] $(wc -l < "$KALLSYMS" | tr -d ' ') symbols -> $KALLSYMS"
fi

# --- 2. Resolve the guest-kernel addresses. Syscall wrappers are prefixed
#        __x64_sys_/__arm64_sys_; do_group_exit is a bare symbol.
case "$ARCH" in aarch64) P=__arm64_sys_ ;; *) P=__x64_sys_ ;; esac
kaddr() { awk -v s="${P}$1" '$3==s{print "0x"$1; exit}' "$KALLSYMS" 2>/dev/null; }
kbare() { awk -v s="$1"      '$3==s{print "0x"$1; exit}' "$KALLSYMS" 2>/dev/null; }

export KILL_ADDR="${KILL_ADDR:-$(kaddr kill)}"
export TKILL_ADDR="${TKILL_ADDR:-$(kaddr tkill)}"
export TGKILL_ADDR="${TGKILL_ADDR:-$(kaddr tgkill)}"
export RTSIG_ADDR="${RTSIG_ADDR:-$(kaddr rt_sigqueueinfo)}"
export RTTGSIG_ADDR="${RTTGSIG_ADDR:-$(kaddr rt_tgsigqueueinfo)}"
export PIDFD_ADDR="${PIDFD_ADDR:-$(kaddr pidfd_send_signal)}"
export EXITGROUP_ADDR="${EXITGROUP_ADDR:-$(kaddr exit_group)}"
export EXIT_ADDR="${EXIT_ADDR:-$(kaddr exit)}"
export DOGROUPEXIT_ADDR="${DOGROUPEXIT_ADDR:-$(kbare do_group_exit)}"

if [ -z "${KILL_ADDR}${TGKILL_ADDR}${TKILL_ADDR}" ]; then
  echo "no kill syscall addresses in $KALLSYMS. Is the AVD rooted and kptr_restrict=0?"
  echo "Re-run after: ./launch-emulator.sh <avd>   (and confirm 'su' works)."
  exit 1
fi

echo "[*] addresses:"
echo "    kill=$KILL_ADDR tkill=$TKILL_ADDR tgkill=$TGKILL_ADDR"
echo "    rt_sigqueueinfo=$RTSIG_ADDR rt_tgsigqueueinfo=$RTTGSIG_ADDR pidfd_send_signal=${PIDFD_ADDR:-<none>}"
echo "    exit_group=$EXITGROUP_ADDR exit=$EXIT_ADDR do_group_exit=${DOGROUPEXIT_ADDR:-<none>}"

# --- 3. Scope. Neutering fatal signals guest-wide (ALL-but-init) reboots the
#        AVD: it starves system_server/zygote, and the platform restarts. So the
#        default scopes strictly to the Soundcore process tree, tracked LIVE by a
#        background poller writing pids to a file. That follows the ijiami
#        watchdog re-exec to a new pid without pinning a stale one, and touches
#        nothing else in the guest. APP_PIDS=... pins a static set; ALL=1 opts
#        back into the broad (reboot-prone) behaviour.
POLLER=""
if [ -n "${ALL:-}" ]; then
  echo "[!] ALL=1: neutering every process but init. This can reboot the AVD by"
  echo "    starving system_server/zygote. Prefer the default app-scoped mode."
elif [ -n "${APP_PIDS:-}" ]; then
  echo "[*] scoping to static pids: $APP_PIDS  (note: will NOT follow a re-exec)"
else
  PIDS_FILE="${PIDS_FILE:-$PWD/.neuter_pids}"
  export APP_PIDS_FILE="$PIDS_FILE"
  : > "$PIDS_FILE"
  # One guest command per tick (pidof plus a ps grep for :remote / re-exec'd
  # procs), so the poller spawns few short-lived guest processes -- each of those
  # exits via exit_group, which the death traps watch during the suicide window.
  POLL_INT="${POLL_INT:-0.5}"
  (
    while :; do
      sh_root "pidof $PKG; ps -A -o PID,NAME 2>/dev/null | grep oceanwing.soundcore | awk '{print \$1}'" 2>/dev/null \
        | tr ' \r' '\n\n' | grep -E '^[0-9]+$' | sort -un > "$PIDS_FILE.tmp" 2>/dev/null \
        && mv -f "$PIDS_FILE.tmp" "$PIDS_FILE" 2>/dev/null
      sleep "$POLL_INT"
    done
  ) &
  POLLER=$!
  trap '[ -n "$POLLER" ] && kill "$POLLER" 2>/dev/null; rm -f "$PIDS_FILE" "$PIDS_FILE.tmp"' EXIT
  echo "[*] app-scoped via live pid poller -> $PIDS_FILE (follows re-exec, no guest collateral)"
fi

# --- 4. Background a delayed (re)launch so gdb arms its traps first, then the
#        app starts and walks into them. Kernel breakpoints are global, so they
#        catch the app (and any re-exec) whenever it appears.
if [ -z "${NO_LAUNCH:-}" ]; then
  echo "[*] force-stopping $PKG; it will relaunch in ${LAUNCH_DELAY}s (after traps arm)"
  $ADB $SER shell "am force-stop $PKG" >/dev/null 2>&1 || true
  (
    sleep "$LAUNCH_DELAY"
    $ADB $SER shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1 || true
  ) &
fi

# --- 5. Hand off to gdb. Not exec'd, so the EXIT trap can stop the pid poller
#        when gdb quits.
GDB_BIN="$(command -v gdb-multiarch || command -v gdb || true)"
[ -n "$GDB_BIN" ] || { echo "install gdb (or gdb-multiarch for a cross-arch guest)"; exit 1; }
echo "[*] $GDB_BIN -> $GDB_REMOTE   mode=$MODE"
"$GDB_BIN" -q -nx -ex "source neuter_gdb.py"
