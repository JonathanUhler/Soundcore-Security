#!/usr/bin/env bash
# Shared config and root helpers for the emu-freeze pipeline. Sourced by the
# other scripts. Override any value from the environment.

ADB="${ADB:-adb}"
EMULATOR="${EMULATOR:-emulator}"
PKG="${PKG:-com.oceanwing.soundcore}"

# Target a specific device with EMU_SERIAL (maps to adb -s).
SER=""
[ -n "${EMU_SERIAL:-}" ] && SER="-s ${EMU_SERIAL}"

# Magisk root prefix. Some builds want "su 0" instead of "su -c".
SU="${SU:-su -c}"

# Run a command as root, text stdout.
sh_root() { $ADB $SER shell "$SU '$*'"; }

# Run a command as root, raw binary stdout (used for memory dumps).
raw_root() { $ADB $SER exec-out "$SU '$*'"; }

# Echo the main process pid for $PKG, waiting up to ~30s for it to appear.
get_pid() {
  local pid="" i=0
  while [ -z "$pid" ] && [ "$i" -lt 300 ]; do
    pid=$(sh_root "pidof $PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')
    [ -z "$pid" ] && { sleep 0.1; i=$((i + 1)); }
  done
  echo "$pid"
}
