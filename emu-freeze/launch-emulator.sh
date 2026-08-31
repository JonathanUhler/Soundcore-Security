#!/usr/bin/env bash
# Strategy 2 only. Launch the AVD with QEMU's gdb stub (and an optional monitor)
# exposed to the host. The stub sits OUTSIDE the guest, below the OS, so the
# ijiami anti-Frida (libexec.so), anti-Xposed/anti-debug (drisk), and
# anti-emulator (libijm-emulator) layers cannot observe it. Strategy 1 does not
# need this script.
#
# Usage: ./launch-emulator.sh <avd_name>
#        GDB_PORT=1234 MON_PORT=55555 ./launch-emulator.sh Pixel_API34
set -euo pipefail
AVD="${1:-${AVD:?set AVD or pass the avd name}}"
GDB_PORT="${GDB_PORT:-1234}"
MON_PORT="${MON_PORT:-55555}"
EMULATOR="${EMULATOR:-emulator}"

echo "[*] launching $AVD   gdbstub=tcp:$GDB_PORT   monitor=tcp:$MON_PORT"
echo "[i] a native arm64-v8a system image avoids the ARM-translation tell that"
echo "    libijm-emulator can fingerprint on an x86_64 + translation image."
exec "$EMULATOR" -avd "$AVD" -no-snapshot-load -writable-system \
  -qemu -gdb "tcp::${GDB_PORT}" \
  -monitor "telnet:127.0.0.1:${MON_PORT},server,nowait"
