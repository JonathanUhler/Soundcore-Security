#!/usr/bin/env bash
# Run in a second terminal alongside `MODE=freeze ... ./freeze.sh`. It launches
# the app and continuously snapshots /proc/<pid>/maps to a file while the app is
# alive, so that when freeze.sh halts the VM at the suicide, the latest maps
# (with the in-memory dex's virtual address) is on disk for the gdb-side dump.
#
# Usage: ./grab-maps.sh [maps_out_file]   (default maps.txt)
set -uo pipefail
cd "$(dirname "$0")"
source ./common.sh

OUT="${1:-maps.txt}"
# Do NOT force-stop here: killing a stale instance would trip freeze.sh on the
# old pid. Force-stop once, before arming freeze.sh (see the workflow in README).
echo "[*] launching $PKG (make sure freeze.sh is already armed)"
$ADB $SER shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1 || true

pid=""
while [ -z "$pid" ]; do pid=$(sh_root "pidof $PKG" | tr -d '\r' | awk '{print $1}'); done
echo "[*] pid=$pid; snapshotting maps to $OUT until the VM freezes (Ctrl-C to stop)"

seen_dex=0
while :; do
  m=$(sh_root "cat /proc/$pid/maps" 2>/dev/null | tr -d '\r')
  [ -z "$m" ] && { echo "[*] pid gone/frozen; last good maps left in $OUT"; break; }
  printf '%s\n' "$m" > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"
  if [ "$seen_dex" = 0 ] && printf '%s' "$m" | grep -qiE 'dalvik-.*dex|InMemoryDex|Anonymous-?Dex'; then
    seen_dex=1
    echo "[+] in-memory dex now mapped and captured in $OUT"
  fi
done
