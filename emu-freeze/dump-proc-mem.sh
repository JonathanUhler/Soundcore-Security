#!/usr/bin/env bash
# Dump a (stopped) process's readable memory regions to ./dumps for carving.
# Regions are page aligned in /proc/<pid>/maps, so a plain page-granular dd is
# exact and each dumped region is virtually contiguous, which is what lets the
# carver validate the dex hashes.
#
# Usage: ./dump-proc-mem.sh <pid> [--dalvik-only]
set -uo pipefail
cd "$(dirname "$0")"
source ./common.sh

PID="${1:?usage: dump-proc-mem.sh <pid> [--dalvik-only]}"
DALVIK_ONLY=false
[ "${2:-}" = "--dalvik-only" ] && DALVIK_ONLY=true

mkdir -p dumps
echo "[*] freezing pid $PID and reading its map"
sh_root "kill -STOP $PID" || true
sh_root "cat /proc/$PID/maps" | tr -d '\r' > dumps/maps.txt
echo "[*] $(wc -l < dumps/maps.txt) mappings"

n=0
while read -r range perms _off _dev _inode path; do
  [ "${perms:0:1}" = "r" ] || continue
  # skip real device-backed maps, but keep dalvik ashmem on old images
  case "$path" in
    /dev/*) echo "$path" | grep -qi dalvik || continue ;;
  esac
  if $DALVIK_ONLY; then
    echo "${path:-}" | grep -qiE 'dalvik|dex|InMemoryDex|Anonymous-DexFile' || continue
  fi
  start=${range%-*}; end=${range#*-}
  s=$((16#$start)); e=$((16#$end)); len=$((e - s))
  [ "$len" -gt 0 ] || continue
  skip=$((s / 4096)); cnt=$((len / 4096))
  [ "$cnt" -gt 0 ] || continue
  out="dumps/region_${start}.bin"
  raw_root "dd if=/proc/$PID/mem bs=4096 skip=$skip count=$cnt 2>/dev/null" > "$out"
  if [ -s "$out" ]; then
    n=$((n + 1))
  else
    rm -f "$out"
  fi
done < dumps/maps.txt

echo "[+] dumped $n regions to ./dumps"
echo "[*] carve with:"
echo "    python3 carve_dex.py dumps/*.bin --out carved"
echo "[i] the app is still STOPPED. Resume with: adb shell su -c 'kill -CONT $PID'"
echo "    or end it with: adb shell su -c 'kill -KILL $PID'"
