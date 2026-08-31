#!/usr/bin/env bash
# Strategy 1 driver (passive). Pushes guest-grab.sh, cold-launches the app, runs
# the passive grabber, then extracts the dumped regions AS ROOT (adb pull runs as
# the unprivileged shell user and cannot read root-created files).
#
# Usage: ./passive-grab.sh              (uses PKG default)
#        PKG=com.oceanwing.soundcore ./passive-grab.sh
#        ./passive-grab.sh 40000        (max poll iterations)
set -uo pipefail
cd "$(dirname "$0")"
source ./common.sh

MAX="${1:-20000}"
REMOTE=/data/local/tmp/guest-grab.sh
OUT=/data/local/tmp/emu-freeze-dump

echo "[*] pushing passive grabber"
$ADB $SER push guest-grab.sh "$REMOTE" >/dev/null
sh_root "chmod 755 $REMOTE"

echo "[*] cold-launching $PKG"
sh_root "am force-stop $PKG" || true
$ADB $SER shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1 || true

echo "[*] running passive grab (no SIGSTOP during bootstrap) -- Ctrl-C to abort"
sh_root "sh $REMOTE $PKG $MAX"
rc=$?

echo "[*] extracting dumps as root"
rm -rf dumps/emu-freeze-dump
mkdir -p dumps/emu-freeze-dump
files=$(sh_root "ls $OUT/*.bin 2>/dev/null" | tr -d '\r')
n=0
for f in $files; do
  base=$(basename "$f")
  raw_root "cat $f" > "dumps/emu-freeze-dump/$base"
  if [ -s "dumps/emu-freeze-dump/$base" ]; then n=$((n + 1)); else rm -f "dumps/emu-freeze-dump/$base"; fi
done

echo
if [ "$n" -gt 0 ]; then
  echo "[+] extracted $n region dumps. Carve with:"
  echo "    python3 carve_dex.py dumps/emu-freeze-dump/*.bin --out carved"
elif [ "$rc" -eq 1 ]; then
  echo "[-] the app died before the dex was mapped (see grab output above)."
else
  echo "[-] the grabber wrote nothing readable. If it reported 'NOTHING dumped',"
  echo "    /proc/mem reads are SELinux-blocked: run 'adb shell su -c setenforce 0'"
  echo "    then rerun. Otherwise the app may release the app cgroup on freeze; try"
  echo "    the Strategy 2 neuter path, which keeps the app fully alive."
fi
