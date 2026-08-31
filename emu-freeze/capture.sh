#!/usr/bin/env bash
# One-command capture. Launch the app, freeze the VM the instant its in-memory
# dex is mapped and resident (well before the anti-emulator suicide), snapshot
# guest RAM, then reassemble and validate the app dexes. This replaces the
# multi-terminal gdb flow for the common case.
#
# How it freezes early and safely, without gdb, kallsyms, or kernel breakpoints:
#   1. Passively poll /proc/<pid>/maps until the in-memory dex appears. Reading
#      maps does not perturb the app (same passive read grab-maps.sh relies on).
#   2. Confirm the dex regions are resident via /proc/<pid>/smaps, so we never
#      snapshot a half-faulted or reclaimed mapping (the 2026-08-30 failure).
#   3. Freeze with a hypervisor-level QEMU monitor `stop`. The monitor sits below
#      the guest, so the freeze is invisible to every in-guest anti-tamper layer.
# Freezing at load, not at the suicide, avoids the ~1s window where the small AVD
# reclaims dex pages and corrupts the capture.
#
# Prereq: ./launch-emulator.sh <avd> is running (gdbstub + monitor exposed).
#
# Usage: ./capture.sh
#        OUT=carved_virt SNAPDIR=/abs/dir ./capture.sh
# The guest RAM layout, including any bank above the 2 GB line, is detected from
# 'info mtree -f', so no RAM size needs to be set for a bigger AVD.
set -uo pipefail
cd "$(dirname "$0")"
source ./common.sh

MON="${MON:-127.0.0.1:${MON_PORT:-55555}}"
SNAPDIR="${SNAPDIR:-$PWD}"                 # where ram-low.bin / ram-high.bin land
RAMSIZE="${RAMSIZE:-0x80000000}"          # fallback low-bank size if 'info mtree -f' fails
OUT="${OUT:-carved_virt}"
DEXPAT='dalvik-.*dex|InMemoryDex|Anonymous-?Dex'

residency() {   # prints "<pct> <swapKB>" for the dex regions in the pid's smaps
  sh_root "cat /proc/$1/smaps" 2>/dev/null | tr -d '\r' | awk -v pat="$DEXPAT" '
    /^[0-9a-f]+-[0-9a-f]+ / { inb = (tolower($0) ~ tolower(pat)) ? 1 : 0; next }
    inb && $1=="Size:" {size+=$2}
    inb && $1=="Rss:"  {rss+=$2}
    inb && $1=="Swap:" {swap+=$2}
    END{ if (size>0) printf "%d %d\n", 100*rss/size, swap; else print "0 0" }'
}

echo "[*] force-stopping $PKG for a clean start"
$ADB $SER shell "am force-stop $PKG" >/dev/null 2>&1 || true
sleep 1

echo "[*] launching $PKG"
$ADB $SER shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1 || true

# PROBE=1: do not capture, just characterize the app. Prints the live pids and any
# dex regions every 100 ms for ~8 s. Use it when capture keeps missing the dex, to
# see the real region names and how long the app lives before its suicide.
if [ -n "${PROBE:-}" ]; then
  echo "[*] PROBE: watching $PKG processes and dex regions (~8s) ..."
  for t in $(seq 1 80); do
    pids="$(sh_root "pidof $PKG" 2>/dev/null | tr -d '\r')"
    dex="$(sh_root "for p in \$(pidof $PKG); do cat /proc/\$p/maps 2>/dev/null; done" 2>/dev/null \
           | tr -d '\r' | grep -icE "$DEXPAT")"
    echo "    t=$(printf '%02d' "$t")  pids=[$pids]  dex_regions=$dex"
    sleep 0.1
  done
  exit 0
fi

# Follow the dex across EVERY package process. ijiami forks a watchdog and the
# packer may re-exec, so the pid that maps the dex is often not the first pidof
# match. One adb round-trip per poll dumps every process's maps tagged by pid.
echo "[*] waiting for the in-memory dex (following all $PKG processes) ..."
get_pid >/dev/null            # let the first process appear (waits up to ~30s)
pid=""; gone=0
for _ in $(seq 1 4000); do
  snap="$(sh_root "for p in \$(pidof $PKG); do echo @@\$p; cat /proc/\$p/maps 2>/dev/null; done" 2>/dev/null | tr -d '\r')"
  if [ -z "$snap" ]; then
    gone=$((gone + 1)); [ "$gone" -gt 60 ] && break     # ~3s with no process at all
    sleep 0.05; continue
  fi
  gone=0
  pid="$(printf '%s\n' "$snap" | awk -v pat="$DEXPAT" '
    /^@@/ { p = substr($0, 3); next }
    tolower($0) ~ tolower(pat) { print p; exit }')"
  [ -n "$pid" ] && break
  sleep 0.02
done

if [ -z "$pid" ]; then
  echo "[!] the in-memory dex never appeared before the app exited. Diagnostics:"
  sh_root "ps -A -o PID,NAME 2>/dev/null | grep -i oceanwing" 2>/dev/null | tr -d '\r' | sed 's/^/      proc: /'
  sh_root "for p in \$(pidof $PKG); do cat /proc/\$p/maps 2>/dev/null; done" 2>/dev/null | tr -d '\r' \
    | grep -iE 'dex|anon:dalvik|ashmem' | head -15 | sed 's/^/      map:  /'
  echo "      Run 'PROBE=1 ./capture.sh' to see the app's lifetime and real dex region names."
  echo "      If the app dies within ~1s of launch, keep it alive with the gdb path first,"
  echo "      then re-run ./capture.sh:  MODE=neuter ./freeze.sh"
  exit 1
fi
echo "[+] in-memory dex mapped in pid=$pid; freezing now"

# One quick residency read for the record, then freeze immediately. Do NOT loop
# waiting for residency here: the app self-kills about a second after load, so a
# long wait would lose it. If residency is low, fix it with more AVD RAM.
read -r pct swap <<<"$(residency "$pid")"
echo "    dex residency at freeze: ${pct}% resident, ${swap}K swapped"
[ "${pct:-0}" -ge 95 ] || echo "    (low residency: use RAMSIZE=0x100000000 on a 4 GB AVD, or 'swapoff -a' in the guest)"

echo "[*] freezing the VM and snapshotting every guest RAM bank ..."
snap="$(python3 snapshot.py "$MON" "$SNAPDIR" "$RAMSIZE")"
printf '%s\n' "$snap" | sed 's/^/    /'
LOWFILE="$(printf '%s\n' "$snap" | sed -n 's/^LOWFILE=//p')"
LOWSIZE="$(printf '%s\n' "$snap" | sed -n 's/^LOWSIZE=//p')"
HIGHFILE="$(printf '%s\n' "$snap" | sed -n 's/^HIGHFILE=//p')"
CR3S="$(printf '%s\n' "$snap" | sed -n 's/^CR3S=//p')"
if [ -z "$LOWFILE" ] || [ ! -s "$LOWFILE" ]; then
  echo "[!] RAM snapshot failed (see the '# ...' notes above). pmemsave writes to the emulator's"
  echo "    own working directory, so if it is a write error, relaunch the emulator from a"
  echo "    writable directory. The '# qemu cwd' line shows where it is trying to write."
  python3 mon.py "$MON" "cont" >/dev/null 2>&1 || true
  exit 1
fi
himem=""
[ -n "$HIGHFILE" ] && himem="--highmem $HIGHFILE --lowsize $LOWSIZE"

echo "[*] reassembling and validating app dexes (CR3 seeds: ${CR3S:-none; auto-detect}) ..."
python3 reassemble_dex.py ${CR3S:+--cr3 $CR3S} --scan-all --loose --fill-holes "$LOWFILE" $himem --out "$OUT" \
  | tee /tmp/reassemble.log
apps="$(grep 'com/oceanwing/soundcore' /tmp/reassemble.log | grep -oE 'dex_[0-9a-f_]+\.dex' | sort -u)"

echo
echo "[*] resuming the VM (the app may now finish its suicide, which is fine) ..."
python3 mon.py "$MON" "cont" >/dev/null 2>&1 || true

echo
if [ -n "$apps" ]; then
  echo "[=] app dex health:"
  ( cd "$OUT" && python3 ../dex_health.py $apps )
  echo
  echo "    Any USABLE dex is ready to fix and decompile:"
  echo "      python3 fix_inmemory_dex.py $OUT/<app>.dex carved_fixed/<app>.dex"
  echo "      jadx --no-res --show-bad-code -d out carved_fixed/<app>.dex"
else
  echo "[!] no app dex was recovered. The app may have died before the dex mapped."
fi
