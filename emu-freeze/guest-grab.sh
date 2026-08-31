#!/system/bin/sh
# Runs INSIDE the emulator as root. PASSIVE capture.
#
# It never SIGSTOPs the app during bootstrap (a stop/continue leash there trips
# ijiami's early native anti-tamper). It only READS /proc/<pid>/maps, which does
# not stop the target and does not set TracerPid, until the decrypted in-memory
# dex is mapped. Then it freezes the app once (the dex is already unpacked, so a
# stop is harmless now) and copies out every region that is a dalvik dex region
# by name OR whose bytes start with the DEX magic. Files are made world readable
# so the host can pull them as root.
#
# Args: <package> [max_poll_iters]
PKG="$1"
MAX="${2:-20000}"
OUT=/data/local/tmp/emu-freeze-dump
NAME_RE='dalvik-.*dex|Anonymous-?Dex|InMemoryDex|\.dex'

rm -rf "$OUT"; mkdir -p "$OUT"; chmod 777 "$OUT"
pid=""
while [ -z "$pid" ]; do pid=$(pidof "$PKG" 2>/dev/null | awk '{print $1}'); done
echo "grab: pid=$pid (passive poll, no stop during bootstrap)"

# true if the 4 bytes at virtual address $1 (decimal) are "dex\n"
is_dex() {
  m=$(dd if="/proc/$pid/mem" bs=1 skip="$1" count=4 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
  [ "$m" = "6465780a" ]
}

dump_one() {  # start_dec end_dec
  s=$1; e=$2; len=$((e - s)); [ "$len" -gt 0 ] || return
  f="$OUT/region_$(printf %x "$s").bin"
  dd if="/proc/$pid/mem" of="$f" bs=4096 skip=$((s / 4096)) count=$((len / 4096)) 2>/dev/null
  if [ -s "$f" ]; then chmod 666 "$f"; echo "  dumped $(printf 0x%x "$s") ${len}B -> $(basename "$f")"
  else rm -f "$f"; fi
}

dump_dex_regions() {  # reads a stable maps snapshot ($1)
  while IFS= read -r line; do
    perms=$(echo "$line" | awk '{print $2}'); case "$perms" in r*) : ;; *) continue ;; esac
    range=$(echo "$line" | awk '{print $1}'); name=$(echo "$line" | cut -d' ' -f6-)
    case "$name" in /dev/*) echo "$name" | grep -qi dalvik || continue ;; esac
    start=${range%-*}; end=${range#*-}; s=$((0x$start)); e=$((0x$end))
    if echo "$name" | grep -qiE "$NAME_RE"; then dump_one "$s" "$e"; continue; fi
    is_dex "$s" && dump_one "$s" "$e"
  done < "$1"
}

# Freeze, then snapshot maps. If the process is already gone it self-killed and
# we lost the passive race. Use the Strategy 2 neuter path instead.
freeze_and_snapshot() {
  kill -STOP "$pid" 2>/dev/null
  if ! cp "/proc/$pid/maps" "$OUT/maps.txt" 2>/dev/null || [ ! -s "$OUT/maps.txt" ]; then
    echo "grab: pid $pid self-killed before the freeze landed (passive race lost)."
    echo "grab: reads work, so use the neuter path (freeze.sh) which keeps it alive."
    echo "PID=$pid"; echo "DONE"; exit 3
  fi
}

i=0
while [ "$i" -lt "$MAX" ]; do
  if grep -qiE "$NAME_RE" "/proc/$pid/maps" 2>/dev/null; then
    echo "grab: in-memory dex detected, freezing pid $pid"
    freeze_and_snapshot
    echo "grab: scanning + dumping"
    dump_dex_regions "$OUT/maps.txt"
    break
  fi
  kill -0 "$pid" 2>/dev/null || { echo "grab: pid died before the dex was mapped (use neuter path)"; exit 1; }
  i=$((i + 1))
done
if [ "$i" -ge "$MAX" ]; then
  echo "grab: name never matched; freezing pid $pid, magic-scanning all regions"
  freeze_and_snapshot
  dump_dex_regions "$OUT/maps.txt"
fi

chmod -R 777 "$OUT" 2>/dev/null
cnt=$(ls "$OUT"/*.bin 2>/dev/null | wc -l | tr -d ' ')
kb=$(du -sk "$OUT" 2>/dev/null | awk '{print $1}')
echo "grab: wrote $cnt files, ${kb}KB total in $OUT"
if [ "$cnt" = "0" ]; then
  echo "grab: nothing dumped. The app most likely self-killed at/just after the"
  echo "grab: dex mapped (passive race lost). /proc/mem reads work here, so use the"
  echo "grab: neuter path (freeze.sh) which keeps the app alive with no race."
fi
echo "PID=$pid"; echo "DONE"
