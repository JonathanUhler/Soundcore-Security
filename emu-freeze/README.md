# Emu-Freeze

Tooling to recover the ijiami packed dex from the Soundcore Android app by running it on an emulator
and reading the decrypted dex out of memory in the window where it is unpacked but the app has not
yet killed itself. Recovering that dex is the way to read the native OTA API client, the request
signing, and the firmware endpoint, none of which live in the Flutter Dart layer (see
`research/notes/2026-08-29_OTA-API-Reconstruction/Signing-Analysis.md`).

## Context

The app decrypts its real dex early in startup and loads it via `InMemoryDexClassLoader` (it shows
up as an `Anonymous-DexFile`). It stays mapped for the rest of the app's life. So the dex is
readable long before the app dies.

The one thing that does not work is stopping the app to catch it. ijiami's early native layer
(`libexec.so`) time-checks its own unpack with wall-clock reads. A `SIGSTOP` freezes the threads but
the wall clock keeps advancing, so a stopped and resumed process looks exactly like one under a
debugger. ijiami reacts by quietly failing to register its native methods, and the shell crashes
with `java.lang.UnsatisfiedLinkError: s.h.e.l.l.N.l` in `attachBaseContext`, before the dex is ever
unpacked. A SIGSTOP leash during bootstrap does not just miss the kill, it causes an earlier crash.

## Usage

Two commands. Boot the AVD in one terminal, capture in another.

```bash
# 1. Start the rooted AVD (rootAVD) and leave it running. This exposes QEMU's
#    gdbstub and monitor to the host.
./launch-emulator.sh Pixel_9a

# 2. Capture. Launches the app, freezes the VM the instant the in-memory dex is
#    mapped and resident, snapshots guest RAM, then reassembles and validates
#    the four app dexes and prints a health table.
./capture.sh
```

For any dex the health table marks `USABLE`, fix the in-memory checksum and `map_list`, then
decompile.

```bash
python3 fix_inmemory_dex.py carved_virt/<app>.dex carved_fixed/<app>.dex
jadx --no-res --show-bad-code -d out carved_fixed/<app>.dex
```

Any AVD size works with no extra flags. `capture.sh` asks QEMU for the real RAM layout with
`info mtree -f`, dumps every bank (including one above the 4 GB hole), and passes every CPU's CR3
from `info registers -a` to the reassembler, which uses the first seed that resolves. So a dex or a
page table sitting above the 2 GB line, or a stale CR3 on CPU0, no longer breaks the capture. If no
seed resolves, the reassembler auto-detects the kernel half from the dump and needs no CR3 at all.

### How capture.sh Freezes Early

The 2026-08-30 capture froze at the app's self kill and got four structurally dead dexes (see
Capture Quality). `capture.sh` freezes earlier and gates on residency instead.

1. Passively poll `/proc/<pid>/maps` until the in-memory dex appears. Reading maps does not
   perturb the app, so no anti-tamper layer reacts.
2. Confirm the dex regions are resident in `/proc/<pid>/smaps`, so a half-faulted or reclaimed
   mapping is never snapshotted.
3. Freeze with a hypervisor-level QEMU monitor `stop`. The monitor sits below the guest, so the
   freeze is invisible to every in-guest anti-tamper layer.

No gdb, kallsyms, or kernel breakpoints are needed for this path. `capture.sh` follows every
process of the package, since ijiami forks a watchdog and may re-exec, so the process that maps the
dex is often not the first `pidof` match.

If capture reports that the dex never appeared before the app exited, run `PROBE=1 ./capture.sh`.
It does not capture, it just prints the live pids and dex region count every 100 ms for about 8
seconds, so you can see the real region names and how long the app lives. If the app dies within
about a second of launch, keep it alive with the gdb path (`MODE=neuter ./freeze.sh`) in one
terminal, then run `./capture.sh` in another.

### Fallback, Catch The Suicide With gdb

If freezing at load is not suitable, the original flow halts the VM at the app's kill syscall. It
breakpoints kernel syscall entries the app cannot checksum. Sometimes freezing catches an
unrelated kill, in which case restart until it is stable with "Continuing...".

```bash
./find-kill-symbol.sh && MODE=freeze ./freeze.sh    # arm the freezer
# In another terminal, launch the app. It loads the dex, detects the emulator, and self kills,
# which halts the VM.
adb shell monkey -p com.oceanwing.soundcore -c android.intent.category.LAUNCHER 1
telnet 127.0.0.1 55555                              # then dump and reassemble by hand
  info mtree -f                                     # RAM bank sizes (dump every 'ram' range)
  pmemsave 0 <low_size> soundcore-ram.bin
  info registers -a                                 # collect every CPU's CR3
# Pass all CR3s (the first that resolves is used), or omit --cr3 to auto-detect the kernel half.
python3 reassemble_dex.py --cr3 <cr3...> --scan-all --loose --fill-holes soundcore-ram.bin --out carved_virt
python3 dex_health.py carved_virt/<app>.dex
```

Why reassembly and not a plain carve: The in-memory dex is virtually contiguous but its 4 KB pages
are scattered across physical RAM, so `carve_dex.py` finds the header and never validates the
body. `reassemble_dex.py` walks the x86-64 page tables from CR3 and rebuilds each process's virtual
space, where the dex is contiguous again.

Notes that matter in practice.

- The process that hit the breakpoint is often a watchdog, and the main app may not be scheduled, so
  its CR3 is not in `info registers`. `--scan-all` uses a CR3 only as a kernel-half fingerprint,
  finds every process PGD, and marks the app process by its `com/oceanwing/soundcore` hits. Pass
  every CPU's CR3 from `info registers -a`, since only some are usable, and the first that resolves
  is used. If none resolve, the kernel half is auto-detected from the dump so no CR3 is needed.
- In-memory dexes have a patched checksum and signature, so add `--loose` to accept them on header
  structure alone. Add `--fill-holes` for a dex that spans an unmapped page.
- 2 GB AVD means one `pmemsave 0 0x80000000` is complete. For more than 3 GB, dump the high bank too
  and pass `--highmem` and `--lowsize`.

## Capture Quality

A `patched-hash` tag does not mean the dex body is intact. `--loose` accepts a dex on header
structure alone, and `--fill-holes` zero-fills unmapped pages, so a badly captured app dex is still
written out. The 2026-08-30 session found all four app dexes structurally dead. Class name
resolution was 0%, the `string_ids` table was scrambled, and offset tables held stray string data.
The file-backed framework dexes from the same dump were byte perfect, which points at the capture,
not the tool. See `research/notes/2026-08-30_App-Dex-Analysis/Decompilation-Diagnosis.md`.

The likely cause is that the old flow caught the app at its self kill, in the ~1s window where the
small AVD reclaims dex pages, so the page walk read reused frames. `capture.sh` addresses this.

- It freezes at dex load, not at the self kill, so the reclaim window never opens. It also waits
  for the dex regions to read resident in `smaps` before it snapshots.
- Give the AVD 4 GB or more to stop reclaim entirely, and pass `RAMSIZE=0x100000000`. Optionally
  `swapoff -a` in the guest. `capture.sh` warns if the dex is under 95% resident at freeze time.
- Validation is automatic. `capture.sh` runs `dex_health.py` on each app dex, and
  `reassemble_dex.py` prints the resolvable percentage per app dex and warns when it is low.
  Require ~100% resolvable before decompiling.

## Files

- `capture.sh`: one-command capture. Launches the app, freezes the VM at dex load via a monitor
  `stop`, snapshots RAM, and reassembles and validates the app dexes. The main entry point.
- `mon.py`: minimal QEMU HMP monitor client. `capture.sh` uses it to `stop`, `pmemsave`, read CR3,
  and `cont` without an interactive telnet session.
- `snapshot.py`: freeze and dump every guest RAM bank using the real layout from `info mtree -f`,
  and report every CPU's CR3. Handles AVDs whose RAM sits above the 2 GB line.
- `common.sh`: shared config and root helpers.
- `launch-emulator.sh`: boot the AVD with the gdbstub and monitor exposed.
- `find-kill-symbol.sh`, `freeze.sh`, `freeze_gdb.py`: the fallback gdb driver that halts the VM at
  the app's kill syscall, for when freezing at load is not suitable.
- `passive-grab.sh`, `guest-grab.sh`: Strategy 1 host driver and passive guest grabber.
- `reassemble_dex.py`: walk the page tables from CR3 and rebuild contiguous dexes from a physical
  RAM dump. Prints a resolvable percentage per app dex and warns when a body is degraded.
- `dex_health.py`: report whether a dex is structurally usable (class resolvable percent,
  `string_ids` monotonicity, zero page percent). Run it to validate a capture before decompiling.
- `fix_inmemory_dex.py`: rebuild the `map_list` and fix the checksum and signature so `jadx` accepts
  an in-memory dex. Fixes the container only, not a body that was corrupt at capture.
- `grab-maps.sh`, `dump-proc-mem.sh`: capture `/proc/<pid>/maps` and dump a stopped process's
  regions (used by Strategy 2 and the earlier grabs).
- `carve_dex.py`: linear carve of a dump, for a physically contiguous dex.
