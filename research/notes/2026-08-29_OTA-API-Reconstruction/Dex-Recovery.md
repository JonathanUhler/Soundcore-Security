# Dex Recovery Via Emulator Freeze

The signing and the OTA endpoint live in the ijiami packed native dex, not the Dart layer (see
`Signing-Analysis.md`). Static extraction of that dex is not possible. This note records the dynamic
method that recovered the decrypted dex from a running app, the tooling built for it under
`emu-freeze/`, and the result. It does not analyze the dex contents yet.

## Result

The decrypted Soundcore app dex was recovered from a running instance. The app is multidex. Of the
87 dex files reconstructed from the app process, four carry `com/oceanwing/soundcore` classes and are
the real app payload. The rest are framework and boot image dexes mapped into the same process.

| Virtual address | Size (bytes) |
| --- | --- |
| `0x3ab5b93c` | 8,875,044 |
| `0x3d1d2824` | 7,816,912 |
| `0x275497a0` | 6,968,124 |
| `0x37757904` | 4,198,864 |

## Environment

- Rooted Android emulator, x86_64 system image running the arm64 app libraries under ndk_translation
  (aarch64 0.2.3), Android 15 or 16 era (generational CMC GC, icudt78). Magisk root.
- The emulator is QEMU with KVM. Its gdbstub and HMP monitor are exposed to the host.
- An earlier, older x86_64 image made ijiami crash at bootstrap with an `UnsatisfiedLinkError` in
  `s.h.e.l.l.N.l`. The newer image runs ijiami cleanly. Prefer a recent image.

## What Did Not Work

- Static. The dex is only in the packed native layer, confirmed in `Signing-Analysis.md`.
- In guest SIGSTOP leash during bootstrap. ijiami's early native layer (`libexec.so`) time checks its
  own unpack with wall clock reads. SIGSTOP freezes threads but the wall clock keeps advancing, so a
  stopped and resumed process looks debugged. ijiami then fails to register its native method and the
  shell crashes with `UnsatisfiedLinkError` before the dex is ever unpacked.
- Passive `/proc/<pid>/mem` grab. Reading maps and memory is passive and does not perturb the app,
  but the app self kills within about a second of the dex being mapped, so the detect then dump race
  is lost.
- Frida and Xposed. Detected earlier and by a native path, per the prior session.

## What Worked

Hypervisor level control to capture the app alive, plus offline page table reassembly.

1. Freeze at the suicide. Host gdb attaches to the QEMU gdbstub and breakpoints the kernel syscall
   entries the app uses to kill itself. This is invisible to every in guest anti tamper layer because
   the breakpoint is on kernel code the app cannot checksum. The app self kills with
   `kill(pid, 9)`, `kill(-pid, 9)`, and `tgkill(pid, tid, 3)`, then falls through to `exit_group`.
   Neutering the signals keeps it alive but it still `exit_group`s, so freeze mode is used, halting
   the whole VM at the first fatal signal with the app alive and its dex resident.
2. Snapshot RAM and CR3. With the VM halted, the QEMU monitor dumps guest RAM with
   `pmemsave 0 0x80000000` and reports CR3 with `info registers`. The AVD has 2 GB of RAM, so a single
   low bank dump is complete.
3. Reassemble offline. The in memory dex is virtually contiguous but its 4 KB pages are scattered in
   physical RAM, so a linear carve of the dump finds the header but never validates the body.
   `reassemble_dex.py` walks the x86-64 page tables from CR3, rebuilds a process's virtual address
   space where the dex is contiguous again, and extracts it.

Three details made the reassembly work.

- Right process. The process that hit the breakpoint is a watchdog, not the main app, and the app
  process was not scheduled on any CPU, so its CR3 is not in `info registers`. Every process kernel
  PGD shares an identical upper (kernel) half, so the tool fingerprints that half from any CR3 and
  finds all process PGDs in the dump. The app process is `pgd=0x9c000`, 1074 MB, 4668 marker hits.
- Patched headers. ART and the packer rewrite the in memory dex checksum and signature, so strict
  Adler-32 plus SHA-1 validation rejects the app dex even though 8 other dexes in the same process
  validate cleanly. The tool validates by dex header structure instead (loose mode). Every recovered
  app dex is tagged `patched-hash`.
- Holes. Unmapped pages inside a dex range are zero filled so a large dex that spans a hole is still
  written (fill holes mode).

Practical gdb notes. Pin the architecture before connecting (`set architecture i386:x86-64`) or the
64-bit register block misparses as 32-bit. Kernel pointers come back from gdb as negative Python
ints, so mask to unsigned before reading memory. Software breakpoints on kernel text do fire under
KVM. KASLR moves the syscall addresses every boot, so pull kallsyms fresh after each boot.

## Capture Parameters For This Run

- CR3 kernel half seed: `0x47e8a000` (any process CR3 works as the seed).
- App process PGD: `0x9c000`.
- Command:
  `python3 reassemble_dex.py --cr3 0x47e8a000 --pgd 0x9c000 --loose --fill-holes soundcore-ram.bin`
- Output: 87 dex extracted, 4 with the app package.

## Tooling

All under `emu-freeze/`. See `emu-freeze/README.md` for the full flow.

- `launch-emulator.sh`, `find-kill-symbol.sh`, `freeze.sh`, `freeze_gdb.py`: freeze the VM at the
  app's suicide via the QEMU gdbstub.
- `reassemble_dex.py`: walk the page tables from CR3 and reconstruct contiguous dexes from the
  physical RAM dump. Supports `--scan-all`, `--pgd`, `--loose`, and `--fill-holes`. Unit tested
  against scattered synthetic page tables and a patched header dex.
- `carve_dex.py`: linear physical carve. Works only for a dex that happens to be physically
  contiguous, superseded by `reassemble_dex.py` for the scattered in memory dex.
- `passive-grab.sh`, `guest-grab.sh`, `grab-maps.sh`, `dump-proc-mem.sh`: earlier in guest
  approaches, kept for reference.

## Confirmed Artifacts, String Level, Before Decompilation

These were read from the RAM image and confirm the recovered dexes hold the target code.

- Hosts. Production `speaker.eufylife.com`, plus `speaker-qa`, `speaker-beta`, `speaker-ci`, and
  `log.eufylife.com`. A path shape `/knowledge/A3947` appears on a speaker host.
- P20i model class. `com.oceanwing.soundcore.model.deviceprodctinfo.A3949ProductModel`, with
  `A3949P25` and `A3949R50` variants.
- OTA cloud classes. `com.oceanwing.ota.m.request.FirmwareUpdateRequestModel`,
  `com.oceanwing.ota.utils.AbOtaVersionCheckUtils`, `com.oceanwing.ota.inter.IOtaUpdate`.
- Signing. `HmacSHA256` is present, along with the header constant `AnkerBG` and the tokens
  `gtoken`, `app_key`, `appKey`, and `openudid`. This points to the newer Anker HMAC-SHA256 scheme
  rather than the old MD5 gtoken. To be confirmed by decompilation.

## Next Step

Decompile the four app dexes and read the two targets. The OkHttp interceptor that builds the
`AnkerBG`, `gtoken`, and `sign` headers answers Goal 1. The Retrofit interface plus
`FirmwareUpdateRequestModel` that define the `speaker.eufylife.com` firmware endpoint answer Goal 2.
Dex analysis has not started.
