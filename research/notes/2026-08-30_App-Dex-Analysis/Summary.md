# Notes: App Dex Analysis

These notes correspond to the plan in
`research/plans/2026-08-30_App-Dex-Analysis/Problem-Statement.md`.

## Status

Goal 0 is resolved and the OTA API is recovered. The first capture was structurally dead, diagnosed
in `Decompilation-Diagnosis.md`. A series of `emu-freeze/` fixes then produced a clean capture of 18
app dexes at 100 percent class resolution, and the OTA firmware API contract was read from it. The
resolution, the lazy code paging limit it exposed, and the API findings are in
`Capture-Resolution-And-OTA-API.md`.

Goal 2, the OTA contract, is answered, endpoint, request, response, and the firmware download URL
field. Goal 1, the signing, is partly answered, the header scheme is known but the algorithm and
keys are stubbed. Goal 3, firmware handling, is mapped but its bodies did not decompile. The signing
is the one blocker left to pulling a firmware file.

## Files In This Note

- `Summary.md`: this file. Current status and the file index.
- `Capture-Resolution-And-OTA-API.md`: the `emu-freeze/` fixes that produced a clean capture, the
  lazy code paging limit, and the OTA firmware API contract, endpoint, request, response, download
  URL, and the signing scheme.
- `Decompilation-Diagnosis.md`: the diagnosis of the first, structurally dead capture, the proof
  that the toolchain is correct, and the root cause. Superseded by the resolution above, kept for
  the diagnostic method.
- `scripts/fix_inmemory_dex.py`: rebuilds the `map_list` and fixes the checksum and signature so
  `jadx` accepts an in memory dex. Promoted to `emu-freeze/fix_inmemory_dex.py`.
- `scripts/dex_health.py`: reports whether a dex is structurally usable, used to validate a
  capture before spending time on decompilation. Promoted to `emu-freeze/dex_health.py`.

The reassembler now carries a health gate. `emu-freeze/reassemble_dex.py` prints a resolvable
percentage for each app dex and warns when a body is degraded, so a bad capture is caught at
extraction instead of being accepted on loose header structure alone.

## Goal 0 Answer

The `jadx` error `Bad dex file checksum` is caused by the ART patched Adler-32 in the in memory
dex. It is fixed by recomputing the signature then the checksum. A second issue, a corrupt tail
`map_list` page, must also be repaired or `jadx` crashes. Both fixes are in
`scripts/fix_inmemory_dex.py`.

Those fixes are necessary but not sufficient. After both are applied, `jadx` still loads zero
classes because the index sections of all four app dexes are pervasively corrupt. Class name
resolution is 0.0 percent on every app dex, while a byte perfect framework dex from the same
capture resolves 100 percent, which proves the fault is in the captured data and not in the tools.

The corruption is not zero filled holes. Only about 1 percent of pages are zeroed. Most pages are
present but hold the wrong bytes, including dex fragments and ASCII text where offset tables
belong. The most likely cause is that the freeze caught the app during its self kill, when the
kernel had begun tearing down the anonymous in memory dex mapping, so the page table walk read
reused frames.

## What Is Needed To Unblock

A fresh capture with the app dex fully resident and its page tables stable. This is now automated
by `emu-freeze/capture.sh`. It launches the app, freezes at dex load instead of at the self kill by
polling `/proc/<pid>/maps` and stopping the VM through the QEMU monitor, gates on `smaps` residency,
then reassembles and runs `dex_health.py` on each app dex. Give the AVD 4 GB or more and pass
`RAMSIZE=0x100000000` to remove page reclaim entirely. Require a resolvable percentage near 100
before decompiling. See `Decompilation-Diagnosis.md` and the emu-freeze README for detail.

## Correction To Prior Notes

`../2026-08-29_OTA-API-Reconstruction/Dex-Recovery.md` treats the `patched-hash` tag as a benign
ART rewrite of an otherwise intact dex. That holds for a fully resident dex, but not for these
four. Here the hash mismatch reflects real body corruption, since roughly half of each index table
is wrong. A capture should be validated by structural resolvability, not accepted on loose header
structure alone. This is noted here rather than edited into the prior file, which was written
before the corruption was known.
