# Dex Decompilation Diagnosis (Goal 0)

This note answers Goal 0 of the App Dex Analysis plan. The goal was to explain the `jadx` checksum
errors on the recovered dexes and recommend a fix. The short answer is that the checksum error is
trivial to fix, but fixing it exposes a deeper problem. The four recovered app dexes have corrupt
bodies and cannot be decompiled. Goals 1 through 3 are blocked on a better capture.

## Summary Of Findings

1. The `jadx` checksum error is caused by the ART patched Adler-32 in the in memory dex header. It
   is fixed by recomputing the checksum. This part of Goal 0 is solved.
2. After fixing the checksum, `jadx` still produces zero classes. The cause is a corrupt tail
   `map_list` page plus, fatally, pervasive corruption throughout the index sections.
3. All four app dexes resolve 0.0 percent of their class names. A byte perfect framework dex from
   the same capture resolves 100 percent, which proves the toolchain is correct and the fault is
   in the data.
4. The corruption is not simple zero filled holes. Only about 1 percent of pages are zeroed. Most
   pages are present but hold the wrong bytes. The app dex was captured with stale or mismapped
   page tables, most likely because the freeze caught the process during its self kill teardown.
5. There is no clean alternate source. The app and Anker code exists only in the four corrupt
   dexes.
6. This corrects a prior assumption. A `patched-hash` tag does not mean an intact body. For these
   dexes the hash mismatch is real body corruption, not just an ART rewrite.

## The Checksum Error And Its Fix

The reported error is a plain dex header check.

```
jadx.plugins.input.dex.DexException: Bad dex file checksum: 0x9933e366, expected: 0xa2838d97
```

The dex header stores an Adler-32 checksum at offset `0x08`, computed over bytes `0x0c` to the
end, and a SHA-1 signature at offset `0x0c`, computed over bytes `0x20` to the end. ART and the
ijiami packer rewrite both when the dex is unpacked in memory, so the stored values no longer
match the body. `jadx` recomputes the Adler-32, gets `0xa2838d97`, sees the stored `0x9933e366`,
and rejects the file. The header value `0x9933e366` matches the checksum this project measured on
the same dex, which confirms the mechanism.

The fix is to recompute the signature over `0x20..end`, write it at `0x0c`, then recompute the
Adler-32 over `0x0c..end` (which now includes the corrected signature) and write it at `0x08`.
Order matters, since the checksum covers the signature field. The helper
`scripts/fix_inmemory_dex.py` does this. After it runs, `jadx` no longer reports a checksum error.

## Why Fixing The Checksum Is Not Enough

With the checksum fixed, `jadx` loads the file but emits `No classes for decompile` and a handful
of `StringIndexOutOfBoundsException: String index out of range: 0` errors. Two problems sit behind
this.

The first is the `map_list`. It lives in the last page of the dex. In these captures that page is
truncated, zero filled, or holds a garbage entry count (one dex reported a count of 2.36 billion),
which makes `jadx` throw a `BufferUnderflowException` while reading it. When several dexes are
passed in one `jadx` invocation, one bad `map_list` aborts the whole batch, so each dex must be
run separately. Rebuilding a valid eight entry `map_list` from the header section table removes
this crash. `scripts/fix_inmemory_dex.py` does this rebuild in place, since every `map_off` sits
inside the file with about 200 spare tail bytes.

The second problem is fatal and is described next.

## The Fatal Problem, Corrupt Bodies

Even with a valid checksum and a valid `map_list`, no class loads. `jadx` reads each `class_def`,
follows its `class_idx` into `type_ids`, then into `string_ids`, then to the type descriptor
string, and finds an empty string. Every class descriptor resolves empty, so `jadx` has nothing to
name or decompile.

Direct parsing of the dex confirms the index sections are wrecked.

- Class name resolution is 0.0 percent on all four app dexes. Not one `class_def` resolves to a
  valid `L...;` descriptor.
- The `string_ids` table is not monotonic. A valid table is strictly increasing. These score 61 to
  84 percent, so the offset entries are scrambled.
- Only about 4 percent of `string_ids` entries dereference to a clean printable string. The rest
  point at zero regions, out of range offsets, or garbage.
- Where offset tables should be, there is ASCII text. Sample `string_ids` entries decode as the
  bytes `ch i`, `USIV`, `ETRY`. String data content is sitting where the string index belongs,
  which is the signature of pages placed in the wrong order.
- The class named at the string level survives as raw data but is not indexed. The descriptor
  `Lcom/oceanwing/ota/m/request/FirmwareUpdateRequestModel;` is present at a raw offset with its
  correct uleb length prefix, but no `string_ids` entry points to it. This is why a `strings` scan
  finds the class while `jadx` cannot load it.

The health check (`scripts/dex_health.py`) summarizes it.

```
dex                          size  classes  resolv%  mono% zeropg%  verdict
app  0x3ab5b93c           8875044     5708     0.0%    64%    1.4%  UNUSABLE
app  0x3d1d2824           7816912    10002     0.0%    63%    1.2%  UNUSABLE
app  0x275497a0           6968124     8766     0.0%    61%    1.0%  UNUSABLE
app  0x37757904           4198864     3945     0.0%    84%    2.7%  UNUSABLE
fwk  0x0c70a778           1910048     2742   100.0%   100%    0.0%  USABLE
```

## The Toolchain Is Correct

The framework dex `0x0c70a778` is one of 25 dexes in this capture whose Adler-32 and SHA-1 verify
byte for byte. It came from the same RAM image, the same process, and the same reassembly. `jadx`
decompiles it into 2690 Java files with 100 percent class resolution. So `jadx`, the checksum fix,
and the parser are all correct. The four app dexes fail because their bytes are wrong, not because
the tools are wrong.

## Root Cause

The failure is not zero filled holes. If the app dex pages had been reclaimed to zram and zero
filled by `--fill-holes`, the file would be about 40 percent zero pages. It is about 1 percent.
The pages are present but hold the wrong bytes, including valid looking dex fragments from other
offsets. That means the virtual to physical mapping used to rebuild the dex returned wrong frames
for most of its pages.

The reassembly is not at fault in general, since the file backed framework dexes in the same
process rebuilt perfectly. The difference is that the framework dexes are file backed and stable,
while the app dex is an anonymous in memory dex that ijiami decrypted and that ART loaded through
`InMemoryDexClassLoader`. The freeze catches the app at its self kill, at the `kill` and
`exit_group` path. By then the kernel has begun tearing down the process address space, so the
anonymous dex mapping is partly dismantled or its frames are already being reused. The page table
walk then reads frames that no longer hold the dex, which produces exactly the present but wrong
pattern seen here. Heavy page reclaim on the 2 GB AVD is a contributing factor.

## No Alternate Source

- The app and Anker code is only in these four dexes. None of the 25 byte perfect dexes contain
  `com/oceanwing/soundcore` or `com/anker`.
- Re-running the reassembly with `--scan-all` over the existing 2 GB dump finds the app dexes only
  in the app process `pgd=0x9c000`, as the same four corrupt files. No second, cleaner copy exists
  in the dump.
- The signing header constants `AnkerBG`, `gtoken`, `openudid`, and the host
  `speaker.eufylife.com` appear in the raw RAM image a few times each but in zero dexes. They are
  runtime decrypted heap strings or live in reclaimed dex pages, so even a `strings` based
  reconstruction of the signer is not possible from this capture.

## Recommendation, A Better Capture

The current dump cannot yield the signing or OTA code. A fresh capture is needed, aimed at getting
the app dex fully resident and its page tables stable.

1. Freeze before the teardown, not at it. Halt the VM in the live window after the dex is mapped
   and before the self kill, rather than on the `kill` or `exit_group` path. Catching the process
   while it is genuinely running keeps its page tables consistent.
2. Raise the AVD RAM to 4 GB or more to cut page reclaim, so the whole app dex stays resident. Use
   the existing `--highmem` and `--lowsize` support for the high bank. Optionally `swapoff -a` in
   the guest to stop zram reclaim.
3. Validate before trusting. Do not rely on loose structural acceptance, which passed these
   corrupt dexes. After extraction run `scripts/dex_health.py` on each app dex and require a
   resolvable percentage near 100 and monotonicity at 100. Anything less means retry the capture.
4. Then fix and decompile. Run `scripts/fix_inmemory_dex.py` on each healthy dex, then `jadx` per
   file. The checksum and `map_list` fixes are still required for any in memory dex, healthy or
   not.

A much harder alternative is to recover the reclaimed dex pages from the zram compressed pool
inside the existing RAM image. This means parsing the guest zram and zsmalloc structures and
decompressing. It is possible in principle but is a large effort and is not recommended over a
clean re-capture.

## Reproduction

All steps are small scripts in `scripts/`.

- `fix_inmemory_dex.py in.dex out.dex` rebuilds the `map_list` and fixes the checksum and
  signature.
- `dex_health.py a.dex b.dex ...` prints size, class count, class resolvable percent, `string_ids`
  monotonicity, and zero page percent, with a usable or unusable verdict.

The four app dexes are
`emu-freeze/carved_virt/dex_00000009c000_0000{275497a0,37757904,3ab5b93c,3d1d2824}.dex`. The byte
perfect control dex is `dex_00000009c000_00000c70a778.dex`.
