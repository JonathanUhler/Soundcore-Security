# Notes: Ijiami Byte Buffer Scrape

These notes correspond to the plan in
`research/plans/2026-08-31_Ijiami-Buffer-Scrape/Problem-Statement.md`. That plan set out to find a
full, un-paged copy of the app's decrypted dex in the existing RAM dump, on the theory that ijiami
fills one `ByteBuffer` with the entire decrypted dex before ART takes its lazily faulted copy. The
goal was to recover the request-signing bytecode, which the prior session read back as empty method
bodies.

## Status

The core premise is refuted. There is no full decrypted buffer to find. ijiami does not pack this
app by whole-dex encryption. It uses method extraction, a per-method packer. The in-memory dex
keeps every `code_item` header but nulls the instruction body, and a native layer restores each
method's real bytecode on demand, only when that method first runs. The signing methods never ran
before the app self-kills, so their bodies were never restored and do not exist anywhere in the
dump.

This reframes the whole plan. Goal 0 is answered but the answer is not the one the plan expected.
Goal 1 fails, and it fails for a reason no re-scan can fix. Goal 2 as written would not help. The
session pivoted to salvage, and recovered most of the signing scheme from the data that survives
extraction, strings, class metadata, field constants, and the static initializers that ran during
class verification. See the two detail files.

## Files In This Note

- `Summary.md`: this file. Status, the corrected memory model, and next steps.
- `Method-Extraction-Finding.md`: the diagnostic chain that proves method extraction, the corrected
  answer to Goal 0, and why Goals 1 and 2 do not yield the signing bytecode.
- `Signing-Scheme-Static-Recovery.md`: the signing scheme recovered from surviving strings, kotlin
  metadata, and constants. The ECDH exchange endpoint, the embedded P-256 key, the two-tier HMAC
  signer, and what is still unknown.

## The Core Finding In One Paragraph

The signing dex is `emu-freeze/carved_virt/dex_0000aeaa2000_743400a18000.dex`, the only copy of it
in the dump. It resolves 100 percent of class names, so its structure is intact. But
`KeyExchangeManager.executeKeyExchange` claims 771 instructions and its `insns` are 0.1 percent
non-zero, a two-word `const/4 v0; return-object v0` stub padded with zeros. Every substantive
signing method reads the same way, `encryptByHMAC256` 0.6 percent, `updateShareKey` 0.3 percent,
`getSharedKey` 3.2 percent, `SHA256.coreUpdate` 0.2 percent, all 27 `HeaderBuilder` setters,
`CommonHeadersInterceptor.intercept` 3.2 percent. The only real bodies in these classes are the
`<clinit>` static initializers, which run at class verification, `SHA256.<clinit>` 91 percent,
`KeyExchangeManager.<clinit>` 79 percent. Adjacent methods in the same 4 KB page differ, one real,
one stub, so this is not page reclaim and not ART lazy faulting. It is per-method extraction.

## Correction To Prior Notes And Memory

The 2026-08-30 notes and the project memory `dex-capture-lazy-code-paging` attribute the missing
bodies to ART's `InMemoryDexClassLoader` faulting `code_item`s in lazily. That model predicts
page-granular absence tied to what ART verified. The evidence contradicts it. Absence is
per-method, not per-page, and it tracks what each method's own execution triggered, not class
verification. The mechanism is ijiami method extraction, restored per method at first run. This is
recorded so the earlier files are not edited in place. They were written before the extraction was
understood.

The practical consequence is the important part. A better or earlier capture cannot recover an
un-executed method's body, because that body is never present in the dex image at any time. It
lives encrypted in ijiami's own store and is written into the `code_item` only for the moment the
method runs.

## Deliverable: The Code Integrity Metric

Goal 1 asked for a code integrity metric in `dex_health.py`, the fraction of `code_item`s whose
`insns` are non-zero. It is implemented, with one correction the plan could not foresee. A naive
"any non-zero byte" test reads 100 percent here, because every extracted method keeps a one or two
word stub. The stub is a fixed size regardless of the original `insns_size`, so it is a large
fraction of a short method and a tiny fraction of a long one. The metric therefore scores only
`code_item`s of at least 16 code units, and counts one present when its `insns` are more than 25
percent non-zero. That cleanly separates a restored body, which is dense, from an extracted stub,
which is near zero. On the signing dex the metric reads `code%` 85 percent, meaning most large
methods ran at startup and were restored, while the specific signing methods sit in the missing
fraction. `dex_health.py` was also hardened so a corrupt carved dex with garbage member counts
cannot hang the scan.

## Recommended Next Steps

The signing bytecode is not statically recoverable from a dump of this app on this emulator. The
options, in rough order of value.

1. Reconstruct and confirm from what survives. The scheme is recovered structurally in
   `Signing-Scheme-Static-Recovery.md`. Reproduce the signer in a script and validate it against a
   single real request captured on hardware. This needs one observed request, not the bytecode.
2. Trigger the methods, then capture. The bodies restore when the methods run. A run that performs
   a real key exchange and a signed request would restore `executeKeyExchange`, `encryptByHMAC`,
   and the header assembly in place, after which a freeze captures them. This still needs the app
   to survive past its emulator self-kill, so it needs the packed unpacker defeated or real
   hardware. The emulator hiding path is a proven dead end, see the 2026-08-29 notes.
3. Reverse ijiami's restore routine. The per-method decrypt and write-back lives in the native
   `libexec.so` and `libexecmain.so`, not in the OTA crypto libraries. Reversing it would let the
   whole dex be restored offline from the encrypted store. High effort, and the store itself must
   also be located in the dump.
4. The native OTA crypto libraries are not a shortcut here. The signer is Kotlin, in
   `com/anker/commonkit/aknetwork`, a from-scratch HMAC and SHA256. The native `libsc*` and
   `libecc*` libraries are a separate, older path and will not contain this signer.
