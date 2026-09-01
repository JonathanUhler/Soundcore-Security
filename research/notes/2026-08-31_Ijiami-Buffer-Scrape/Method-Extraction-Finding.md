# Method Extraction, The Real Blocker

This file records the diagnostic chain that identified ijiami method extraction as the reason the
signing bodies are missing, and the corrected answer to Goal 0. All work used the existing RAM
dump, `emu-freeze/ram-low.bin` and `ram-high.bin`, and the reassembled dexes in
`emu-freeze/carved_virt/`. No re-capture was done.

## The Dump Already Held Every Copy

The reassembler walks each process's page tables and writes out every dex-magic region it finds, at
any offset, so a heap-embedded dex is already carved. Deduplicating the marker-bearing carved dexes
by content hash gives 20 distinct app dexes. Eighteen sit in process PGD `aeaa2000` at high,
page-aligned mmap addresses, which is where ART's `InMemoryDexClassLoader` maps live. Two sit in a
second process, PGD `9c000`, at low, non-page-aligned addresses, the Java heap signature the plan
predicted for the source buffer.

The two heap hits are a red herring. They resolve 0 percent of class names, their string tables are
incoherent heap fragments, unrelated media and framework strings mixed together, and neither
contains the `com/anker/commonkit/aknetwork` signing package. They are stale dex-magic hits in heap
memory, not a clean source buffer. So the only usable copies of the app dexes are the 18 in the
`aeaa2000` process, and each app dex exists exactly once. There is no second, more complete copy to
find.

## The Signing Dex Resolves But Does Not Decompile

The signing classes cluster in one dex, `carved_virt/dex_0000aeaa2000_743400a18000.dex`. It is the
only copy that defines `KeyExchangeManager`, `CommonHeadersInterceptor`, `EcdhKeyUtils`,
`EncryptUtil`, `HMAC`, `SHA256`, `HeaderBuilder`, and the exchange entities. It resolves 100 percent
of its class names.

The prior session decompiled this exact file. The `apk/ram-scrape/` output records it, every method
of `KeyExchangeManager`, `EncryptUtil`, `EcdhKeyUtils`, and `HMAC` came out as an empty stub,
`return null`, each tagged `JADX WARN: Invalid debug info offset`. The prior conclusion was lazy
code paging. That conclusion is wrong.

## The Raw Bytes Show Extraction, Not Paging

Reading the `code_item`s directly settles it. Take `executeKeyExchange` at file offset `0x9420a8`.

```
009420a8  14 00 03 00 06 00 06 00 ff ea ff 03 03 03 00 00   header: regs=20 ins=3 outs=6 tries=6
                                                             debug_off=0x03ffeaff insns_size=0x303=771
009420b8  12 00 11 00 00 00 00 00 00 00 00 00 00 00 00 00   insns: const/4 v0,#0; return-object v0; 0...
  ... 1526 more bytes, all zero ...
```

The header is intact and realistic. The body claims 771 code units but holds a two-word stub,
`const/4 v0,#0` then `return-object v0`, then zeros for the rest. Its `insns` are 2 non-zero bytes
of 1542, or 0.1 percent. The method immediately before it, ending at `0x9420a7`, holds real dense
bytecode. Both are in the same 4 KB page `0x942000`. Page reclaim and ART lazy faulting are
page-granular, so they cannot leave one method real and the adjacent one nulled inside a single
resident page. Only a per-method operation can, which is method extraction. The packer overwrites
each protected method's body with a `return default` stub and restores the real instructions at
runtime.

Every substantive signing method reads the same way. The per-method non-zero fractions:

| Method | insns | non-zero |
| --- | --- | --- |
| `KeyExchangeManager.executeKeyExchange` | 771 | 0.1% |
| `KeyExchangeManager.performKeyExchange` | 668 | 0.1% |
| `KeyExchangeManager.convertToInnerResponse` | 542 | 0.2% |
| `EncryptUtil.encryptByHMAC256` | 159 | 0.6% |
| `EncryptUtil.encryptByHMAC` (4-arg) | 163 | 0.6% |
| `EcdhKeyUtils.updateShareKey` | 159 | 0.3% |
| `EcdhKeyUtils.getSharedKey` | 31 | 3.2% |
| `SHA256.coreUpdate` | 274 | 0.2% |
| `CommonHeadersInterceptor.intercept` | 31 | 3.2% |
| all 27 `HeaderBuilder` setters | 6 to 203 | under 17% |

## What Survives Extraction

Three things survive and they are what the salvage rests on.

1. Static initializers. `<clinit>` runs when a class is first touched, which class verification
   does, so every referenced class ran its `<clinit>`. These are real. `SHA256.<clinit>` is 91
   percent non-zero and 180 code units, it holds the SHA256 round-constant table.
   `KeyExchangeManager.<clinit>` is 79 percent, `EcdhKeyUtils.<clinit>` and `EncryptUtil.<clinit>`
   are 69 percent. These carry the class's `static final` constants.
2. Strings. The `string_data` section is never extracted. Every string constant, class name,
   method name, log message, endpoint, and header name is intact.
3. Class metadata. Kotlin's `@Metadata` annotation, the `class_data` member tables, the
   `method_id` and `proto_id` tables, and every `static final` field value survive. So each
   method's full signature, its parameter names and types and return type, is readable even though
   its body is a stub.

## The debug_info_off Damage Is A Separate, Smaller Issue

Every extracted `code_item`'s `debug_info_off` points far past the end of the file, for example
`0x03ffeaff` in a 10.7 MB dex. That is what jadx reports as `Invalid debug info offset`. It is a
side effect of extraction, the packer does not fix these offsets because it never intends the dex
to be read as a file. It matters only in that it clutters the decompiler output. It is not why the
bodies are empty. The bodies are empty because they are stubs.

## Goal 0, Answered

`InMemoryDexClassLoader` on this ART version copies the `ByteBuffer` into a fresh anonymous native
mapping, it does not reference the caller's buffer in place. That is why the app dexes appear at
high mmap addresses in the `aeaa2000` process. But this is not the operative fact. The operative
fact sits one layer below ART. Whatever ijiami hands to `InMemoryDexClassLoader` is already
method-extracted, bodies nulled. So no full-bodied dex ever reaches ART, and copying it eagerly or
faulting it lazily makes no difference. The full bodies are not in the buffer, the mapping, or the
heap. They exist only transiently, one method at a time, inside a `code_item` at the instant that
method executes.

## Why Goal 1 Fails And Goal 2 Would Not Help

Goal 1 asked to find a high-code-integrity copy in the existing dump. There is none, because a
complete copy never exists. The 85 percent `code%` on the signing dex is not a partial copy of one
image, it is the union of every method that happened to run at startup, each restored in place. The
signing methods are not among them.

Goal 2 asked to re-capture earlier, at decryption or at `InMemoryDexClassLoader` construction,
before ART's lazy copy. That is aimed at the wrong layer. At construction the dex is already
extracted. Freezing earlier captures the same stubs. The only capture that would contain
`executeKeyExchange`'s body is one taken after that method has actually run, which requires the app
to perform a live key exchange, which requires it to survive its emulator self-kill.
