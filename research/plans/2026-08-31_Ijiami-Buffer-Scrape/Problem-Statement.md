# Problem Statement: Ijiami Byte Buffer Scrape

This plan continues the App Dex Analysis session, written up in
`research/notes/2026-08-30_App-Dex-Analysis/`. Read `Summary.md` there first, then
`Capture-Resolution-And-OTA-API.md`. The anti-tamper context is in
`research/notes/2026-08-29_APK-Firmware-Upgrade-Analysis/Anti-Tamper-And-Dynamic-Analysis.md`.

The prior session captured the app's decrypted dex from a running emulator and recovered the OTA
API contract. It also hit a wall. The capture reads ART's `InMemoryDexClassLoader` copy of the
dex, whose method `code_item`s are faulted in lazily, so only methods that executed before the
freeze have bytecode. The request signing and the OTA crypto never ran on the emulator, so their
bodies are stubbed. The full decrypted dex existed earlier, in ijiami's own decryption buffer,
before ART's lazy copy. This session targets that buffer to recover all bytecode, which unblocks
the signing.

## Background

Key facts carried over. See the prior notes for detail.

- The OTA contract is known. `POST /v1/speaker/sound_core/A3949/firmware/update` on
  `speaker.eufylife.com`, request `OtaRequestModel` with `product_code`, `sn`, `version`,
  `matched`, response `LastPackageModel` whose `url` field is the firmware file, likely on the
  unpinned object store `speaker-oss.anker-in.com`. See `Capture-Resolution-And-OTA-API.md`.
- The signing is the newer Anker scheme, ECDH P-256 plus HMAC-SHA256 with a session key, not a
  static key. Confirmed by the P-256 curve constants, `KeyExchangeManager`, `EcdhKey`,
  `ExchangeKeyRequest` and `ExchangeKeyResponse`, `ClientSecretInfo`, and the `X-Signature`,
  `X-Request-Ts`, `X-Request-Once`, `X-Key-Ident`, and `X-Encryption-Info` headers. There is no
  static key to grab.
- The signing bodies are stubbed. `KeyExchangeManager`, `EcdhKeyUtils`, `EncryptUtil`, `HMAC`, and
  the `CommonHeadersInterceptor` all decompile to empty method bodies. They never executed on the
  emulator, so their code was never faulted in.
- Running the app on the emulator is a dead end. `libijm-emulator.so` kills the app about one
  second after startup, and the prior session proved that Magisk, Zygisk, Shamiko, property
  scrubbing, and fingerprint spoofing do not defeat it. But the dex is decrypted and loaded before
  that kill, so a capture that does not need the app to keep running is still viable.
- Artifacts on hand. The RAM dump `emu-freeze/ram-low.bin` at 3 GB and `ram-high.bin` at 1 GB, the
  reassembled dexes in `emu-freeze/carved_virt/`, and the `emu-freeze/` capture tooling.

## Why The Buffer Should Exist

`InMemoryDexClassLoader` is constructed from a `ByteBuffer` that ijiami fills with the entire
decrypted dex. Every byte is written during decryption, so that buffer is fully resident, all
`code_item`s included, unlike ART's lazily faulted copy. The observed per dex code residency, from
about 3 percent to 92 percent, is the signature of lazy fault in, not of an eager full copy. So a
complete copy of each dex should exist in memory as the source buffer. The open question is
whether it survives to the freeze or is freed and garbage collected once ART has taken its copy.

## Goal 0: Characterize The InMemoryDexClassLoader Memory Flow

Establish where the full bytes live and for how long, so the search is targeted.

1. Determine, for this ART version, whether `InMemoryDexClassLoader` copies the `ByteBuffer` into
   a native `MemMap` or references it in place, and whether ijiami passes a heap `byte[]` backed
   buffer or a direct buffer. A heap `byte[]` is a contiguous Java heap object with the dex magic
   at its start, and is garbage collected once unreferenced.
2. From that, predict the buffer's location, a Java heap object versus a native mapping, and its
   lifetime relative to the app's self kill.

## Goal 1: Recover The Buffer From The Existing Dump

Try the dump already on disk before any re-capture.

1. Add a code integrity metric to `dex_health.py`, the fraction of `code_item`s whose `insns` are
   non zero. The current metric measures class name resolvability only and over reports these
   dexes as usable. This metric is the search signal.
2. Re-scan every dex magic region in both RAM banks, across all processes, for a copy that is high
   on both class resolvability and code integrity. The four soundcore app dexes are the targets. A
   copy near 100 percent on both is the ijiami buffer.
3. Account for the buffer being a Java `byte[]`. Its dex magic may not be page aligned and may be
   preceded by array header words. The carve should find the magic at any offset and validate by
   dex header structure, not assume alignment.
4. If a full copy is found, fix its header with `fix_inmemory_dex.py` and decompile. Done, proceed
   to Goal 3.

## Goal 2: Re-Capture Freezing At Decryption, If Needed

If the buffer was freed by the suicide time freeze, capture it earlier.

1. Freeze at ijiami's decryption completion or at the `InMemoryDexClassLoader` construction,
   before ART's lazy copy and before garbage collection, which is earlier than the current dex
   mapped trigger in `capture.sh`.
2. Detection options, in order of preference. Poll the app's writable heap for the dex magic
   before the `InMemoryDex` mapping appears. Or breakpoint the ART native in memory dex entry,
   which needs `libart.so` symbols. Or freeze at the first dex magic that appears anywhere in the
   app's anonymous heap. Keep the hypervisor level freeze, no in guest hooks, so ijiami cannot see
   it.
3. Validate the captured buffer with the code integrity metric from Goal 1 before trusting it.

## Goal 3: Reconstruct The Request Signing From Full Bytecode

With real bodies in hand, answer the signing.

1. The ECDH exchange. Read `KeyExchangeManager`, `EcdhKeyUtils`, `EccKeyPair`,
   `ExchangeKeyRequest`, and `ExchangeKeyResponse`. Recover the keypair generation, the exchange
   endpoint and its request and response, and how the shared secret and the session key are
   derived.
2. The signer. Read `CommonHeadersInterceptor`, `HeaderBuilderKt`'s callers, `EncryptUtil`, and
   `HMAC`. Recover the exact signed string with its field order, which key signs it, session or
   bootstrap, and how `X-Key-Ident` selects it. Record any bootstrap client credential for
   `X-Client-Credential` and `Client-id`.
3. Reproduce the signing in a script. Verify against any captured request if one becomes
   available.

## Goal 4: Drive The Endpoint And Fetch Firmware (Optional, End Of Session)

With the signing reproduced, POST to `/v1/speaker/sound_core/A3949/firmware/update` with product
code `A3949` and a spoofed low `version` such as `1.00`, read `LastPackageModel.url` from the
response, then download the firmware from the object store. Keep probing minimal and respectful.
This is a third party production gateway.

## Constraints And Fallbacks

- Try the existing dump first, Goal 1, before re-capturing. It is on disk and needs no emulator.
- If the buffer is genuinely gone and cannot be re-captured, pivot to Ghidra on the native
  security libraries for the ECDH and HMAC and any bootstrap credential, `libscsecurity.so`,
  `libcrypto-security.so`, `libsecuritytool.so`, `libecc-encryption.so`, and the Jieli
  `libjl_ota_auth.so`. The MCP `ghidra` server is available.
- Real hardware MITM stays blocked. The iPhone is certificate pinned and not jailbroken, and there
  is no rootable Android device. Do not repeat the emulator hiding work, it is a proven dead end.
- Respect the production gateway on any live request, minimal targeted calls only.
