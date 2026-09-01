# External References, Signing And Packer

Web research on 2026-08-31, after the extraction finding. Two questions were asked. Can the packer
be avoided by an older or unpacked app, and is the firmware download URL pattern known. The more
important result is that the signing this session could not extract from bytecode is already
documented in public reverse engineering of the same Anker backend. Defeating ijiami is not required
to reproduce it.

## The Signing Is Public And Confirms The Static Recovery

The charliex2 write-up on the eufy and Anker ecosystem documents the exact scheme, and it matches
`Signing-Scheme-Static-Recovery.md` point for point, filling the gaps this session left open.

- ECDH key exchange endpoint, `POST /openapi/oauth/key/exchange` for the makeitreal apps, which is
  the Soundcore variant, and `POST /v3/pc/oauth/key_exchange` for anker_make. The makeitreal path is
  exactly the `EXCHANGE_KEY_REQUEST` constant recovered from the dex.
- Signed string, `timestamp + "+" + nonce + "+" + encrypted_body_base64`. This closes the open
  question on field order and separator. The fields join with a literal `+`, and the body is the
  encrypted, base64 body.
- HMAC-SHA256, with the key being the hex string taken as UTF-8, not the raw bytes. This is the
  gotcha the prior notes flagged and it is confirmed.
- Headers, `X-Signature`, `X-Request-Ts`, `X-Request-Once`, `X-Key-Ident`, all confirmed.
- Four regional localKeys, 16 bytes each from hex, makeitreal QA, anker_make QA, makeitreal PROD,
  anker_make PROD. Soundcore is makeitreal PROD. The values are redacted in the public post.
- Body encryption, AES-128-CBC under the shared key with a random IV prepended, then base64.

The open-source `bropat/eufy-security-client` cross-validates the key material. Its `src/http/api.ts`
hardcodes the identical server public key found in the Soundcore signing dex,
`04c5c00c4f8d1197cc7c3167c52bf7acb054d722f0ef08dcd7e0883236e0d72a3868d9750cb47fa4619248f3d83f0f662671dadc6e2d31c2f41db0161651c7c076`,
used with `createECDH("prime256v1")` and `computeSecret(serverPublicKey)`. So that constant is the
shared Anker server public key, not app-specific, and it is used for the credential encryption path.
That library also sets `gtoken = md5(user_id)`, which names what `generateGTOKEN` produces, and its
`encryptAPIData` is AES-256-CBC with the IV as the first 16 bytes of the key. Note the library
targets the older eufy security camera API, which authenticates with `X-Auth-Token` and not the
`X-Signature` scheme, so it confirms the primitives and the server key but not the newer signer. The
newer signer is the charliex2 write-up and the USENIX paper below.

The peer-reviewed version is Goeman, De Ruck, Cordemans, Lapon, Naessens, "Reverse Engineering the
Eufy Ecosystem," USENIX WOOT 2024, with a paper PDF, slides, and a talk.

## The Packer, Method Extraction Is Beatable Only At Runtime

ijiami has more than one mode. The mode on this app is the method-extraction mode, Chinese 抽取壳,
which nulls method bodies and restores them at run. Public write-ups describe this as "replaces all
method bodies with NOP code." Every documented defeat is a runtime dumper that forces the methods to
run or hooks the restore, then dumps the code items. BlackDex is the common one, plus FART and FDex2
on an instrumented device, and drizzleDumper and Frida-based unpackers. FART is the canonical tool
for extraction shells, since it actively invokes every method to trigger restoration, but it is an
ART modification that needs a custom ROM on real hardware. All of these need the app to execute,
which is the same barrier the emulator work already hit. None recover code from a static dump.

No public unpacked Soundcore build, and no evidence that a specific older version ships without the
packer. APKMirror carries 3.1.5 from 2022 through 5.x. Whether an older build predates the
extraction hardening can only be settled by downloading it and checking for the ijiami markers,
`s.h.e.l.l.S`, `libexec.so`, `assets/ijiami.dat`. This is a cheap experiment but a low payoff now,
because the signing is already known and does not need the bytecode.

## Firmware Download URL, Dynamic Not Fixed

There is no static URL pattern to predict. The download URL is returned in the OTA response, the
`url` field of `LastPackageModel` for the speaker endpoint. In the eufy camera line the same design
returns a dynamic S3 URL with a name like
`ANKER_V8260_RELEASE_3.2.73_0001_20260209_15C97C_ENCRYPT.bin`, the firmware is fully encrypted, the
`_ENCRYPT` suffix and near 8 bits per byte entropy confirm it, and there is no signature
verification. The speaker firmware is a Jieli image on its own object store, and whether it is
encrypted the same way is not established publicly. The practical point stands, the URL is obtained
by making the signed request, not by guessing a host.

## Links

- charliex2, eufy and Anker write-up. https://charliex2.wordpress.com/2026/03/06/eufy/
- bropat/eufy-security-client. https://github.com/bropat/eufy-security-client
- USENIX WOOT 2024, Reverse Engineering the Eufy Ecosystem.
  https://www.usenix.org/conference/woot24/presentation/goeman and the PDF
  https://www.usenix.org/system/files/woot24-goeman.pdf
- AWAKE packer wiki, iJiami. https://awakewiki.org/packers/ijiami/
- BlackDex runtime unpacker. https://github.com/CodingGay/BlackDex
- OpenSCQ30, open Soundcore control, BLE layer not the cloud OTA.
  https://github.com/Oppzippy/OpenSCQ30
