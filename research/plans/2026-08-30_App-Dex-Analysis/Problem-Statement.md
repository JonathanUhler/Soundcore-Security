# Problem Statement: App Dex Analysis For Signing And OTA API

This plan continues the OTA API Reconstruction session, written up in
`research/notes/2026-08-29_OTA-API-Reconstruction/`. Read `Summary.md` there first, then
`Dex-Recovery.md`, `Signing-Analysis.md`, `MITM-Analysis.md`, and `Prior-Work.md`.

The prior session proved the request signing and the OTA endpoint are not in the Dart layer. They
live in the ijiami packed native dex, which was then recovered. The decrypted app dex is now in
hand.  This session decompiles it to answer the signing and OTA questions the packer was hiding, and
to map the firmware handling. It is primarily static dex analysis, with an optional live request at
the end.

## Background

Key facts carried over. See the notes for detail.

- The P20i product code is `A3949`. Both earbuds run firmware `14.43`. The serial is derivable from
  the Bluetooth MAC. See `MITM-Analysis.md`.
- The firmware status API host is `speaker.eufylife.com`, behind the APISIX gateway, certificate
  pinned inside the app. QA, beta, and CI variants exist, plus `log.eufylife.com`. The pinning is in
  app only, so an external client with a valid signature can still route. See `Signing-Analysis.md`.
- The signing and OTA endpoint are in the packed dex, reached from Dart over a Flutter platform
  channel, not in `libapp.so`. See `Signing-Analysis.md`.
- The decrypted app dex is recovered with the `emu-freeze/` pipeline. See `Dex-Recovery.md`. The app
  is multidex. Four files carry `com/oceanwing/soundcore` classes (virtual addresses `0x3ab5b93c`
  8.87 MB, `0x3d1d2824` 7.82 MB, `0x275497a0` 6.97 MB, `0x37757904` 4.20 MB).
- Starting classes seen at the string
  level. `com.oceanwing.ota.m.request.FirmwareUpdateRequestModel`,
  `com.oceanwing.ota.utils.AbOtaVersionCheckUtils`, `com.oceanwing.ota.inter.IOtaUpdate`. The app
  uses Retrofit (`retrofit2/http` annotations present). `HmacSHA256` and the header constant
  `AnkerBG` are present in the dex, which points to the newer Anker HMAC-SHA256 scheme rather than
  the old MD5.
- Signing verification ground truth. The captured telemetry `token`
  `361ec02987361d207d05392b9f0d89e4` at `timestamp` `1788043091` is body independent. See
  `Signing-Analysis.md`. The telemetry token may be a simpler scheme than the full API signing, so
  treat it as one data point, not the definition of the API signature.
- Public prior work. A 2026 write up documents an HMAC-SHA256 scheme where the key is the hex string
  encoded as UTF-8, with four hardcoded keys per environment, and OTA patterns
  `/v1/app/ota/get_app_version` and `device/firmware/{id}/{component}/update/{version}`. See
  `Prior-Work.md`.
  
## Goal 0: Get a Proper Decompilation

Running `jadx` directly on the recovered `.dex` files results in checksum errors. The first step is
to make recommendations on the cause and solutions of these errors. Here's an example output:

```
$ jadx -d output dex_00000009c000_00003ab5b93c.dex
INFO  - loading ...
ERROR - File open error: /home/jonathanuhler/Documents/Computer-Science/Security/Soundcore/emu-freeze/carved_virt/dex_00000009c000_00003ab5b93c.dex
jadx.plugins.input.dex.DexException: Bad dex file checksum: 0x9933e366, expected: 0xa2838d97
```

You can install `jadx` in your environment for testing, or ask the user to run `jadx` commands for
you.

## Goal 1: Reconstruct The Request Signing

This is the core deliverable and the prerequisite for driving the API.

1. Find the interceptor or signer that adds the auth headers for `speaker.eufylife.com` requests.
   Identify the exact algorithm (HMAC-SHA256 or MD5), the string that is signed with its exact field
   order, the key and how it is obtained, and every header the request carries (`AnkerBG`, `gtoken`,
   `app_key`, `timestamp`, `nonce`, `sign`, `x-auth-token`, `openudid`, `country`, and any others).
2. Record every hardcoded `app_key`, secret, salt, or HMAC key value, and which environment or
   business group each belongs to.
3. Document the app level signing used when no user is logged in, since the firmware check runs with
   an empty `user_id`.
4. Reproduce the signing in a small script. If the scheme matches the telemetry channel, verify
   against the captured `token`. Otherwise document the difference and defer verification to a live
   signed request in Goal 4.

## Goal 2: Recover The OTA API Contract

1. Find the Retrofit interface for the firmware or OTA version check. Record the host, the path, and
   the HTTP method.
2. Decode the request. The `FirmwareUpdateRequestModel` fields, how the product code `A3949` and the
   current firmware version are sent, and any device identifiers such as serial or MAC.
3. Decode the response schema. The latest version, the download URL field, size, hash, and any
   `forceUpgrade` style flag.

## Goal 3: Firmware Handling And Protections From The Dex

1. Trace how the firmware is fetched after the check, including the download URL source and host,
   which is likely an unpinned object storage or CDN.
2. Find the firmware decryption and verification. The keys, the algorithm, and whether any signature
   is verified before flashing. Note where the Java calls into native libraries over JNI, since the
   crypto may live in `libscsecurity.so`, `libcrypto-security.so`, `libsecuritytool.so`,
   `libecc-encryption.so`, or the Jieli `libjl_ota_auth.so`. This feeds the original plan Goals 3
   and 4, firmware download and protection assessment.

## Goal 4: Drive The Endpoint (Optional, End Of Session)

With the signing reproduced, make one signed request to the OTA endpoint with product code `A3949`
and a spoofed low `firmware_version` such as `1.00` to retrieve the latest firmware metadata and the
download URL, then fetch the binary. Keep probing minimal and respectful. This is a third party
production gateway.

## Constraints And Fallbacks

- The recovered dexes have patched checksums and some zero filled pages, so a few classes near a
  hole may be corrupt. If a needed class is unreadable, re-capture with the `emu-freeze/` pipeline,
  which is fast now that it is understood -- pause and ask the user to gather the data you need.
- The app is multidex. Target classes may be split across the four files, so decompile all four and
  search across the whole tree.
- If the signing or the firmware crypto bottoms out in a native library through JNI, pivot to Ghidra
  on the relevant `.so`. The MCP `ghidra` server is available for this.
- If a live request is attempted, respect the production gateway. Make minimal, targeted calls only.
