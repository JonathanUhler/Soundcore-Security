# Notes: OTA API Reconstruction

These notes correspond to the plan in
`research/plans/2026-08-29_OTA-API-Reconstruction/Problem-Statement.md`.

## Status

Goal 1 investigation showed the signing is not in the Dart layer. It runs in the ijiami packed native
dex, reached from Dart over a Flutter platform channel. Full detail and evidence are in
`Signing-Analysis.md`. That put Goals 1 through 4 behind the same wall, the packed dex and the pinned
`speaker.eufylife.com` host.

That wall is now down. The decrypted app dex was recovered from a running emulator instance by
freezing the VM at the app's self kill and reassembling the scattered in memory dex from a physical
RAM dump with the guest page tables. Four multidex files carrying `com/oceanwing/soundcore` were
recovered, and they contain the OTA and signing code (class names, hosts, and `HmacSHA256` confirmed
at the string level). Method, tooling, and results are in `Dex-Recovery.md`. The signing and OTA
endpoint are now readable by decompiling those dexes, which is the next step and has not started.

## Files In This Note

- `Summary.md`: this file. Goal 1 answers and current status.
- `Signing-Analysis.md`: the evidence that the signing is native, the telemetry `token` recovered
  from the captured flows, and the failed attempt to reproduce it.
- `Dex-Recovery.md`: the emulator freeze and page table reassembly method that recovered the
  decrypted app dex, the `emu-freeze/` tooling, and the recovered artifacts.

## Goal 1 Answers

1. Where is `token`, `gToken`, `sign`, `timestamp`, `nonce` built, and with what algorithm and
   inputs? Not in the Dart layer. The prior session's claim that these were in the blutter output was
   based on false positive string matches. All HTTP, including signing, is built natively and invoked
   from Dart through `Bridge.request`, a Flutter `MethodChannel`. The signing algorithm and any
   hardcoded `app_key`, secret, or salt are in the packed native dex, not in any static artifact
   available to us.
2. Reproduce the signing and verify against the telemetry `token`? Partly characterized, not
   reproduced. The telemetry `token` is a body independent MD5 keyed on the `timestamp` header and a
   fixed secret, `token = MD5(timestamp + secret)`. Two `timestamp` to `token` pairs were recovered
   from the flows. The secret is in native code and was not recoverable by guessing or from public
   sources, so the token cannot yet be reproduced.
3. Document the app level signing used when no user is logged in. The captured firmware check ran with
   an empty `user_id`, so it is app signed, not user bound. The telemetry channel used only a `token`
   and `timestamp` header with a plaintext JSON body, plus fixed `AnkerBG: SPEAKER`, `country`,
   `language`, and `phone_virtual_id`. The richer `speaker.eufylife.com` API signing (`gToken`,
   `nonce`, `sign`) was not observed, because that host is pinned and no request to it was captured.

## Correction To Prior Notes

`../2026-08-29_APK-Firmware-Upgrade-Analysis/MITM-Analysis.md` previously stated that the Dart layer
holds the signing pieces and that the scheme was reconstructable from the blutter output. That claim
is corrected in place, with a pointer to `Signing-Analysis.md`.

## Incidental Findings For Later Goals

- API host map, from `network_security_config.xml`. Production `speaker.eufylife.com` with mirror
  `speaker-api.anker-in.com`. QA `speaker-qa.eufylife.com` and `speaker-api-qa.anker-in.com`. Beta
  `speaker-beta.eufylife.com` and `speaker-api-beta.anker-in.com`. Logging `log.eufylife.com` and
  `eufy-log.anker-in.com` plus CI variants. The `.eufylife.com` and `.anker-in.com` mirror pairs and
  the QA and beta environments are candidates for the later authenticated enumeration in Goal 2.
- On demand native libraries relevant to Goals 3 and 4, delivered in the `soundcoreso` split.
  `libjl_ota_auth.so` (Jieli OTA authentication), `libecc-encryption.so`, `libsecuritytool.so`, and
  `libargon2.so`.

## Recommended Next Step

The decrypted dex is recovered (see `Dex-Recovery.md`). Decompile the four app dexes and read the two
targets. The OkHttp interceptor that builds the `AnkerBG`, `gtoken`, and `sign` headers answers
Goal 1. The Retrofit interface plus `FirmwareUpdateRequestModel` and `AbOtaVersionCheckUtils`, which
define the `speaker.eufylife.com` firmware endpoint, answer Goal 2. With the signing understood, a
signed request to the endpoint with product code `A3949` and a low `firmware_version` reaches Goal 3,
the firmware download URL.
