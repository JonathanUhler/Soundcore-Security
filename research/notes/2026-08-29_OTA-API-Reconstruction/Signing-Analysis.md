# Request Signing Analysis

This note answers Goal 1 of the OTA API Reconstruction plan. The goal was to find where the request
signing (`token`, `gToken`, `sign`, `timestamp`, `nonce`) is built in the blutter reconstruction,
identify the algorithm and inputs, and reproduce it against the captured telemetry `token`.

## Result

The signing is not in the Dart layer. It cannot be reconstructed from the blutter output. All of the
signing artifacts that the prior session believed were in Dart were false positive string matches.
The real signing runs in the ijiami packed native dex, reached from Dart through a Flutter platform
channel. The one thing that was recovered is the shape of the telemetry `token`, which is a body
independent MD5 keyed on the `timestamp` header and a secret that lives in native code.

## Evidence 1: The Dart Signing Pieces Are False Positives

Searching the blutter object pool (`pp.txt`, `objs.txt`) and the symbolized assembly (`asm/`) for
the signing constants returns only unrelated matches.

| Claimed piece | Actual match | Source |
| --- | --- | --- |
| `signKey` | `Fernet._signKey` | the `encrypt` package |
| `nonce` | `BaseAEADBlockCipher._nonce` | pointycastle AEAD cipher |
| `gToken` | `TagToken`, `StringToken`, `StartTagToken` | the `html` tokenizer |
| `app_key` | `app_keyboard` | aichat UI string |

The distinctive real constants do not appear at all. `AnkerBG`, `gtoken`, `x-auth-token`,
`openudid`, the telemetry host `eufylife`, and the path `push_log_hdfs` return zero hits across
`pp.txt`, `objs.txt`, and `asm/`. A raw `strings` scan of `libapp.so` gives the same result, only the
false positives above.

## Evidence 2: Not In Any Native Library Or The JADX Sources

The signing constants are also absent from every shipped and on demand native library. A `strings`
scan of all `arm64-v8a` `.so` files in `resources/lib/` and in the `soundcoreso` split found none of
`AnkerBG`, `gtoken`, `x-auth-token`, `openudid`, `push_log_hdfs`, or `eufylife`. The only near match
is `id-regCtrl-regToken`, an OpenSSL ASN.1 constant in the BoringSSL derived libraries.
`libcrypto-security.so` is a renamed BoringSSL and exports only generic primitives (`AES_*`, `BF_*`,
`CMS_*`). The JADX sources hold only the ijiami shell (about 300 files, no `com.oceanwing.soundcore`
app classes), because the real dex is packed.

The `soundcoreso` split does carry libraries that matter for later goals, listed here so they are on
record. `libjl_ota_auth.so` (Jieli OTA authentication), `libecc-encryption.so`, `libsecuritytool.so`,
and `libargon2.so`. None of them contain the cloud API signing strings.

## Evidence 3: All HTTP Goes Native Through A Platform Channel

The app has exactly one authenticated Dart API client, the ankerday insight card feature. It does not
make an HTTP request. `InsightCardApi.getOperation` builds a request model and calls
`Bridge.request` in `package:module_flutter/common/channel.dart`, which is a Flutter
`MethodChannel.invokeMethod` call into the native Android layer. The `Anker-X-User-Id` string in
`insight_card_request_model.dart` is a field key in that model, not a header the Dart code signs and
sends. So the Dart layer marshals request models over the platform channel and the native side builds
and signs the actual HTTP request. This is consistent with the prior finding that the P20i is driven
by the packed native layer, not by Dart.

## The Telemetry Token, From The Captured Flows

The `flows` file in the prior session notes is a mitmproxy dump of five `POST` requests to
`log.eufylife.com/push_log_hdfs`. Parsing it (mitmproxy uses a tnetstring container) recovers the
full request headers and bodies. The signed headers are minimal.

```
timestamp: 1788043091
token: 361ec02987361d207d05392b9f0d89e4
AnkerBG: SPEAKER
country: US
language: en
phone_virtual_id: DFC3E714-0121-4B87-9187-22CBA056D1F7
User-Agent: Soundcore-iOS-5.0.21
Content-Type: application/json
```

The body is plaintext JSON. There is no `nonce`, no `gtoken`, no `sign`, and no body encryption or
base64 wrapping. This is a simpler scheme than the newer eufyMake product documented publicly, which
uses HMAC-SHA256 over `timestamp + nonce + encrypted_body` plus an ECDH session (see `Prior-Work.md`
and the charliex2 post).

The decisive observation is that the `token` does not depend on the body. Two `token` and `timestamp`
pairs appear across the five flows, and within each pair the body differs while the `token` stays the
same.

| token | timestamp | body sizes across flows |
| --- | --- | --- |
| `361ec02987361d207d05392b9f0d89e4` | `1788043091` | 2345, 2317, 1045 |
| `436b5cf376c9f57db2bf7d08d2456b52` | `1788043121` | 2025, 1381 |

Same `timestamp` gives the same `token` regardless of body. Every other signed input (`country`,
`AnkerBG`, `phone_virtual_id`, `language`, empty `user_id`) is constant across all five requests. So
the token is a function of the `timestamp` plus fixed values, and the model is

```
token = MD5( timestamp + fixed_secret )   (exact concatenation order unknown)
```

## Why The Token Still Cannot Be Reproduced

Reproducing the token needs the `fixed_secret`. It was not recoverable.

- Offline guessing failed. `MD5` of the timestamp alone, and of the timestamp combined with plausible
  secrets and the constant header values in many orders, plus HMAC-MD5 variants, do not match either
  captured token. The two known pairs were used as an oracle.
- Public sources redact it. The charliex2 write up documents the Anker signing architecture but
  redacts all key and salt values.
- The secret is in native code. Given Evidence 1 through 3, the secret and the exact concatenation
  live in the ijiami packed dex or a native library called over JNI, which is the same wall that
  blocked the prior dynamic work.

An important caveat for Goal 2. This telemetry `token` is the log channel scheme. It is not proven to
be the same scheme as the real `speaker.eufylife.com` API signing, which uses the richer
`gToken`, `nonce`, `sign` set. That host is certificate pinned and no request to it was captured, so
its exact signing is still unknown.

## Consequence For The Plan

Goal 1 as written, reconstruct the signing from the blutter output, is not achievable. The material
is not in the Dart layer. Recovering the signing (and, in the same move, the OTA endpoint and the
firmware download URL) requires getting the app to run far enough to decrypt its dex and then reading
that dex or capturing the live request. The recommended route is a host level emulator freeze that is
invisible to the in guest anti tamper, described in the plan discussion. It is not yet executed.

## Reproduction

The flows parser and the token cracking attempt are small scripts run from the session scratchpad.
They are quick to rebuild. Parse `flows` with a minimal tnetstring reader (types `,` bytes, `;` str,
`#` int, `^` float, `!` bool, `~` null, `]` list, `}` dict), then read each flow's `request` for
`headers` and `content`. The blutter output searched here is the prior session build described in
`../2026-08-29_APK-Firmware-Upgrade-Analysis/Blutter-Setup.md`.
