# Session Status And Blockers

This is the wrap up for the 2026-09-03 session. It records what was proven, what was built, what
was tried and failed, the current blocker, and the decided next direction. Read this first to resume.

## One Paragraph Status

The custom dylib vehicle works and is not detected. Goal 1 passed. The request signing scheme and the
static credentials were fully recovered from the iOS binary. A host side signed client was written.
The blocker is that a replayed firmware check returns `406 Access token expired`, the same as an
unsigned probe, so `406` reads as a generic "not authenticated" rather than a literal expiry. The app
runs logged out yet still authenticates its own calls, so whatever it sends is computable or present
in memory, not tied to an account. Passive capture of the live per request auth values failed because
they are computed just in time and freed, and clean hooking is blocked on this stack. The leading
hypothesis is that logged out requests do not send `gtoken` at all and the `406` is our signature
being wrong, not a missing token. The decided next step is offline reversing to nail the exact
signature, which needs no device runs.

## What Is Proven

- The passive dylib path is viable. A benign, app signed dylib added at re-sign time loads, the app
  boots, and the log is recoverable. No load time library whitelist. See `Summary.md`.
- Static credentials, both Swift string literals in the iOS `__TEXT`.
  - clientId `109c01b71e210048304bd70a1c971d33` at Ghidra `0x103999660`.
  - clientSecret, the HMAC key, `b1c3d818cc952ed054676a7b6a736ad4` at Ghidra `0x1039996b0`.
  - These do not rotate. A re-dump on a later day returned the identical values.
- The config singleton chain, read by the signer, confirmed on device.
  - `holder = *(main_base + 0x5446558)`, `sub = *(holder + 0x10)`.
  - `sub + 0x30` is the config name `netApi`, `sub + 0x40` is the clientSecret key, `sub + 0x48` is
    the bootstrap secret and is empty in this config.
- The signing algorithm, read from the real iOS bodies. See `Signing-Scheme-iOS-Recovery.md`.
  - Session signer `FUN_102d78190`, a hand rolled HMAC-SHA256, ipad `0x36` and opad `0x5c`.
  - `X-Signature = lowercase_hex( HMAC_SHA256( clientSecret, ts + "+" + once [ + "+" + body ] ) )`.
  - Separator `+` is `DAT_1042abbc0`, hex is `FUN_102d37078`.
  - `X-Request-Ts` is a millisecond timestamp, `snprintf("%lld", ...)` in `FUN_102d388ec`.
  - `X-Request-Once` is a generated nonce. `Client-id` and `X-Client-Credential` default to empty in
    the per request header builder.
- `gtoken` is computed client side by `FUN_102ee542c`, `hex(hash(...))` through a global hasher
  `FUN_102d42cbc` keyed off `DAT_1054464c0`, and it is only set inside a branch gated by a user flag,
  `(param_1 + 0x20) & 1`. The `updateUserInfo ... usr = ...` string near it is a debug log line, not
  the hash input.

## Artifacts Built This Session

Under `scripts/ios-dylib/`, all built by `SRC=<file> ./build.sh`, injected with Sideloadly, read
over `pymobiledevice3 syslog live`. See `scripts/ios-dylib/README.md`.

- `scprobe.c`, the Goal 1 hello world probe, marker `SCPROBE_HELLO_WORLD`. Ran, passed.
- `screader.c`, the config credential reader, marker `SCREAD`. Ran, returned the credentials.
- `scharvest.c`, the URL harvester and version forcer, marker `SCHARV`. Ran, see blockers.
- `scheaders.c`, the header value capture by key reference, marker `SCHDR`. Ran, found nothing.

Under `scripts/`, `sign_firmware_request.py`, the host side signed client. It builds the
`OtaRequestModel`, signs per the recovered scheme, and posts. Flags `--swap`, `--no-body`,
`--ts-unit`, `--gtoken`, `--authorization`, `--key-ident`. Dry run by default.

## What Was Tried And Failed

- Signed replay. `sign_firmware_request.py --send` returned `406 Access token expired`, identical to
  the unsigned probe. See `Firmware-URL-Harvest-Pivot.md`. So the signature was never confirmed, the
  server rejects before or without telling us about it.
- Version forcing in app. `scharvest` overwrote the `14.43` version string on the heap, the writes
  succeeded with `kr=0`, but the app still reported `14.43`. The sent version is sourced from the
  earbuds over BLE and held numerically, so the display string is not what the request uses. Patching
  heap strings cannot force it.
- Token capture. `scharvest` extended to log JWTs printed nothing, consistent with being logged out,
  so there is no user bearer token in memory.
- Header value capture. `scheaders` scanned about four minutes for heap pointers to the header key
  constants and found none. The per request header map is transient and freed, so a seconds long scan
  races a millisecond lived structure, or the map copies keys rather than referencing the constants.
- Hooking is blocked on this stack. Ktor uses NSURLSession, whose TLS runs inside already bound system
  dylibs, so a `dyld` interpose or fishhook on `SSL_write` does not catch its internal calls. The
  commonkit signer functions are internal with no symbol to interpose. The only thing that would work
  is an inline hook, which is the anonymous executable memory footprint the anti tamper kills.

## Useful Runtime Facts From The Device

- Logged out, the app still makes successful authenticated calls to `speaker.eufylife.com/api/v2/...`,
  the same host as the firmware endpoint `/v1/speaker/sound_core/A3949/firmware/update`.
- The app carries a full endpoint config template with `*_DOMAIN_PLACE_HOLDER` slots, including
  `OTA_DOMAIN_PLACE_HOLDER`, resolved at runtime from a config fetch. The resolved OTA domain was not
  observed, only the unresolved placeholder.
- Confirmed live hosts include `speaker.eufylife.com`, `aiot-sc-api-pr.soundcore.com`,
  `anka-api-us.soundcore.com`, and the `d2htfo7ft368vg.cloudfront.net` asset CDN.

## The Current Blocker And The Leading Hypothesis

The endpoint returns `406 Access token expired` and we cannot yet tell whether that means a missing
`gtoken` or a wrong signature, because the unsigned probe gets the same message. Two facts point at
the signature, not the token. First, `gtoken` is only set under a logged in user flag, and the tests
were logged out, so the app itself likely sends no `gtoken` for these calls. Second, our replayed
`Client-id` and `X-Client-Credential` were set to the clientId literal, but the app defaults them to
empty for app level calls, which could itself be the rejection.

## Decided Next Direction

Offline reversing to nail the exact signature, no device runs required. The specific questions.

1. Which signer the firmware POST actually invokes, the bootstrap `FUN_102d78e9c` or the session
   `FUN_102d78190`, by tracing the request type discriminants in `FUN_102d7097c`, values `0x5c7`,
   `0x979`, `0xc33`.
2. The exact signed message for that path, in particular whether the JSON body is included, and
   whether the body is signed raw or hashed or encrypted, given `X-Encryption-Info` exists.
3. Whether `Client-id` and `X-Client-Credential` must be empty for an app level call, and whether any
   `X-Key-Ident` is required.
4. Whether logged out sends `gtoken` at all, by resolving the `(param_1 + 0x20) & 1` flag in
   `FUN_102ee542c`.

Then update `sign_firmware_request.py` to match and test once. If the signature still fails and a
`gtoken` is required, reconsider capturing a real request deterministically, accepting that this is
the first non passive step, or fully reversing the `gtoken` hasher `FUN_102d42cbc`.

## Ghidra Reference Map

Preferred base `0x100000000`, so runtime is `main image base + (ghidra - 0x100000000)`.

| Ghidra | Symbol or role |
| --- | --- |
| `0x102d5e760` | `initConfig`, real Kotlin |
| `0x102ee3508` | `doInitConfig` @objc thunk |
| `0x102d5e4dc` | config holder lazy init, writes `0x105446558` |
| `0x102f03264` | Swift config setup, writes `sub + 0x40` directly |
| `0x102d78e9c` | bootstrap signer `encryptByHMAC256` |
| `0x102eee3bc` | `encryptByHMAC256` @objc thunk |
| `0x102d78190` | session signer, hand rolled HMAC-SHA256 |
| `0x102d7097c` | per request signing interceptor |
| `0x102d388ec` | per request base header builder |
| `0x102ee542c` | `gtoken` and identity injector |
| `0x102d42cbc` | global hasher used by `gtoken` |
| `0x102d37078` | bytes to lowercase hex |
| `0x105446558` | config holder pointer global |
| `0x1054464c0` | hasher global for `gtoken` |
| `0x103999660` | clientId literal |
| `0x1039996b0` | clientSecret literal |
| `0x1042abbc0` | `+` separator constant |
| `0x10428fed0` | empty string constant |
| `0x1041c4a31` | Kotlin String TypeInfo |

Header name constants, all Ghidra addresses. `X-Request-Once 0x1042c1830`, `X-Request-Ts 0x1042c1860`,
`Client-id 0x1042c1af0`, `X-Client-Credential 0x1042c1b20`, `gtoken 0x1042c1b90`,
`X-Signature 0x1042c1bb0`, `uid 0x1042c1a70`, `app-name 0x1042c1700`, `language 0x1042c1a40`.
