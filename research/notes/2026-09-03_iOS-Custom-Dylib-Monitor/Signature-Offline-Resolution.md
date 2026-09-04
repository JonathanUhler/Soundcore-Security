# Signature Offline Resolution

This note closes the four questions that `Session-Status-And-Blockers.md` left for offline reversing.
Every finding here comes from static reads of the iOS binary in Ghidra, no device runs. The headline
result is a concrete bug in `scripts/sign_firmware_request.py`. It sent `X-Client-Credential` as the
raw clientId literal, but the app computes that header as a hash. The signature itself was already
correct. This resolves the leading hypothesis from the blocker note, the `406` was very likely our
wrong `X-Client-Credential`, not a missing token.

## Question 1, Which Signer The Firmware POST Invokes

The per request interceptor `FUN_102d7097c` splits at the top on whether the request URL is the ECDH
key exchange. The discriminant string `DAT_1042c46c0` decodes to `openapi/oauth/key/exchange`. The
firmware POST is not that URL, so it takes the business request branch, `(int)uVar6 == 0`.

Inside that branch the interceptor switches on the request body object type at `*(body + 0x5c)`, with
type ids `0x979`, `0xc33`, and a default. A JSON body, which is what `OtaRequestModel` serializes to,
falls through to the default arm. That arm extracts the body bytes and calls the session signer
`FUN_102d78190` with the body included. So the firmware POST uses the session tier with the body, not
the bootstrap tier. This confirms the assumption in `Signing-Scheme-iOS-Recovery.md`.

## Question 2, The Exact Signed Message

The session signer `FUN_102d78190(key, ts, once, body_or_0, out)` was read end to end.

- The message is built with the `+` separator `DAT_1042abbc0`. No body gives `ts + "+" + once`. With
  a body it gives `ts + "+" + once + "+" + body`.
- The body is signed as its raw UTF-8 string. It is not hashed and not encrypted on this path. The
  `X-Encryption-Info` worry from the plan does not apply here.
- The output is `lowercase_hex(HMAC_SHA256(key, message))`. The ipad `0x36` and opad `0x5c` xor loops
  are explicit in the body, and the digest object is the SHA-256 vtable `PTR_LOOP_104216090`.
- The key is `*(sub + 0x40)`, the clientSecret `b1c3d818cc952ed054676a7b6a736ad4`, passed straight
  from the config by the interceptor. The clientId to clientSecret assignment is settled, no swap.

So the `X-Signature` computation in `sign_firmware_request.py` was already correct. The default flags,
include body and millisecond timestamp, match the app.

## Question 3, Client-id And X-Client-Credential

This is the bug. Both headers start empty and one is then overwritten with a hash.

The base header builder `FUN_102d388ec` constructs a fresh header map per request. Near the end it
sets `Client-id` (`DAT_1042c1af0`) to the empty string `DAT_10428fed0`, and `X-Client-Credential`
(`DAT_1042c1b20`) to the empty string. It also sets `Authorization` (`DAT_1042afd80`) to empty,
`X-Request-Ts` to a `%lld` millisecond timestamp, and `X-Request-Once` to a generated nonce.

Nothing in the request pipeline writes a non empty `Client-id`. The only other references to that key
are `initConfig`, which stores the value in the config object, and the interceptor, which reads it. So
`Client-id` is sent empty for a logged out app level call.

The interceptor then computes `X-Client-Credential`. Disassembly at the call site is unambiguous.

```
102d7105c  bl   0x102d78e9c      ; bootstrap signer, returns the hash in x0
102d71060  mov  x2, x0           ; x2 = the hash, this is the value that gets set
102d71064  adrp x1, 0x1042c1000
102d71068  add  x1, x1, #0xb20   ; x1 = 0x1042c1b20 = "X-Client-Credential"
102d7106c  mov  x0, x24          ; the request
102d71070  bl   0x102c0a244      ; setHeader(request, "X-Client-Credential", hash)
```

The bootstrap signer `FUN_102d78e9c(clientIdValue, ts, once, out)` builds `clientIdValue + ts + once
+ secret` with no separators, where `secret = *(sub + 0x48)`, the bootstrap secret, empty in this
config. It then returns `lowercase_hex(SHA256(message))`. This is a plain SHA-256 of the
concatenation, not an HMAC. There are no ipad or opad loops in this body.

So the app sends the following, using the same `ts` and `once` that are in the headers.

```
Client-id           = ""                                         (logged out)
X-Client-Credential = lowercase_hex( SHA256( "" + ts + once + "" ) ) = SHA256_hex( ts + once )
```

The old script sent `Client-id` and `X-Client-Credential` both equal to the clientId literal. That is
almost certainly why the signed replay was rejected the same as the unsigned probe.

## Question 4, Whether Logged Out Sends gtoken

No. The identity injector `FUN_102ee542c` sets `gtoken` (`DAT_1042c1b90`), `uid` (`DAT_1042c1a70`),
and `Authorization` (`DAT_1042afd80`) only inside the branch gated by `(*(byte *)(param_1 + 0x20) & 1)
!= 0`, a user session flag. When the flag is zero, none of the three are set, and the debug line
`updateUserInfo tk = ... , usr = ...` decoded from `DAT_1042c40b0` and `DAT_1042c4010` confirms this
is the identity path. So a logged out firmware check carries no `gtoken` and no `Authorization`. The
`406` cannot be a missing or expired one of those unless the endpoint requires a session the app never
attaches when logged out.

## What Changed In The Client

`scripts/sign_firmware_request.py` now mirrors the app exactly.

- `Client-id` defaults to empty. The flag `--client-id-header` sets it, for the alternate hypothesis
  that the endpoint wants the literal there.
- `X-Client-Credential` is computed as `lowercase_hex(SHA256(clientIdValue + ts + once + secret))`
  from whatever `Client-id` is sent, using the same `ts` and `once` as the signature, so the two stay
  self consistent the way the interceptor makes them. The flag `--bootstrap-secret` overrides the
  secret, empty by default.
- The `X-Signature` path is unchanged, it was already correct.

## Live Test Result, The Gate Is A User Token

The corrected client was sent. Every variant, empty `Client-id`, the clientId literal in
`--client-id-header`, `--swap`, and `--ts-unit s`, returned the identical body.

```json
{ "res_code": 406, "message": "Access token expired." }
```

Identical output across all signature and credential variants means the gateway rejects on a token
gate that runs before it ever evaluates the signature. So the credential fix was necessary but not
sufficient, the request never reaches the signature check.

The base header builder confirms why. Its full header set is device and request context only,
`app-name`, `app_version`, `model-type` = `PHONE`, `os_type`, `os_version`, `phone_model`, `country`,
`openudid`, `timezone`, `sn`, `language`, `uid`, `X-Request-Ts`, `X-Request-Once`, `X-Replay-Info`,
`X-Encryption-Info`, `Cache-Control`, and the three empties `Authorization`, `Client-id`,
`X-Client-Credential`. None of these is an app level token. So a logged out request carries no token
at all, its only auth material is `X-Signature` and `X-Client-Credential`.

This is consistent across three independent facts, and they converge on one conclusion.

- The identity injector attaches `gtoken`, `uid`, and `Authorization` only under the login flag.
- The base builder carries no token, so logged out there is nothing to attach.
- The harvest pivot already recorded that the app itself cannot check firmware while logged out and
  needs a valid session first, see `Firmware-URL-Harvest-Pivot.md`.

The message is `Access token expired`, not an invalid signature error, and the word expired implies a
time bounded server issued credential. That is a user session token, not the static client identity.
The firmware update endpoint requires a logged in user, and neither the app nor a static host side
client has that token when logged out. There is no anonymous or purely static path to this endpoint.

## What This Means For The Path

A static reproduction from clientId and clientSecret cannot pass this endpoint. The remaining work
needs live session state from a logged in app. The signature and credential are now correct, so the
only missing input is a valid `Authorization` token, and its `uid` if `gtoken` is also required.

The cleanest route keeps host side control of the request body, which matters because the version
field must be forced low to make the server return a download URL, and forcing it on device failed
since the version comes from the earbuds over BLE.

1. Log into the app on the device.
2. Capture the live user token, and the `uid`, from the logged in app with a passive reader, the same
   footprint as `screader`. The token source location is the next offline reversing target, or the
   existing `scharvest` heap scan can be pointed at it since a logged in run should surface the token
   that was absent when logged out.
3. Feed the token to the corrected client, `--authorization` and if needed `--gtoken`, with a low
   `--version`. The corrected signature and credential plus a valid token should clear both gates and
   return `lastPackage.url`.

The alternative, reproducing login and the ECDH key exchange fully host side, is more crypto reversing
for the same result and is only worth it to stay fully off device.
