# The Signing Scheme, Fully Recovered From The iOS Binary

The credential reader dump plus a static read of the iOS signer bodies closed every gap the Android
based recovery left open in `../2026-08-31_Ijiami-Buffer-Scrape/Signing-Scheme-Static-Recovery.md`.
The signing is now specified end to end, and the credentials are recovered. This note is the
reference for reproducing a signed request.

## What The Reader Returned

The `screader` dylib dumped the network config singleton at Ghidra `0x105446558`. Runtime base was
`0x102054000`, a slide of `0x2054000`. The config chain the bootstrap signer reads resolved as
follows.

- `holder = *(0x105446558)`, the config holder pointer.
- `sub = *(holder + 0x10)`, the config data object.
- `sub + 0x30` = `"netApi"`, the config name, Ghidra constant `DAT_1042c3e20`.
- `sub + 0x40` = `"b1c3d818cc952ed054676a7b6a736ad4"`, the HMAC key, a heap string.
- `sub + 0x48` = `""`, the bootstrap secret, empty in this config, the `DAT_10428fed0` empty string.

The key at `sub + 0x40` is a 32 character hex string used as UTF-8, 32 bytes, which matches the
"keys are the hex string taken as UTF-8" note from the charliex2 writeup.

## The Credentials

Both credential values are Swift string literals in the iOS `__TEXT`, in one cluster with the
`setupWebsocketConfig()` and `SpeechConfig appName: soundcore_app` log strings.

| Address | Value | Role |
| --- | --- | --- |
| `0x103999660` | `109c01b71e210048304bd70a1c971d33` | clientId, the paired identifier |
| `0x1039996b0` | `b1c3d818cc952ed054676a7b6a736ad4` | clientSecret, the HMAC key |

`FUN_102f03264`, a Swift bridged config setup, writes `sub + 0x40` directly from a Swift config
object field at `+0x78`, then calls `initConfig` with empty `clientId` and `clientSecret`. So the
active signing key is set directly and is `b1c3d818...`. The sibling literal `109c01b71e...` is the
paired clientId. The two are adjacent 32 hex literals, the textbook clientId and clientSecret layout.
The clientId to clientSecret assignment is the most likely reading, and the signer tries the swap as
a fallback.

## The Algorithm

The session signer is `FUN_102d78190`, a hand rolled HMAC-SHA256. The ipad `0x36` and opad `0x5c`
byte xor loops are explicit in the body, and the digest is `PTR_LOOP_104216090`, SHA-256.

- Key, the first argument. In the request interceptor `FUN_102d7097c` the key passed is
  `*(sub + 0x40)`, the clientSecret `b1c3d818...`.
- Message, built with a `+` separator, the `DAT_1042abbc0` constant.
  - No body, `ts + "+" + once`.
  - With body, `ts + "+" + once + "+" + body`.
- Output, lowercase hex. `FUN_102d37078` is a bytes to hex string routine, the classic `0x30` and
  `0x57` nibble base selectors, lowercase.

So the signature is the following.

```
X-Signature = lowercase_hex( HMAC_SHA256( clientSecret, ts + "+" + once [ + "+" + body ] ) )
```

The bootstrap signer `FUN_102d78e9c` has the same shape with message `clientId + ts + once + secret`,
but `secret` is empty here, so the bootstrap path reduces to `clientId + ts + once`. The firmware
update call is a POST with a JSON body, so it takes the session path with the body included.

## The Headers

Names confirmed by reading their string constants.

| Header | Value | Constant |
| --- | --- | --- |
| `X-Signature` | the signature above | `DAT_1042c1bb0` |
| `X-Request-Ts` | the timestamp | `DAT_1042c1860` |
| `X-Request-Once` | the nonce | `DAT_1042c1830` |
| `Client-id` | clientId | `DAT_1042c1af0` |
| `X-Client-Credential` | clientId, set equal to `Client-id` in the interceptor | `DAT_1042c1b20` |

The interceptor reads `X-Request-Ts` and `X-Request-Once` back from the request to sign, so a
reproduction sets those headers to its own timestamp and nonce and signs those exact values. The
signature and the sent values are self consistent, so the timestamp and nonce formats only need to
be values the server accepts, a recent millisecond timestamp and a unique nonce.

## Reproduction

`scripts/sign_firmware_request.py` implements this. It builds the `OtaRequestModel` body, signs
`ts + "+" + once + "+" + body`, sets the five headers plus the contextual identity headers, and posts
to the firmware update endpoint. It prints the request by default and sends only with `--send`. The
options `--swap`, `--no-body`, and `--ts-unit` cover the residual unknowns, the clientId to
clientSecret assignment, whether the firmware call signs the body, and the timestamp unit.

## Residual Unknowns And How They Resolve

- clientId to clientSecret assignment. Try the default, then `--swap`.
- Body inclusion. The session path includes the body, try the default, then `--no-body`.
- Timestamp unit. Try milliseconds, then `--ts-unit s`.
- `X-Key-Ident` and `X-Encryption-Info`. Not set on this static credential path, since there is no
  ECDH session and the body is not encrypted. Add them only if a signed request is rejected in a way
  that points at them.

All of these iterate host side against the endpoint, which is cheap. If every combination is
rejected, the fallback is a live capture. The `screader` dylib polls the config, so re-dumping while
the app is driven to a speaker API call would confirm the active clientId and key, in case this
config is not the one the firmware client uses.
