# The Guest Auth Pathway

This note supersedes one conclusion in `Signature-Offline-Resolution.md`. That note said a logged out
request sends no token and inferred the endpoint needs a logged in user. That inference was wrong. The
firmware endpoint needs an app level token, but the app has one without an account, a tourist session.
This note records the guest pathway, the confirmed `gtoken` algorithm, and the resulting client change.
The goal is a successful script run with no account.

## Why The Account Assumption Was Wrong

Soundcore firmware upgrades work without an account on other products, and the app must be able to
check the version for a logged out user. That cannot be reconciled with a hard user login requirement.
The binary resolves it. The network config object carries a `touristId` right next to `userId` and
`userToken`, seen in the config copy selector.

```
doCopyAppName:domain:exchangeKeyDomain:path:userId:userToken:touristId:iotPublicKey:openUdid:...
```

The connect layer manages this guest identity, with log lines `connect - The tourist ID does not
exist`, `connect - The visitor ID exists`, and `connect - The visitor id needs to be replaced`, at
`0x103999610`, `0x103999640`, and `0x1039995e0`, in the same commonkit cluster as the clientId
literal. So the app is never truly unauthenticated. Logged out it runs on a tourist session, and every
business call, including the firmware check, rides on that. Our static script started cold with no
tourist session, so the gateway reports the absent token as `406 Access token expired`.

## The gtoken Algorithm, Confirmed MD5

`gtoken` is the app level token header, `DAT_1042c1b90`. The identity injector `FUN_102ee542c`
computes it by running the identity through the global hasher `FUN_102d42cbc`, then hex, then setting
the header. The hasher is initialized by `FUN_102d41b38`, which fills a 64 entry constant table from
`floor(abs(sin(i + 1)) * 2^32)` for `i` in `0..63`. That is the MD5 sine constant table, so the
hasher is MD5.

```
gtoken = lowercase_hex( MD5( identity ) )
```

The identity is `userId` when logged in and `touristId` for a guest. This matches the public
`gtoken = md5(user_id)` recovery. The injector also sets `uid` to that identity, and `Authorization`
to the user token, which is empty for a guest.

Correcting question 4 of the other note. The injector gate `(*(byte *)(param_1 + 0x20) & 1)` is not
"is a user logged in". It is "is there a session", and a guest has one, the tourist session. So a
logged out call does send `gtoken`, computed from the `touristId`, and an empty `Authorization`.

## The Signature Key Is The clientSecret, No Key Exchange Needed

The two tier scheme in `../2026-08-31_Ijiami-Buffer-Scrape/Signing-Scheme-Static-Recovery.md` raised
the worry that business calls sign with an ECDH session key, not the clientSecret. The iOS interceptor
`FUN_102d7097c` passes the key `*(sub + 0x40)` to the session signer for business calls. The
`screader` dylib dumped `*(sub + 0x40)` on a running logged out app and it was the static clientSecret
`b1c3d818cc952ed054676a7b6a736ad4`, not a random 32 byte derived key. So the firmware signature key is
the clientSecret and no key exchange is required for the signature. The ECDH `uniqueSign` is for body
encryption, which this small JSON check does not use.

## touristId Origin, Most Likely Server Issued

Where the `touristId` comes from could not be pinned statically. The commonkit connect logic is
Kotlin/Native dispatched through metadata, so the string and selector have only data table references,
no code xrefs to trace. The wording `The visitor id needs to be replaced` implies the server drives
assignment and replacement, which points to a server issued id rather than a locally generated UUID.
`SCCheckRegisterRequestModel` maps to `user/check_register_email`, part of email signup, not the
tourist path, so it is not the source. If the id is server issued, a self generated one will not be
recognized and `gtoken = md5(self_id)` will still be rejected.

## The Client Now Does Guest Mode

`scripts/sign_firmware_request.py` adds the tourist session.

- `--tourist-id VALUE` sets `uid = VALUE` and `gtoken = md5(VALUE)`, self consistent the way the
  injector makes them.
- `--gen-tourist-id` makes a random tourist id, for the cheap test of whether the server accepts a
  client chosen id.
- `--gtoken` still overrides the computed hash with a raw value captured from the app.
- The signature and `X-Client-Credential` are unchanged, both already correct.

## Next Test, A Decision Tree

1. Cheap host side test, one request.

   ```bash
   python3 scripts/sign_firmware_request.py --gen-tourist-id --send
   ```

   If it clears the `406`, the server accepts a client chosen tourist id and we are done host side, no
   capture and no account. Read the body for `lastPackage.url`.

2. If it still returns `406 Access token expired`, the tourist id must be one the server issued. Get
   it from the logged out app. `screader` already walks the config object, so a logged out run after
   the app has connected should surface the `touristId` field. Then send with the real value.

   ```bash
   python3 scripts/sign_firmware_request.py --tourist-id <captured> --send
   ```

   This stays account free, the capture is a plain launch of the logged out app plus the existing
   passive reader, no login. If even a captured tourist id is rejected, the remaining possibility is
   that the tourist session must be established live against the server through the connect flow, at
   which point capturing the live `gtoken` header value directly and passing `--gtoken` is the
   fallback.
