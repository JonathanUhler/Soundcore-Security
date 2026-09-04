# Notes: OTA Batch Request Capture

These notes correspond to the plan in `research/plans/2026-09-04_OTA-Batch-Request-Capture/`.
The plan continues the iOS Custom Dylib Monitor work. Auth to the firmware API is solved and account
free. The one blocker is the exact request schema for the batch check,
`POST api/v2/speaker/firmware/upgrade_check/batch`, model `SCOTAMultipleRequestModel`, where every
hand guessed body returns `{"res_code":400,"message":"Err_InvalidRequest"}`. This session built the
capture vehicle for the real body and gathered the static evidence explaining why guessing failed.

## Status

- First vehicle failed on device. `scripts/ios-dylib/scjson.c` swept the writable heap for the
  serialized body but caught nothing across many taps. The string is freed faster than a full heap
  pass, so racing it passively does not work. Kept for reference and the object-walk fallback note.
- Second vehicle worked. `scripts/ios-dylib/scbody.m` captured both the plaintext JSON and the
  actual wire body by ObjC swizzling, no race, first try. See `scbody.log`.
- The real finding, the batch body is an encrypted envelope, not plaintext JSON. That is why every
  guessed JSON shape, and the captured plaintext replayed directly, all return `400
  Err_InvalidRequest`. The plaintext schema was never the blocker. See the section below.
- The envelope is forgeable without the key, confirmed live. It is a malleable stream cipher with no
  MAC, so a version forced body is forged by XOR with a recovered keystream. A verbatim replay
  returned `res_code 1 SUCCESS`, and a forged body returned `402 Err_InvalidParameter`, a semantic
  error past auth and decryption. That proves `token` and `unique-sign` are body independent and the
  forgery decrypts server side. `scripts/forge_batch_check.py` automates the recovery, forge, and
  probe from `scbody.log`.
- The wall is server side version validation, not crypto. A sweep of forged versions showed the
  server accepts only `14.43` and `14.44` and rejects every other value with `402
  Err_InvalidParameter`. `14.44`, a single byte forge, succeeding proves the forgery decrypts
  correctly server side, so the failures are semantic. Downgrade forcing does not work, the server
  rejects a made up old version. Both accepted versions return the same small response, so this
  device is offered no update.
- Remaining, read the response. It is an encrypted envelope, so any `currentFirmware` or
  `lastPackage.url` must be decrypted, with the recovered `localKey` or by capturing the app's own
  decryption in process.

## Why The Schema Resisted Static Analysis

The OTA models live in the Swift `ModuleOTA` framework, file `SCOTAMultipleRequestModel.swift`, and
serialize through HandyJSON and ObjectMapper, both linked as `@rpath` frameworks. HandyJSON emits a
Swift `String`, UTF-8 backed, which becomes the UTF-8 `Data` body. There is no Kotlin serialization
on this path, the `kotlinx.serialization` symbols belong to the unrelated SpeechKit module.

The field name evidence is the Swift reflection string pool at `0x103e028f0`. Read in order it
holds, among neighbours from other models, this run.

```
product_code  sn  version  wifiVersion  firmwareList  all  device  box  productCode
productComponent  productLanguage  relationSn  productCode  body  upgradeList
```

Two facts fall out. The wrapper key is `firmwareList`, camelCase, confirmed again at `0x103aec91d`
and referenced by a HandyJSON mapping descriptor at `0x104565b80`. The item fields appear in two
styles at once, snake_case `product_code`, `sn`, `version` sitting right next to camelCase
`wifiVersion`, `productComponent`, `productLanguage`, `relationSn`. The Swift mangled field records
add more, `product_code` as `String?`, `wifi_Version` as a non-optional `String`, `base_version` and
`product_language` as `String?`. So the metadata does not agree with itself on snake versus camel,
which is exactly why the three shapes tried last session all returned `400`. One of the item fields,
or its case, or a required non-optional like `wifi_Version`, was wrong in every guess.

The only reliable answer is to read the JSON the app actually serializes, rather than keep guessing
against ambiguous metadata.

## First Try, The Passive Heap Sweep scjson.c, Failed

`scjson.c` swept every readable, writable region on a tight loop looking for a JSON object prefix,
re-read a bounded window from each hit, walked it quote and brace aware, and logged any object with
the `firmwareList` wrapper key or two OTA markers. It is a pure read only vehicle, no writes, same
footprint as `scident`. On device it caught nothing across many taps. The serialized string is freed
faster than a full heap pass, so racing it passively does not work. The file is kept as a record and
because its heap walk is the basis for the object-walk fallback below.

## The Deterministic Capture scbody.m

The fix is to stop racing and stand at a fixed choke point the body must pass through. `scbody.m`
does that by ObjC method swizzling, and it is important that this is still not a Frida agent and not
an inline hook.

The reason it survives where Frida died is that swizzling changes data, not code.
`method_setImplementation` swaps an `IMP` pointer inside a class method list, a `__DATA` structure,
and the replacement is ordinary, validly signed code inside this dylib's own `__TEXT`, which AMFI
runs because it is file backed. Nothing patches an existing instruction, builds a trampoline, or
allocates anonymous executable memory. Every detector the SDK has actually demonstrated,
`HOOK_ATTACK`, code integrity of function bytes, the `_dladdr` code redirection checks, targets code
tampering, so a data only `IMP` swap is invisible to them. The residual risk is a generic swizzle
detector, but those target the SDK's own protected methods and known jailbreak selectors, not a
Foundation JSON or URL method.

It swizzles two choke points, both confirmed present in the binary.

- `+[NSJSONSerialization dataWithJSONObject:options:error:]`, selector at `0x103b602d0`, class
  imported at `0x1054dd520`. ObjectMapper `toJSONString` at `0x1055ae2ea` and HandyJSON
  `toJSONString` at `0x1055bcc2f` both funnel their dictionary to string step through this method,
  so the serialized `Data` is captured the instant it is produced, before it can be freed.
- `-[NSMutableURLRequest setHTTPBody:]`, selector at `0x103ba6501`, reached by the Swift
  `URLRequest.httpBody` setter at `0x1055a6111`. This is the network boundary, so whatever bytes the
  app is about to send pass through here regardless of how they were built. It is filtered by the
  request URL, forcing a capture when the URL is the batch endpoint.

Each replacement calls the original by saved `IMP`, never by `objc_msgSend`, so there is no
recursion, and returns the original result unchanged, so there is no behavioral tell. A captured
body is logged uncapped and chunked exactly like `scjson`, a `CAPTURE #n src=... BEGIN` line,
then `#n seg k/m` lines, then `CAPTURE #n END`, deduped by content hash under a lock so two queues
cannot interleave a capture. `src` is `json` or `httpBody`.

## What The Capture Showed

Every check for update produced a pair in the log. A `json` capture at `NSJSONSerialization`, the
plaintext, and immediately after it an `httpBody` capture to the batch URL, the actual wire body.
They are different objects, and the wire body scored zero markers, so the field names are not in it.

The plaintext, capture `#59`, is the real schema.

```json
{"firmware_list":[{"sn":"3949E7BDE52DB6F4","relation_sn":"","product_code":"A3949","product_component":"ALL","version":"14.43"}]}
```

So the wrapper key is `firmware_list`, snake_case, and the item is snake_case, `sn`, `relation_sn`,
`product_code`, `product_component` set to `ALL`, and `version` `14.43`. There is no
`product_language`, no `base_version`, no `wifiVersion`, no `matched`. This settles the schema
question, but the schema was never the blocker.

## The Batch Body Is An Encrypted Envelope

The blocker is that the plaintext JSON is not what goes on the wire. The actual body, capture `#60`,
is a base64 string that decodes to this.

```
base64( ts_ascii[16] || ciphertext[129] )
```

The first 16 bytes are an ASCII microsecond timestamp, `1788546770331674`, generated fresh per
request, matching the capture time to the microsecond. The rest is ciphertext, and its length equals
the plaintext length, 129, so this is a stream cipher, and there is no MAC or tag. Almost certainly
AES-128-CTR with the 16 byte timestamp as the IV and the makeitreal `localKey` as the key, the same
key behind `token = md5(ts + localKey)`.

This is why every attempt returned `400 Err_InvalidRequest`, including the captured plaintext
replayed directly. The endpoint wants the encrypted envelope, and a plaintext body fails validation
regardless of the token or timestamp paired with it. The simple `sound_core` endpoint accepts
plaintext, the batch endpoint does not, an asymmetry worth remembering.

On the timestamp freshness question. The timestamp matters, but as the crypto IV embedded in the
body, not only as a header gate. The permanent captured token still authenticates, but the body must
be a valid envelope, and the embedded timestamp derives the keystream. Whether that embedded
timestamp is also freshness checked is the open question the header replay will answer.

## Malleability, A Forged Body Without The Key

Because the cipher is a stream cipher with no MAC, and both the plaintext `#59` and the ciphertext
`#60` are in hand, the 129 byte keystream is recovered by XOR. A modified body can then be forged
without the key, as long as it keeps the same length and the same embedded timestamp, so the
keystream still aligns. A version forced body, `14.43` changed to `00.00`, was forged this way and
round trips cleanly. The recovery and forge are one small script over `scbody.log`.

The limit of this path is that the forgery reuses the captured timestamp, so it works only inside
that timestamp's freshness window, if one exists. The general fix is to recover the `localKey` and
the exact AES-CTR construction from the binary, which lets a fresh timestamp body be encrypted at
will, with no timing pressure, and confirms the token scheme at the same time.

## The Batch Auth Headers

A second capture pass logged the headers, in `scbody.log` captures `#21`/`#22` and `#49`/`#50`. The
batch endpoint uses a hybrid header scheme, not the pure `token` plus `timestamp` the telemetry host
used. That earlier note was about `log.eufylife.com`, this endpoint is stricter.

```
token           md5(ts + localKey), 32 hex, fresh per request
X-Request-Ts    unix seconds, matches the body embedded timestamp
X-Request-Once  a fresh UUID nonce
unique-sign     32 hex, fresh per request, keyed by an unrecovered secret
Gtoken          f0be43d1ade9a039ca82efae10580425, constant, md5 of an unknown identity
X-App-Key       soundcore
AnkerBG SPEAKER, country US, language en, Openudid/terminal-id/phone_virtual_id the device uuid
Content-Type    application/json
```

Two facts pin the timestamp. The body embedded microsecond timestamp's integer seconds equal the
`X-Request-Ts` header, for both captures, `1788548753` and `1788548764`. So the header timestamp and
the body IV are the same clock, minted together per request. And the keystream differs per
timestamp, consistent with AES-CTR keyed on the timestamp IV.

`token` and `unique-sign` do not derive from any known value. A brute force of both against the
clientId, clientSecret, gtoken, the device ids, the body, and the plaintext, with md5, sha1, sha256,
plain and HMAC, up to four element combinations and seven separators, found no match. So both are
keyed by the unrecovered `localKey`. `token` is body independent, established earlier. Whether
`unique-sign` covers the body is the pivotal open question, because it decides if a forged body can
reuse a captured `unique-sign`.

## The Decisive Test, Result

The `#50` body was replayed verbatim with its captured headers, then a version forced `#50` body,
`14.43` to `00.00`, with the same headers. `scripts/forge_batch_check.py` recovers the keystream,
the IV, and the headers from `scbody.log` and forges the body.

- Verbatim returned `res_code 1 SUCCESS`. The envelope format, the full header set, and freshness
  are all accepted. Freshness is lenient, at least minutes, consistent with the token not being
  freshness gated. The forgery transport is proven.
- Forged `00.00` returned `res_code 402 Err_InvalidParameter`. This is a semantic parameter error,
  not `Err_InvalidRequest` and not a signature error, so it is reached only after auth passes and
  the body is decrypted and parsed. Three conclusions follow. `token` and `unique-sign` do not cover
  the body, so no key is needed to forge. The keystream forgery decrypts correctly on the server.
  And `00.00` is simply an invalid version value, the wrong number, not a broken request.

So the exploit transport works and the pivotal `unique-sign` question is answered, it is body
independent. What it cannot do is covered next.

## The Wall Is Server Side Version Validation

A sweep of forged versions settled what the forgery can and cannot do. Only `14.43` and `14.44` are
accepted, every other value tried, `14.42`, `14.41`, `14.40`, `14.10`, `14.00`, `13.99`, `13.00`,
`10.00`, `01.00`, and the higher `14.45`, `14.50`, `14.90`, returns `402 Err_InvalidParameter`.

`14.44` is the key clue. It is a single byte forge of the captured `14.43`, and it succeeded, which
is only possible if the server decrypted our forged ciphertext to exactly `14.44`. A garbling cipher
would have failed that same single byte edit, as `14.42` did. So the cipher is a pure stream cipher,
the keystream is right, and the forgery decrypts correctly server side. The failures are therefore
semantic, not crypto.

The server validates the reported `version` against what it knows for this device and product, the
installed `14.43` and the adjacent `14.44`, and rejects arbitrary values. Both accepted versions
return the same small `107` byte response, so neither is offered an update. The consequence is that
the request auth and body encryption are fully bypassed, forgeable without a key and replayable, but
downgrade forcing does not work, so an up to date device is handed no package by an honest check.

## The Response Is Also Encrypted

The success response carries a `data` field that is the same envelope, base64 of a 16 byte IV prefix
followed by stream ciphertext. The IV here is a 16 character hex nonce, not a timestamp. The no
update plaintext is only 91 bytes, so an update response with `lastPackage` is much larger. That
signals an update by size even before it is decrypted. Reading `lastPackage.url` in the clear needs
either the `localKey`, to decrypt offline, or the app's own decryption captured in process.

## What Is Left

- Read the decrypted response to get the ground truth for this device, whether a `currentFirmware`
  or `lastPackage` url or an md5 is present even without an update. Keyless, extend `scbody.m` to
  hook `+[NSJSONSerialization JSONObjectWithData:options:error:]`, the app decrypts the response.
  Confirm against the app UI, whether it showed up to date or an update to `14.44`.
- If the honest response carries no url, recover the `localKey` and the AES-CTR construction in
  Ghidra, near the request adapter, `CCCrypt` and `kCCAlgorithmAES`. That decrypts every response
  and reproduces the whole request offline, and clarifies the version validation.
- Consider other routes to the image. The firmware may be reachable through a CDN url pattern from
  the product code and version, or a firmware history endpoint, rather than an upgrade check that a
  current device fails.
- Download the firmware from the unpinned CDN with `curl`. That image is the goal of the plan.
