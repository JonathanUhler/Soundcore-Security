# The Eufy Token Scheme, And How The Firmware API Is Actually Called

This note consolidates the firmware auth picture after the anka-api-us detour. The short version is
that the firmware host is `speaker.eufylife.com`, it is eufy infrastructure, and it signs with a
simple `token` plus `timestamp` scheme, not the soundcore ECDH scheme we spent this session chasing.
The evidence is the unpinned `log.eufylife.com` telemetry captured on the real device, in
`../2026-08-29_APK-Firmware-Upgrade-Analysis/MITM-Analysis.md` and its `flows` file.

## The Two Backends

The app talks to two different backends with two different auth schemes.

- The soundcore backend, `anka-api-us.soundcore.com` and `aiot-sc-api-pr.soundcore.com`. This uses
  the aknetwork ECDH scheme, `X-Signature` over an ECDH derived session key, `X-Key-Ident`, per
  service `uniqueSign` keys. All the live traffic in the `scident` sweep was here. See
  `Guest-Auth-Pathway.md` and the derived keys captured there.
- The eufy backend, `speaker.eufylife.com` and `log.eufylife.com`. This is where the firmware check
  and the telemetry go. It uses the token scheme below.

We wasted several probes sending soundcore headers to the eufy firmware host, and one probe sending a
soundcore session key to the wrong host entirely.

## Why speaker.eufylife.com Is The Firmware Host

- MITM on the real device saw a request fire to `speaker.eufylife.com` every time the firmware reload
  button was pressed. It is certificate pinned, so its body did not leak, but the host is confirmed.
- A signed probe to `speaker.eufylife.com/v1/speaker/sound_core/A3949/firmware/update` returned a JSON
  app response, `{"res_code":406,"message":"Access token expired."}`. A JSON app error means APISIX
  routed the request to the backend, so the path exists there.
- The same path on `anka-api-us.soundcore.com` returned a gateway `404 Route Not Found`. Auth failures
  on that backend return 406 or 401, not 404, so the 404 means the route is not defined there. The
  firmware route lives on `speaker.eufylife.com`.

## The Token Scheme

Read directly from the `log.eufylife.com/push_log_hdfs` request headers in the `flows` file. The
request carries these headers and no soundcore signing headers at all.

```
token            32 hex md5 digest
timestamp        unix seconds
AnkerBG          SPEAKER
country          US
language         en
phone_virtual_id the device uuid
User-Agent       Soundcore-iOS-5.0.21
```

Two facts pin the token construction.

- It is body and path independent. Three requests with different JSON bodies but the same
  `timestamp` header all carried the identical token. So the token does not sign the body.
- It is app global, not per device. The token depends only on the timestamp and a fixed secret. The
  capture device uuid `DFC3E714-...` differs from the sideload device uuid `5D95595D-...`, yet the
  scheme is the same, so the secret is not the device id.

The two observed pairs.

```
timestamp 1788043091  ->  token 361ec02987361d207d05392b9f0d89e4
timestamp 1788043121  ->  token 436b5cf376c9f57db2bf7d08d2456b52
```

So `token = md5( timestamp + secret )`, or a close variant. The secret is not `clientId`,
`clientSecret`, the config sha256, the appId, the app version, or any simple concatenation of them.
A wide brute force over those with many separators and orderings, and HMAC-MD5, found no match. The
secret is almost certainly the makeitreal regional 16 byte localKey, which is redacted publicly and is
not brute forceable. It has to be recovered from the binary or captured.

## user_id Is Empty, So It Is App Signed

Every telemetry event had an empty `user_id`. The firmware check runs with no logged in user. This
confirms the account free premise. The scheme is app signed, and the MITM note already concluded it is
replayable.

## How To Call It, Two Paths

The body and path independence of the token gives a path that needs no secret.

Path one, capture and replay. `log.eufylife.com` is not pinned. Capture a live `timestamp` and
`token` pair off any telemetry POST, then send the firmware request to `speaker.eufylife.com` with
that same `timestamp` and `token`, plus `AnkerBG`, `country`, `language`, and a low `version` body.
Because the token does not depend on the body or the path, the captured token is valid for the
firmware request too, as long as it is sent inside the server freshness window for that timestamp.

```bash
python3 scripts/sign_firmware_request.py --host speaker.eufylife.com \
  --eufy --eufy-timestamp <captured> --eufy-token <captured> --send
```

This is also the cheapest confirmation of the whole theory. If it returns firmware metadata, the host,
the scheme, and the token are all correct. If it fails, the firmware host wants something the
telemetry host does not, and we recapture.

Path two, recover the localKey. Once the localKey is recovered from the binary, the token is
computable for any fresh timestamp, with no timing pressure.

```bash
python3 scripts/sign_firmware_request.py --host speaker.eufylife.com \
  --eufy --eufy-localkey <localKey> --send
```

The exact concatenation, `timestamp + localKey` versus a variant, is verified against the two known
pairs above once the localKey is in hand.

## Result, Auth Is Solved And The Token Does Not Expire

Path one worked. A captured `timestamp` and `token` pair sent to the firmware endpoint returned an app
level success.

```json
{ "res_code": 1, "message": "SUCCESS", "needUpdate": false, "lastPackage": null }
```

So the host, the eufy scheme, the endpoint, and the token are all correct. Auth is done, and it is
account free.

The token also does not expire. The same pair from the 2026-08-29 flows, `timestamp 1788043091` and
`token 361ec02987361d207d05392b9f0d89e4`, still returns `res_code 1` days later. The server checks only
that `token == md5(timestamp + secret)`, not that the timestamp is recent. So the captured pair is a
permanent reusable credential, and there is no freshness window to beat. That pair is baked into
`sign_firmware_request.py` as the default, so `--eufy` needs no capture. Recovering the localKey is no
longer required for auth, only to regenerate a token if this one is ever revoked.

## The Real Endpoint Is The Batch Check, And Its Schema Is The New Blocker

The simple endpoint returns success but `needUpdate false` no matter the `version` or `sn`, so it does
not serve the A3949 firmware. The iOS app checks firmware through the batch endpoint instead. The
string `speaker/firmware/upgrade_check/batch` is in the binary, and the model is
`SCOTAMultipleRequestModel`, matching the Android `CheckOtaUpgradeCommand`, a POST to
`api/v2/speaker/firmware/upgrade_check/batch` whose body wraps a list of firmware requests.

The blocker is the exact request schema. Every attempt returns `{"res_code":400,"message":
"Err_InvalidRequest"}`, an app level validation error, not an auth error, since the token is accepted.
Tried and failed.

- `{"firmware_list":[{ snake_case item }]}`, the Android `@SerializedName` shape.
- `{"firmwareList":[{ snake_case item }]}`.
- `{"firmwareList":[{ camelCase item }]}`, minimal, then with `productComponent` empty and set to
  `A3949`, then with `productLanguage`.

The iOS models are camelCase. The reflection field records show `firmwareList` at `0x103aec91d` and
`wifiVersion` at `0x103aec911`, both camelCase, and the snake_case strings like `product_component`
belong to the response model. So the request is camelCase, but the exact required fields of the item,
`SCOTAMultipleItemStruct`, are not confirmed, and one required field or a type is still wrong. The
Android method bodies that build the request are stubbed by the lazy code paging limit, and the Swift
`mapping` and the item field descriptor could not be resolved cleanly from static analysis.

`sign_firmware_request.py` now has `--batch`, `--batch-key`, `--product-component`, `--product-language`,
`--base-version`, `--matched`, and `--raw-body` to iterate the schema by hand. Because the token is body
independent, any body can be tried with no re-auth.

## What Is Left

Resolve the batch request schema. Static analysis has stalled on it, so the decided next step, in the
`2026-09-04_OTA-Batch-Request-Capture` plan, is to observe a real batch body from the running app with
the passive dylib, extending `scident` to capture the serialized `firmwareList` JSON when the operator
taps check for update. That hands over the exact object. Then lower the `version` to force
`needUpdate true`, read `lastPackage.url`, and download the firmware from the unpinned CDN.