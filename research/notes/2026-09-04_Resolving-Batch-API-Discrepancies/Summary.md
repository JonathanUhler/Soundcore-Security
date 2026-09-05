# Notes: Resolving Batch API Discrepancies

These notes correspond to the plan in `research/plans/2026-09-04_Resolving-Batch-API-Discrepancies/`.
The plan continues `2026-09-04_OTA-Batch-Request-Capture`, which fully broke the OTA request
transport but could not pull a firmware image because the batch check returned
`needUpdate:false` for a device on the latest version. This session investigated three
discrepancies in the `scbody` first launch logs that might have revealed a hidden pinning field,
resolved all three, hardened `scbody.m` to remove them as variables, and re-tested on device. The
conclusion is that no client controllable field yields a firmware URL, because the batch check has
no package to serve this product.

## Status

- All three discrepancies are resolved. None is a hidden server pin on firmware delivery.
- `scbody.m` was refactored to strip the anti tamper telemetry, scrub the analytics anonymous id,
  and rewrite version, serial, and MAC through one clean table driven helper.
- A device re-test with every one of those factors neutralized, plus a synthetic serial the server
  has never seen, still returned `needUpdate:false`. That is the decisive result of the session.
- The batch check is the only production firmware endpoint in the binary. There is no catalog,
  detail, or download endpoint to pivot to, so no request can reach a package the check will not
  offer.

## Discrepancy 3, The `src=resp` Firmware List Is A Local Parse

The plan flagged capture `#35` in `scbody_firstlaunch_3.log`, a `src=resp` body carrying the true
`14.43` and real serial in a `firmware_list` shape, as possible proof the server knows the true
version. It is not from the server. The `resp` label is a misnomer. That capture is the
`JSONObjectWithData:` hook, a generic deserialize that fires on every JSON parse, most of them
local.

The timing settles it. In `_3.log` the deserialize `#35` is at `.376370`, the encrypted body is not
sent until `#38` at `.377013`, and the real response does not arrive until `#43` at `.470856`. A
response cannot precede its own request by 94 milliseconds, so `#35` is a local parse that runs
while the request is still being built. `_2.log` shows the identical ordering. The genuine server
response is the `upgrade_list` shape at `#43`, and it echoes no version and no serial, only
`needUpdate:false`.

The true values survive in `#35` because the rewrite only touches the serialize path,
`dataWithJSONObject:`. The pipeline is model to HandyJSON string, parse to dict (`#35`, true),
re-serialize (`#36`, true), rewrite (`#37`, fake), encrypt, send (`#38`). So the discrepancy gives
zero evidence of server side pinning.

## Discrepancy 2, `anonymous_id` Is A Keychain Persisted Analytics Id

The plan noted `anonymous_id` `25175005-856F-4AAB-A276-01988F6459F5` is the only identifier constant
across installs. That is confirmed. Across all three first launch logs only `anonymous_id` and
`distinct_id` are constant. The per install `terminal-id`, `Openudid`, `phone_virtual_id`, the
SensorsAnalytics `$device_id`, and the SA `uuid` all regenerate.

Origin, it is the SensorsAnalytics SDK anonymous id, `$lib_version:4.8.3`. It is not hardcoded, a
string search of the binary for the value is empty. The SDK generates a random UUID and persists
it, and on iOS it writes to the keychain, the one store that survives an app uninstall, which is
exactly why it alone persists across reinstalls. The generator lives in
`@rpath/SensorsAnalyticsSDK.framework`, a separate binary not loaded in Ghidra. The main binary
only holds the app wrapper, `SCSensorsDataSdkProvider` and `SCSensorsDataReport+SoundCore`, and a
keychain wrapper, `keychainValueWithIdentifier:appID:` and friends.

It rides only the analytics collector, never the firmware host. The only `httpBody` URL in any log
is `speaker.eufylife.com/.../upgrade_check/batch`, and `anonymous_id` appears exclusively in the SA
serialize events. The firmware backend never receives it directly.

## Discrepancy 1, The Anti Tamper Telemetry Is Off The Firmware Host

The three events, `APP_FIRM_NON_APPSTORE_DOWNLOAD`, `APP_FIRM_SIGNATURE_TAMPER`, and
`JMDetectionResultJailBreak`, are posted to `log.eufylife.com/push_log_hdfs`, a different host from
the firmware API. They carry `product_code:"none"`, empty serial, and empty MAC, so no device
binding and no account, only the per install `uuid`. The app fires them and does not self destruct.

The important caveat, raised by the operator, is that the backend does cross reference telemetry.
Last session proved that lowering the version only in the firmware request gives `402`, but lowering
it in every outgoing packet, telemetry included, flips the check to `SUCCESS`. So a value reported
through telemetry does reach the firmware decision, which is why removing the tamper flags and the
stable identity was worth doing before concluding.

## Changes To `scbody.m`

The rewrite pipeline was cleaned up and extended, all still data only object and string edits, so
the reinforcement SDK sees nothing and the body independent `token` and `unique-sign` still verify.

- `rewrite_body` replaces `rewrite_version_and_sn` and its dead commented predecessor. It is a table
  of `{from, to}` pairs, each with an enable guard. Version is field qualified, serial, MAC, and the
  anonymous id are scrubbed by literal value so every field that carries them changes at once.
- `strip_tamper_events` edits the object graph before serialization. It drops any `events[]` element
  whose `name` is in the tamper set, then serializes the filtered dictionary. That yields valid
  JSON, unlike excising an object from the serialized string. It logs a `STRIP removed N` line.
- `ANON_FROM` and `ANON_TO` scrub the constant analytics id to a synthetic UUID.

## The Decisive Device Test, `scbody_firstlaunch_4.log`

All rewrites landed. The log shows `STRIP removed 1 tamper event(s)` for all three names,
`anonymous_id` and `distinct_id` rewritten to the synthetic UUID in the `json-mod` captures, and the
sent body `#59` carrying serial `3949000000000000` and version `14.42`.

The response `#63` was `res_code:1 SUCCESS, upgrade_list:[{needUpdate:false, lastPackage:null}]`.

This is the clincher. The request used a serial the server has never seen, claiming a version below
the known latest `14.43`, with the tamper flags stripped and the stable identity scrubbed, and it
returned SUCCESS with no update. If the server decided `needUpdate` by comparing the claimed version
against an available package, a fresh device claiming `14.42` would have been offered `14.43`. It
was not. So `needUpdate:false` is not an unspoofed pin, it is the server having no package to serve.

## Why No URL Is Returned

The batch check is a pure availability query, is there something newer for this product now, and for
A3949 the answer is no. That is consistent with three indistinguishable causes, no build newer than
`14.43` exists, the `14.43` push was retired once it became the shipping baseline, or OTA is off for
this product. From the client they are equivalent. All mean the check cannot emit a URL, and no
request forgery conjures a package that does not exist server side.

Two structural facts from Ghidra support this.

- The only production firmware endpoint string is `speaker/firmware/upgrade_check/batch`. There is
  no catalog, detail, list, or download endpoint, so there is no un-gated way to ask for the A3949
  package directly.
- `checkD3200FirmwareUpdate(callback:)`, the P20i is codenamed D3200 and the app route is
  `/d3200/homePage`, lives in `SCFlutterMethodChannel.swift` and only reads a cached `..._firmware`
  value from `NSUserDefaults`. It is a Flutter bridge over cached state, not a second network path,
  and it has no fallback fetch when the server says no update.

## One Loose Thread, The CI Endpoint

The binary hardcodes a CI host endpoint, `https://speaker-ci.eufylife.com/v1/speaker/temp_fireware`,
the misspelling is in the binary. It has no code xref in production, so it is build gated or a dead
leftover, and it points at Anker internal CI infrastructure, so it is a long shot. It is the only
string hinting at a firmware fetch path outside the gated check and is worth closing out before the
network path is declared fully dead.

## Outcome And Future Directions

The API path to the image is exhausted. The transport is fully broken and understood, but the batch
check is architecturally incapable of returning a URL for a device already on the latest firmware
with no newer build published, and it is the only firmware endpoint. The three discrepancies were
red herrings for firmware delivery, though the anonymous id and tamper strip are worth keeping in
the disclosure writeup as privacy and anti analysis findings.

Remaining routes to the image, unchanged from last session.

- Opportunistic capture, `scbody.m` still logs `lastPackage.url` if Anker ever ships a newer build.
  Not expected soon, `14.43` has been latest for over a year.
- The CI `temp_fireware` endpoint, pending analysis of whether it is reachable and how it is gated.
- Hardware, Jieli UBOOT or forced download over UART with `jl-uboot-tool`, or desolder plus SPI.
- BLE cannot read the image, it is a one way push.
