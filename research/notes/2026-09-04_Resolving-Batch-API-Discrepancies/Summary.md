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

The API path looked exhausted at the time of writing, but that was later disproven, see the version
spoof addendum below. The batch check does return a URL when a package exists and the reported
version is lowered below it. What holds is that the transport is fully broken and understood, that
the batch check is the only firmware endpoint, and that a device genuinely on the latest build with
no newer package is offered nothing. The three discrepancies were
red herrings for firmware delivery, though the anonymous id and tamper strip are worth keeping in
the disclosure writeup as privacy and anti analysis findings.

Remaining routes to the image, unchanged from last session.

- Opportunistic capture, `scbody.m` still logs `lastPackage.url` if Anker ever ships a newer build.
  Not expected soon, `14.43` has been latest for over a year.
- The CI `temp_fireware` endpoint, pending analysis of whether it is reachable and how it is gated.
- Hardware, Jieli UBOOT or forced download over UART with `jl-uboot-tool`, or desolder plus SPI.
- BLE cannot read the image, it is a one way push.

## Addendum, A30 Cross-Device Validation

A second device, the Sleep A30, product code D1301S, was captured to test whether the batch check
behavior is P20i specific or general. The A30 is higher end, BLE based, and importantly the operator
has updated its firmware before, so the API is known to serve it packages. Both the buds, `01.07`,
and the charging case, `01.01`, are on the latest. The capture is `logs/a30_1.log`, taken with
`scbody.m` in the new `MONITOR_ONLY` read only mode, which worked as intended, no edits and full
capture.

The result is the same wall. The A30 uses the exact same endpoint,
`speaker.eufylife.com/api/v2/speaker/firmware/upgrade_check/batch`, the same encrypted envelope
transport, and the same schema. The real check sends two items, the buds at `01.07` and the case at
`01.01` with the buds sn as `relation_sn`, and the response returns `needUpdate:false,
lastPackage:null` for both. A later single bud check repeats it. So a device with a real update
history, currently on the latest, is offered nothing, exactly like the P20i.

This looked like it closed the last doubt, but a30_2 later showed otherwise, see the version spoof
addendum below. The check is inventory gated, but the reported `version` is a client field that does
move it. The A30 was simply on the latest here, so nothing newer existed to offer. The firmware body
carries only `sn`, `version`, `product_code`, `product_component`, and `relation_sn`, no MAC, no
UUID, no account, so the version is the lever.

Other observations from the A30 capture, none of which are the device image.

- `sound_mix/firmware/find` is a second endpoint the P20i never called, but its "firmware" is sleep
  sound presets, not the SoC image. The request carries `ids` and `firm_preset_ids`.
- `/resource/music/sleep_list/get/for_product` returns the sleep sound catalog. The sounds are plain
  files on the CDN, for example `d2htfo7ft368vg.cloudfront.net/music_resource/ci/..._Keyboard.wav`
  and `anker-speaker.s3.us-west-2.amazonaws.com/white_noise/A6611/ci/wav/Train.wav`, each with an
  `md5` field. The A30 resource bundles `d1301_home_audio.zip` and `d1301_home_resource.zip` sit at
  `cloudfront.net/upload_file/prod/` and download without auth. These are content and assets, not
  the Jieli firmware.
- The large base64 `resp` blobs near the firmware captures are encrypted content list envelopes,
  sound presets, sleep list, app resources, not firmware. One large decrypted `resp` is a flat array
  of numbers, most likely audio waveform data for the sound player, not UI coordinates.
- `dts-log.anker.com/sa?project=production` is the SensorsAnalytics collector. Its body is
  `crc=...&gzip=1&data_list=<gzip+base64>`, the batched anonymous id events. This is a third host,
  separate from the firmware API and the `log.eufylife.com` HDFS sink.

## Addendum, The A30 MAC Field Is A Hex Encoded UUID

On the A30 the telemetry `mac` field is not a MAC. It is a long colon separated hex string, for
example `30:33:45:44:31:36:35:41:2D:...`, which decodes byte by byte as ASCII to the UUID
`03ED165A-9DDF-3A76-EC03-CC0B31AF80C1`. On iOS the app cannot read a Bluetooth MAC, so for this BLE
device it appears to take a UUID string and hex encode each character into the MAC shaped field. The
P20i, classic Bluetooth, reported a real MAC instead.

Searching `logs/a30_1.log`, the decoded UUID appears nowhere in plaintext, zero hits for the full
value or any distinctive substring. Only the hex encoded form appears, in the `mac` field of
telemetry events, and never in a firmware or upgrade body. It is also distinct from every other
identifier in the log, the SA `$device_id` idfv, the `device_id`, the `terminal-id`, and the SA
`uuid`. So it is a separate identifier, most likely the BLE peripheral identifier, that the app only
ever emits in this encoded telemetry form. It is not a firmware pin.

## Addendum, A Version Spoof Yields A Firmware URL On The A30

The a30_1 conclusion, that the check has no client field that moves it, was wrong. A second A30 run,
`logs/a30_2.log`, rewrote only the buds version, `01.07` to `01.05`, a real prior version from
Reddit, kept the real serial, and left everything else untouched. The check returned
`needUpdate:true` with a full `lastPackage`, the first positive firmware response of the project.

The recipe, confirmed from the log. The real buds serial `13017CE9136B47AC` was preserved, the
version was lowered by `rewrite_body` across telemetry and check together, and there was no serial,
MAC, or anonymous id scrub. The synthetic anon `7F3C1A2B...` never appears and the real anon is
present throughout, so the anon scrub was off. The case, `D1301S-Box` serial `1301S11288A13E97C` on
`01.01`, was left real and returned `needUpdate:false`, so only the buds, claiming to be behind,
were offered a package.

The `lastPackage` schema, capture `#81`.

```json
{"id":"8e885caf-e6e2-4607-8877-ccd91502bc63","product_code":"D1301S","product_name":"Sleep A30 Special","product_component":"ALL","version":"1.07","is_forced":false,"can_return":true,"md5":"cdca27d1f975fac8609ecaff70ab7fbc","change_log":"1. Optimized tap controls\n2. Bug fixes and other improvements","url":"https://d2htfo7ft368vg.cloudfront.net/upgrade/prod/1775099301461220_D1301S_ota_01.07_release_20260304162801.bin","size":1313572,"update_time":1776850177,"upgrade_scheme":0,"ext":{"file_name":"D1301S_ota_01.07_release_20260304162801.bin","base_version":"","require_box_version":"","instruction_set":[],"ios_upgrade_time":5,"android_upgrade_time":5},"force_option":"NONE"}
```

The binary. Downloaded, md5 verified against the response, stored in `a30_firmware/`. Size `1313572`
bytes. `base_version` and `instruction_set` are empty, so it is a full image, not a delta. A
`binwalk -E` shows entropy near `0.97` throughout, so it is encrypted. The image is in hand but not
yet readable.

The URL is not guessable. The format is
`upgrade/prod/{16 digit microsecond upload ts}_{product}_ota_{version}_release_{YYYYMMDDHHMMSS}.bin`.
Two independent high entropy fields, the microsecond upload timestamp and the release datetime, put
it out of brute force range against a rate limited CDN. The API is the only practical source, and it
hands over the exact URL when a package exists.

## Addendum, The Corrected P20i Status

The P20i is not confirmed end of life. Every P20i version lowering test in the logs also synthesized
the serial. The value `14.42` was always paired with `3949000000000000`, and the real serial
`3949E7BDE52DB6F4` was only ever sent with the true `14.43`. So the P20i has never had the A30
winning recipe, real serial with version only. A synthetic serial the server has never seen is a
confound, it may fail closed with no device record.

The operator re-tested the P20i with a version only rewrite and still got no URL, but did not have a
real prior P20i version to claim, so the test is inconclusive. The next step is to find a real prior
P20i version online, then claim it with the real serial and nothing else changed. If a low real
version still returns `needUpdate:false`, end of life is then well supported. If it returns a
`lastPackage`, the P20i image is in reach, encrypted like the A30.

## Addendum, Scope Extended To The A30

The A30, `D1301S`, is owned hardware on the same API, and is now in scope alongside the P20i. It is
the first device to yield a firmware image, so it is the stronger near term target for the
decryption and image analysis work. The image encryption, Jieli style, is the next wall for both
devices.
