# Problem Statement: OTA Batch Request Capture

This plan continues the work in `research/notes/2026-09-03_iOS-Custom-Dylib-Monitor`. Read that
session's `Eufy-Token-Scheme.md` first, it is the current state. The short version is that calling
the P20i firmware API is now solved except for one thing, the exact request body of the batch
firmware check. This plan captures that body from the running app with the passive dylib vehicle,
then uses it to pull the firmware.

## What Is Already Solved

Do not redo any of this. It is settled and recorded in the prior session notes.

- The firmware host is `speaker.eufylife.com`, eufy infrastructure, not the soundcore backend
  `anka-api-us.soundcore.com`. See `Eufy-Token-Scheme.md`.
- The eufy hosts sign with a `token` plus `timestamp`, not the soundcore ECDH scheme. The token is
  `md5(timestamp + localKey)`, body and path independent. The server does not *appear* to check
  timestamp freshness, but that is **not** 100% confirmed for every endpoint. A pair captured off
  the unpinned `log.eufylife.com` telemetry from several days ago does return SUCCESS for the
  non-batched firmware upgrade endpoint (although says no update is required). One such pair is the
  default in `scripts/sign_firmware_request.py`, so `--eufy` should authenticate every time.

## The One Blocker

The real firmware check is the batch endpoint, `POST api/v2/speaker/firmware/upgrade_check/batch`,
model `SCOTAMultipleRequestModel`. Every body shape tried returns `{"res_code":400,"message":
"Err_InvalidRequest"}`. The tried and failed shapes are listed in `Eufy-Token-Scheme.md`. Static
analysis stalled here, the Android request builders are stubbed by lazy code paging, and the Swift
`mapping` and the item field descriptor did not resolve cleanly.

## Goal 1: Capture A Real Batch Request Body

Observe the exact JSON the app sends to the batch endpoint instead of continuing with guesses based
on static analysis. When the operator taps check for update, the app serializes
`SCOTAMultipleRequestModel` to a JSON string in memory before it goes out over the pinned TLS
connection. That string is the answer. `speaker.eufylife.com` is certificate pinned, so a proxy
cannot see it, which is why an in process passive read is the right tool.

The vehicle is the passive dylib proven all last session, no hooks and no code patches, only fault
proof `mach_vm_read_overwrite`. Extend `scident.c`, or write a focused sibling, to sweep the heap
for the serialized body and log it uncapped.

- The target string starts with `{` and contains `firmwareList`, or `productCode`, or
  `upgrade_check`, or possibly the snake-case versions of those (based on the Android
  convention). The prior `scident` run already caught the OTA telemetry JSON this way, so the
  approach works, it just needs to catch this specific transient object at the right time.
- The body is short lived. Sweep on a tight loop around the tap, or widen the string capture and run
  several passes while the operator taps check for update repeatedly. Consider also scanning for the
  `SCOTAMultipleItemStruct` object fields directly, not only the serialized string, in case the JSON
  string is freed faster than the model object.

The deliverable is the exact batch request body, its field names, which fields are present, and the
`version` and `productComponent` values the app sends for the A3949.

## Goal 2: Force An Update And Download The Firmware

With the real body in hand, reproduce it in `scripts/sign_firmware_request.py`, which already speaks
the eufy token scheme and the batch endpoint and has a `--raw-body` for exact bodies. Then lower the
`version` field so the server reports an update.

- Send the corrected batch body with a low version and read `needUpdate` and `lastPackage`.
- `lastPackage.url` is the firmware download URL. Per the prior notes it is on an unpinned object
  store or CDN, so the download itself needs no signing, a plain `curl` should work.
- Pull the firmware image. That image, a Jieli UFW with a weak scrambler, is the whole point of the
  project, and it is decryptable with public tooling once obtained.

## Constraints And Notes

- Keep the dylib passive. The whole reason this vehicle works is that it has none of the footprint
  the reinforcement SDK detects. No `Interceptor`, no inline hooks, reads only.
- The token is permanent and already in the client, so there is no timing pressure and no account is
  needed. The only device interaction required is running the dylib and tapping check for update.
- If capturing the serialized string proves too transient even under a tight sweep, the fallback is
  to read the `SCOTAMultipleRequestModel` and `SCOTAMultipleItemStruct` objects out of the heap and
  decode their fields, the same object walking `scident` already does for the config. Beyond that,
  looking into possible ways of hooking through a custom (non-Frida) dylib might be worthwhile,
  although is probably a stretch.
