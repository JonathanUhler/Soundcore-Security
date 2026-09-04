# Notes: OTA Batch Request Capture

These notes correspond to the plan in `research/plans/2026-09-04_OTA-Batch-Request-Capture/`.
The plan continues the iOS Custom Dylib Monitor work. Auth to the firmware API is solved and account
free. The one blocker is the exact request schema for the batch check,
`POST api/v2/speaker/firmware/upgrade_check/batch`, model `SCOTAMultipleRequestModel`, where every
hand guessed body returns `{"res_code":400,"message":"Err_InvalidRequest"}`. This session built the
capture vehicle for the real body and gathered the static evidence explaining why guessing failed.

## Status

- Artifact built. `scripts/ios-dylib/scjson.c` captures the serialized batch body from the running
  app. It is not yet run on device, that is the operator step. See the operator sheet in
  `scripts/ios-dylib/README.md`.
- Static evidence gathered. The reason the schema resisted guessing is now clear. The OTA models
  carry two conflicting key styles in their metadata, so no single guessed shape was right.

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
against ambiguous metadata. That is what `scjson.c` does.

## The Capture Vehicle, scjson.c

Same passive vehicle proven all last session, a file backed, app signed dylib added at re-sign time.
It reads only through `mach_vm_read_overwrite` and writes nothing, so it has none of the footprint
the reinforcement SDK detects. It is strictly read only, no version forcing or any write, unlike
`scharvest`, because this plan only needs to observe the body.

How it works.

- It sweeps every readable, writable region on a tight loop for ten minutes, in 1 MB chunks, looking
  for a JSON object prefix, `{"` in UTF-8 or the UTF-16LE form. UTF-8 is the expected encoding for a
  HandyJSON body, the wide form is a cheap safety net.
- On a hit it re-reads a bounded window straight from the hit address, independent of the scan
  chunk, so a body straddling a chunk boundary is never truncated. It walks that window quote,
  escape, and brace aware, so a brace inside a string does not close the object early, and stops at
  the matching close brace.
- It logs any object that carries the definitive `firmwareList` wrapper key, or at least two OTA
  field markers from the set recovered above. Random JSON with a lone `version` does not trigger.
- Bodies are logged uncapped, a `CAPTURE #n BEGIN` header, then `#n seg k/m` lines carrying the JSON
  in order, then `CAPTURE #n END`, because `os_log` truncates a single long argument. The operator
  concatenates the segments to get the exact body. Captures are deduped by content hash, so each
  distinct body logs once even though it is re-observed on many passes.

## Deliverable And How To Read It

Run per `scripts/ios-dylib/README.md`, tap check for update several times inside the sweep window,
and grep the log for `SCJSON`. The concatenated `seg` payloads are the exact body. The deliverable
is that body, its field names, which fields are present, and the `version` and `productComponent`
values the app sends for the A3949.

## What Is Left

- Reproduce the captured body in `scripts/sign_firmware_request.py` with `--batch --raw-body`, which
  needs no re-auth because the eufy token is body independent. Confirm it returns `res_code 1`
  instead of `400`.
- Lower the `version` field so the server reports an update, read `needUpdate` and
  `lastPackage.url`, then download the firmware from the unpinned CDN with `curl`. That image is the
  goal of the project.
- Fallback if the transient string is never caught. Read the `SCOTAMultipleRequestModel` and
  `SCOTAMultipleItemStruct` objects out of the heap and decode their fields, the object walk
  `scident` already does, since the model object outlives the freed JSON string.
