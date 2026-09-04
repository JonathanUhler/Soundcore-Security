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
- Second vehicle built, the deterministic one. `scripts/ios-dylib/scbody.m` captures the body by
  ObjC method swizzling at a fixed choke point, no race. Not yet run on device, the operator step.
  See the operator sheet in `scripts/ios-dylib/README.md`.
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

## Deliverable And How To Read It

Run per `scripts/ios-dylib/README.md`, tap check for update once, and grep the log for `SCBODY`.
There is no race, so a single tap is enough. Concatenate the `seg` payloads to get the exact body.
The deliverable is that body, its field names, which fields are present, and the `version` and
`productComponent` values the app sends for the A3949.

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
