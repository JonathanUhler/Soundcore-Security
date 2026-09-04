# Custom Dylib Monitor, Operational Sheet

Operator steps for the iOS Custom Dylib Monitor plan. The reasoning and the
feasibility assessment are in
`research/notes/2026-09-03_iOS-Custom-Dylib-Monitor/Summary.md`. This file is the
command sheet.

The idea is a passive, file backed, app signed dylib added to the Soundcore
bundle at re-sign time, instead of a Frida agent. Frida is dead on this device
because the reinforcement SDK detects the gum agent and sabotages the boot, and a
non JIT process cannot recover executable memory. A normal dyld image with the
app's own signature has none of that footprint. See the research note.

## Goal 1 Artifact

`scprobe.c` is the Goal 1 probe. Its constructor logs a `SCPROBE_HELLO_WORLD`
marker to the unified log and drops the same marker in the app sandbox tmp dir.
It links only libSystem and patches no code, so it is passive. Goal 1 passed on
device, so the passive reader path is open.

## Goal 2 Artifact

`screader.c` is the credential reader. It polls the network config singleton the
app's own signer reads, then dumps its string fields to the unified log under the
`SCREAD` marker, so the host can reproduce a signed firmware check. It reads only
through `mach_vm_read_overwrite`, so a bad pointer cannot crash the app, and it
hooks nothing. Build it with `SRC=screader.c`, inject and verify the same way,
and grep the log for `SCREAD`. See
`research/notes/2026-09-03_iOS-Custom-Dylib-Monitor/Goal2-Credential-Reader.md`.

```bash
SRC=screader.c scripts/ios-dylib/build.sh
pymobiledevice3 syslog live | grep SCREAD
```

## Goal 2b Artifact, The URL Harvester

The firmware endpoint has a second gate beyond the signature, an access token, and
a replayed request returns `406 Access token expired` without one. The fix is to
let the app make the call itself, since it holds a valid token and signs
correctly, and to read the result. `scharvest.c` does this. It hooks nothing and
touches memory only through `mach_vm_read_overwrite` and one optional
`mach_vm_write` to a heap string.

- URL harvest, always on. It scans the writable heap for http URLs and logs each
  unique one, tagging firmware looking ones `FWLIKELY`. The check response, parsed
  into a heap string, is where `lastPackage.url` lands.
- Version forcing, optional. The earbuds are already current, so a normal check
  returns no update. Set `VER_FROM` and `VER_TO` at the top of `scharvest.c` to
  the current firmware version and a lower value of the SAME length. It overwrites
  the version string in place so the app sends an old version and the server
  returns a URL.

Flow.

1. Find the current P20i firmware version in the app, device info screen. Set
   `VER_FROM` to it exactly and `VER_TO` to a lower same length value, for example
   `01.62.00` to `00.00.01`. Leave both empty to first try a harvest only pass.
2. Build, inject, install, launch.

   ```bash
   SRC=scharvest.c scripts/ios-dylib/build.sh
   pymobiledevice3 syslog live | grep SCHARV
   ```

3. Connect the P20i, navigate to the firmware or OTA screen, and tap check for
   update. Watch for a `FWLIKELY` line, that is the firmware URL.
4. Download the firmware from that URL outside the app with `curl`. The CDN is
   unpinned and needs no signing.

Do NOT tap download or install in the app while a low version is forced. That
could push a firmware downgrade to the earbuds. Only the check for update is
needed, the URL is in its response.

## Goal 2c Artifact, The Identity Sweeper

`screader` dumps the `netApi` network config, which holds only the signing
material, the clientSecret and presetKey. The token gate on the firmware endpoint
needs the guest session identity instead, the `touristId` and its `gtoken`, which
live in a different object. `scident.c` finds it. It waits for the config to
populate, then sweeps the whole `0x5446xxx` global cluster and walks the object
graph a few levels deep, decoding every Kotlin string and flagging the ones that
look like an identity or token with an `IDENT` marker. It reads only through
`mach_vm_read_overwrite` and hooks nothing, the same footprint as `screader`.

It sweeps five times, at 10, 20, 35, 55, and 80 seconds after the config appears.
The first run proved the model. The app signs the session tier with an ECDH
derived per service key, the `uniqueSign`, a 32 char string used as 32 UTF-8 bytes,
keyed per host. It was captured live for `anka-api-us.soundcore.com`, the user API
host, but the firmware endpoint is a different service, so its key was not caught
because no firmware check ran during that sweep.

The point of the next run is to capture the firmware service exactly. It flags any
URL or firmware or routing string uncapped and tagged `URL`, so the firmware
request's routing object, which carries the exact host and path, is never dropped.
`IDENT` still tags key and token shaped values.

```bash
SRC=scident.c scripts/ios-dylib/build.sh
pymobiledevice3 syslog live | grep SCIDENT
```

1. Build and inject as below. Connect the P20i first so it is ready.
2. Launch the app. Within the first 80 seconds, go to the device or firmware
   screen and tap check for update, so the app makes its own firmware request.
   Do this before the sweeps end. Do not tap download or install.
3. Read the log.
   - `URL` lines carry hosts and paths. Find the one with `firmware` or
     `sound_core`, which is the real firmware endpoint, host and path. That
     settles the host guessing.
   - The `IDENT` `md5/gtoken?` value in the same object cluster, at a nearby
     `parent`, is that service's `uniqueSign` signing key. Sign with it, pass it as
     `--client-secret`, and set `--host` to the captured host.
   - A `JWT?` or `token/id?` value in the firmware request context is a `gtoken` or
     bearer, pass it with `--gtoken` or `--authorization`.
4. Then reproduce. Sign with the captured key over `ts+"+"+once+"+"+body`, send to
   the captured host and path. If it is rejected for a missing `X-Key-Ident`, that
   header is `generateKeyIdent(key)` and must be reversed or captured next.

Keys rotate about every three days, the server public key lifetime, so capture and
test in the same session.

## Goal 1 Artifact Of The Batch Capture Plan, The JSON Body Capturer

`scjson.c` captures the exact serialized batch request body. Auth to the firmware
API is solved, but the real check is the batch endpoint
`api/v2/speaker/firmware/upgrade_check/batch`, model `SCOTAMultipleRequestModel`,
and every hand guessed body returns `400 Err_InvalidRequest`. The reflection
metadata carries two conflicting key styles, snake_case `product_code` next to
camelCase `firmwareList` and `wifiVersion`, so the required shape is ambiguous.
This dylib reads the JSON the app itself serializes just before the pinned TLS
send. See `research/notes/2026-09-04_OTA-Batch-Request-Capture/Summary.md`.

It sweeps the readable, writable heap on a tight loop looking for a JSON object
prefix, `{"` in UTF-8 or the UTF-16LE form, re-reads a bounded window from the hit
address so a body straddling a scan chunk is not truncated, walks it quote and
brace aware to capture one complete object, and logs any object carrying the
`firmwareList` wrapper key or two OTA field markers. It reads only through
`mach_vm_read_overwrite` and writes nothing, the same footprint as `scident`, so it
stays passive. Bodies are logged uncapped, chunked across `seg` lines with a
capture id, and deduped by content so each distinct body logs once.

```bash
SRC=scjson.c scripts/ios-dylib/build.sh
pymobiledevice3 syslog live | grep SCJSON
```

1. Build and inject as below. Connect the P20i first so it is ready.
2. Launch the app. Within the 10 minute sweep window, go to the device or firmware
   screen and tap check for update. Tap it several times, the body is short lived
   and repeated taps re-serialize it, giving more passes a chance to catch it. Do
   not tap download or install.
3. Read the log. A `CAPTURE #n ... BEGIN` line starts a body, then `#n seg k/m`
   lines carry the JSON in order, then `CAPTURE #n END`. Concatenate the `seg`
   payloads in order to get the exact body. The `enc` field says `ascii` or
   `utf16`, `score` is how many OTA markers matched, and `closed` versus
   `TRUNCATED` says whether the object ended on its own close brace.
4. Reproduce it. Pass the concatenated body to `sign_firmware_request.py --batch
   --raw-body '<body>'`, then lower the `version` field so the server reports an
   update and returns `lastPackage.url`.

If the serialized string is never caught because it is freed too fast, the
fallback is to read the `SCOTAMultipleRequestModel` and `SCOTAMultipleItemStruct`
objects out of the heap and decode their fields, the object walk `scident` already
does, since the model object outlives the transient JSON string.

## Goal 1 Artifact, The Swizzle Capturer

`scjson.c` never caught the body on device. The serialized string is freed faster
than a full heap sweep, so racing it passively is a losing game. `scbody.m`
replaces the race with a deterministic capture at a fixed choke point.

It is still the same passive, file backed, app signed dylib, and it is still not
Frida and not an inline hook. It captures by ObjC method swizzling, which the
reinforcement SDK does not detect, because swizzling changes DATA, not code.
`method_setImplementation` swaps an `IMP` pointer in a class method list, a
`__DATA` structure, and the replacement is ordinary signed code inside this dylib's
`__TEXT`. Nothing patches an instruction, builds a trampoline, or allocates
anonymous executable memory, so the `HOOK_ATTACK`, code integrity, and `_dladdr`
code redirection detectors, which all target code tampering, cannot see it. See
`research/notes/2026-09-04_OTA-Batch-Request-Capture/Summary.md`.

It swizzles two choke points, both confirmed present in the binary.

- `+[NSJSONSerialization dataWithJSONObject:options:error:]`. ObjectMapper and
  HandyJSON funnel their serialization through this Foundation method, so the JSON
  `Data` is captured at the instant it is produced, before it can be freed.
- `-[NSMutableURLRequest setHTTPBody:]`. The network boundary. Filtered by the
  request URL, so the batch check body is captured regardless of how it was built.

Each replacement calls the original and returns its result unchanged, so there is
no behavioral tell. Bodies are logged uncapped, chunked like `scjson`, deduped by
content.

```bash
SRC=scbody.m scripts/ios-dylib/build.sh
pymobiledevice3 syslog live | grep SCBODY
```

1. Build and inject as below. `build.sh` links Foundation automatically for a `.m`
   source. Connect the P20i first so it is ready.
2. Launch the app, go to the device or firmware screen, and tap check for update
   once. There is no race, so a single tap is enough. Do not tap download or
   install.
3. Read the log. A `CAPTURE #n src=... url=... BEGIN` line starts a body, then
   `#n seg k/m` lines carry the JSON in order, then `CAPTURE #n END`. The `src`
   field is `json` for the serialization hook or `httpBody` for the network hook.
   Concatenate the `seg` payloads to get the exact body.
4. Reproduce it with `sign_firmware_request.py --batch --raw-body '<body>'`, then
   lower the `version` field so the server reports an update and returns
   `lastPackage.url`.

## Build

The build host is the same Mac used for Sideloadly, an Intel Mac with only the
Command Line Tools. `build.sh` cross compiles an arm64 dylib.

```bash
scripts/ios-dylib/build.sh
```

The one prerequisite is an iPhoneOS SDK. With full Xcode it is found
automatically. Without Xcode, pass a standalone SDK, for example from a Theos
install.

```bash
SDK=$THEOS/sdks/iPhoneOS16.5.sdk scripts/ios-dylib/build.sh
```

The output `scprobe.dylib` must be arm64, not arm64e, to match the app and its
images. `build.sh` prints `file scprobe.dylib` so this can be confirmed. Leave it
unsigned. Sideloadly signs it during the re-sign.

Build note. The iOS SDK gates `<mach/mach_vm.h>` behind
`#error "mach_vm.h unsupported."`, so a source that includes it fails to compile.
The function is still in libSystem and works on iOS for our own task, so the fix
is to declare the prototype directly and not include the gated header, which is
what `screader.c` does.

## Inject And Install

1. Open Sideloadly and load the unmodified IPA,
   `ipa/com.oceanwing.SoundCore_5.0.02_und3fined.ipa`, the same known good build
   from `scripts/ios-frida/COMMANDS.md` section 2.
2. In the dylib inject box, add `scprobe.dylib`. This is the box that was left
   empty for the Frida flow. Sideloadly copies the dylib into the bundle, adds an
   `LC_LOAD_DYLIB`, and signs the dylib with the re-sign identity.
3. Keep the same Remove app extensions and auto bundle ID settings as the known
   good build.
4. Install to the device. No developer image, no tunnel, no Frida gadget. This is
   a plain launch, which is the point.

## Verify

Launch the app normally by tapping it. Stream the device log over USB and grep
for the marker.

```bash
pymobiledevice3 syslog live | grep SCPROBE_HELLO_WORLD
```

`idevicesyslog | grep SCPROBE_HELLO_WORLD` works too if libimobiledevice is
installed instead.

Record the outcome against the three cases.

- App boots and the marker appears. Goal 1 passes. No load time library
  whitelist, and the passive dylib path is viable. Proceed to Goal 2.
- App crashes or force closes at launch. The SDK reacted to the added image.
  Pull a fresh crash report and read the terminating frame, then see the note's
  discussion of the image list vector.
- App boots but no marker appears. The dylib did not load, or the log did not
  surface. Confirm the `LC_LOAD_DYLIB` is present with `otool -l` on the
  installed main binary, check the arm64 slice, and try the tmp file fallback.

## Recover The Fallback Marker File

If the log channel is unclear, the constructor also writes
`$TMPDIR/SCPROBE_HELLO_WORLD.txt` inside the app sandbox. It is pullable with
house_arrest only if the app exposes file sharing, so treat it as a secondary
check, not the primary proof.

```bash
pymobiledevice3 apps afc --bundle-id <installed bundle id> ls /tmp
```
