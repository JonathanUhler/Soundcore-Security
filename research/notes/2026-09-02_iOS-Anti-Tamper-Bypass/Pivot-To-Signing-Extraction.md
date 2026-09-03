# The Pivot To Signing Extraction

Once the Frida bypass was proven unworkable, the session pivoted. The real goal was never a live
Frida session, it was the P20i firmware. The firmware needs a signed call to the check for update
endpoint, and the signing needs credentials that are recovered from the app. This note records the
pivot, the iOS signing structure recovered statically, the dynamic capture attempt and why it
failed, the detection surface, and the assessment that a passive custom dylib is the viable path.

## Why Not Just Bypass The Anti Tamper

The anti tamper cannot be bypassed reactively on this device. See `Bypass-And-Walkthrough.md` for
the eight run history. The short version is that the kill is an execute permission strip on the
SDK's own trampoline pages, and iOS AMFI will not let a no JIT process re-arm or relocate executable
memory, so the faults cannot be patched into a boot. Preventing the detection would work, but the
detection vector is a memory and thread scan that a Frida session cannot hide from. The user set the
direction, extract the signing crypto from the app rather than keep fighting the anti tamper.

## What The Firmware Call Needs

The endpoint and request are already reconstructed, see
`../2026-08-30_App-Dex-Analysis/Capture-Resolution-And-OTA-API.md`. The call is a POST to
`speaker.eufylife.com/v1/speaker/sound_core/A3949/firmware/update` with an `OtaRequestModel`, and
the batch endpoint returns `lastPackage.url`, the firmware link on an unpinned CDN. The unsigned
probe was run in a prior session and the endpoint enforces signing, so the signature is required.

The signing scheme is recovered structurally in
`../2026-08-31_Ijiami-Buffer-Scrape/Signing-Scheme-Static-Recovery.md`, an ECDH P-256 exchange
feeding a two tier HMAC-SHA256, with a bootstrap tier keyed off the client credential and a session
tier keyed off the ECDH secret. What is missing is the credential values, `clientId`,
`clientSecret`, and `presetKey`, which are the bootstrap key material.

## The iOS Binary Has The Real Code

The Android signer bodies are ijiami method extraction stubs, all `return null`, and the Android
decompilation carries no resources. So Android gives the header names and method signatures but not
the algorithm or the keys. The iOS binary is different. The `commonkit/aknetwork` signer is compiled
into it as real Kotlin Native code, and it decompiles.

Confirmed addresses, preferred base `0x100000000`, so runtime is `main image base + offset`.

| Ghidra address | Offset | Symbol |
| --- | --- | --- |
| `0x102ee3508` | `0x2ee3508` | `-[.. doInitConfigClientId:clientSecret:presetKey:appName:..]` @objc thunk |
| `0x102d5e760` | `0x2d5e760` | the real Kotlin `initConfig` |
| `0x102eee3bc` | `0x2eee3bc` | `-[.. encryptByHMAC256ClientId:tsMsg:onceMsg:]` @objc thunk |
| `0x102d78e9c` | `0x2d78e9c` | the real Kotlin bootstrap signer |
| `0x105446558` | data | the network config singleton, `g` global, holds the credentials at runtime |

The bootstrap signer was read. It builds the message as the concatenation of `clientId`, `tsMsg`,
`onceMsg`, and a secret pulled from the config singleton at `*(config + 0x10) + 0x48`, then HMACs
it, alongside a debug log path that concatenates the same fields with newline labels. The header
constants are all present, `X-Signature`, `X-Request-Ts`, `X-Request-Once`, `X-Key-Ident`,
`X-Client-Credential`, `Client-id`, and `gtoken`, in `HeaderBuilderKt`.

The problem is the credential values are not static constants. They are injected into the config
from the Swift layer at runtime. The two static callers of `initConfig` that were traced pass either
empty strings or the IoT websocket config, `AnkaIoTNetwork` and `wss://`, not the speaker API
credentials. A search of both binaries for `makeitreal`, `clientSecret`, and similar found
nothing. So the values are Swift string literals passed through KMP interop at init, and reading
them means either deep Swift reversing or catching the init at runtime.

## The Dynamic Capture Attempt

The plan was to not boot the app, only to run `doInitConfig` once while hooked, which carries all
three credentials. `scripts/ios-frida/capture-signing.js` hooks `doInitConfig` and
`encryptByHMAC256` by address, loaded together with `anti-tamper.js` to keep the process limping. It
did not work, for two reasons that both matter for the next plan.

- The ObjC `ApiResolver` scan in the first version crashed the agent during load, before resume.
  Enumerating the ObjC runtime forces class realization, which runs `+initialize` and `+load`
  methods, and one of those is anti tamper code. The scan was removed, the script is address only
  now.
- With the clean script, `doInitConfig` never fired. The app hits the same execute strip livelock
  and dies before the network config initializes. So `initConfig` runs later in startup than the
  kill, and the race cannot be won while the anti tamper stops execution that early. Inline hooking
  app code with `Interceptor.attach` may also trip the code integrity check, a second reason to
  avoid it.

## The Detection Surface

The reinforcement SDK resolves its detection primitives dynamically, from symbol tables at
`0x1055cd060` and a duplicate near `0x1058axxxx`, so there are no static xrefs and the exact logic
is obfuscated. The resolved set is telling.

- `_vm_region_64`, a process memory scan. This is what catches jailed spawn gum, whose code is
  anonymous executable memory with no backing file.
- `_task_threads` and `_thread_info`, thread enumeration, another way to spot the agent's threads.
- `_dyld_get_image_name`, `_dyld_image_count`, `_dyld_get_image_header`, and `_dladdr`, image list
  enumeration and address to image resolution.

The memory and thread scans are the Frida catchers. The image list scan can see a normal dyld image,
but it is not what catches gum, since gum is not a dyld image.

## Why A Passive Custom Dylib Is The Viable Path

A code signed dylib added to the app bundle at re-sign time is loaded by dyld as a normal image,
with the app's own signature. It has none of Frida's footprint. The assessment, from the detection
surface and from facts already in hand.

- The memory and thread scans do not see a file backed signed dylib. It is not anonymous executable
  memory, and if it avoids spawning agent like threads it does not stand out to thread enumeration.
  These are the checks that actually catch Frida.
- The image list scan can see it, but the app tolerates re-signing and sideloading and runs fine
  without Frida, so there is no strict per image hash or signature validation against a
  baseline. The binary loads 127 plus `@rpath` frameworks and the runtime image count is about 1277,
  a set that varies by iOS version, so a hardcoded whitelist or count check would be too brittle to
  be likely. A name scan is evaded by a benign name.
- A passive dylib that only reads memory does not patch code, so it does not trip the code integrity
  or hook checks, and `_dladdr` based checks target code redirection, not passive images.

The read side is feasible. The credentials land in the config singleton at `0x105446558`, with the
bootstrap secret at `*(config + 0x10) + 0x48`, set by `initConfig`. A constructor in the dylib can
resolve the main image base, compute the config address, poll until the credentials are populated,
then read and exfiltrate them.

The one thing static analysis cannot close is the exact image list check, since it is dynamically
resolved and obfuscated. The cheap decisive experiment is to inject a trivial no op signed dylib and
confirm the app still boots without Frida. That isolates the single open question before the real
reader dylib is built. This is the subject of the next plan.  </content>
