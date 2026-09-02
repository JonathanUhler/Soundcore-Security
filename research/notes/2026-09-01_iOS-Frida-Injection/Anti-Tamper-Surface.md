# The iOS Anti Tamper Surface

This started as a static finding from scanning the decrypted main binary in
`ipa/com.oceanwing.SoundCore_5.0.02_und3fined.ipa`. It documents an anti tamper and anti
instrumentation SDK linked into the app. The first `recon.js` session then produced runtime evidence
that the SDK fires, see the Runtime Observation section. This is now the active blocker, not a
theoretical one.

## Not The Android Packer

The Android APK is packed with ijiami method extraction, documented in the 2026-08-31 Ijiami Buffer
Scrape notes. That is a per method bytecode packer and it is Android only. The iOS finding here is a
different thing, a reinforcement SDK statically linked into the Mach O, with runtime detection
routines. Do not conflate the two.

## The Detection Taxonomy

The main binary contains a set of `APP_FIRM_` result codes that name the detection categories.

- `APP_FIRM_LIBRARY_INJECTION`, an injected dylib, which is what a Frida gadget is.
- `APP_FIRM_HOOK_ATTACK`, an inline or ObjC hooking runtime, which is what Frida installs.
- `APP_FIRM_DEBUG` and `APP_FIRM_FUNC_DEBUG`, a debugger attached.
- `APP_FIRM_SIGNATURE_TAMPER`, a changed or re-signed signature.
- `APP_FIRM_MODIFY_CODE` and `APP_FIRM_SOURCE_FILE_MODIFIED`, patched code or a changed bundle file.
- `APP_FIRM_NON_APPSTORE_DOWNLOAD`, a sideloaded install.
- `APP_FIRM_OBSTRUCT_JAIL_DECT`, a jailbreak detection bypass tweak.
- `APP_FIRM_HTTP_DETECTION` and `APP_FIRM_VPN_DETECTION`, a proxy or VPN in the network path.

## The Kill Switch And The Vendor

The detections funnel through one Swift entry point, `JMSafeExit(type:handler:)`, also present as
`JMSafeExitWithType`, with an alert type enum `JMExitAlertType`. A single choke point is useful. A
hook that neutralizes `JMSafeExit` disarms every category at once, which is the recommended first
move when the SDK is confirmed to fire.

Supporting symbols include `JMDetectionResult` with `JMDetectionResultJailBreak`, a logging class
`JMRLog`, and a config class `JMConfig`. There is also an Anker layer with `ACSafety` and
`ACJailBreak`, and selectors `isJailBreak`, `isAppJailBreak`, and `ac_isJailBreak`.

The `JM` prefix reads as jiami, the pinyin for encrypt. Combined with the `APP_FIRM_` taxonomy this
is most likely the ijiami, also styled aijiami, iOS reinforcement product. This is an inference from
the naming, not a confirmed vendor identification.

## Pinning And Proxy Detection

The SDK carries `JMCheckHttpsCer`, a certificate check, and an embedded cert name that decodes
to `Test Untrusted Root CA`, a known interception CA marker. This is the same SDK that raises
`APP_FIRM_HTTP_DETECTION`. The practical consequence is that this one SDK gates both the Frida path
and a naive mitmproxy path. Neutralizing `JMSafeExit` would defuse the response for both.

This corrects the memory note `ios-ipa-dynamic-vehicle`, which reads pinning as not visible. A named
pinning library is indeed absent, but the reinforcement SDK does its own certificate check.

## The Jailbreak Path List

The classic file and path checks are present as a string block, `/Applications/Cydia.app`,
`/Library/MobileSubstrate/MobileSubstrate.dylib`, `/usr/sbin/sshd`, `/etc/apt`,
`DYLD_INSERT_LIBRARIES`, `/private/jailbreak.txt`, `/panguaxe`, `/xuanyuansword`, and
`/private/var/lib/apt`, along with a `.SignerIdentity` check. These matter less on a stock device,
which is not jailbroken, but the `LIBRARY_INJECTION` and `HOOK_ATTACK` categories are the ones aimed
at Frida.

## Runtime Observation

The first jailed spawn session captured the SDK's response. `recon.js` ran fully during the spawn
pause, enumerated the process, and finished, all before the app's own code ran. The moment Frida
resumed the main thread the process died. The `recon.log` tail reads `Resuming main thread!` and
then `Process terminated`.

The unmodified app stays up, so a self termination this early, only with the Frida agent
present, matches `LIBRARY_INJECTION` or `HOOK_ATTACK` reaching `JMSafeExit`. This
is strong evidence, not yet proof. To confirm, hook `exit`, `abort`, and `JMSafeExit` and read the
backtrace at termination, or pull a fresh crash report and check whether the terminating
frame is in the app rather than in the agent.

Note the process survived the whole recon enumeration because that work happens during the spawn
pause. The detection runs on the app's own startup path after resume, not at agent load. That timing
is useful. The spawn pause is a clean window to install the bypass before the detection can run.

## What This Means For Instrumentation

The jailed spawn path still injects Frida's gum agent, which is exactly what `LIBRARY_INJECTION` and
`HOOK_ATTACK` are built to detect. Getting the agent to load is not the same as staying undetected.
The likely sequence once the app is resumed and driven is a detection followed by a `JMSafeExit`
call.

The plan to test and, if needed, defeat this.

1. Resume the spawned app and drive it, watching for an exit shortly after resume. That confirms
   whether the SDK fires at runtime.
2. If it fires, use the spawn pause, which lands before app code runs, to install a hook on
   `JMSafeExit` and its ObjC and C fallbacks, `exit`, `abort`, `__pthread_kill`.
3. Find the `JMSafeExit` call site and the detection dispatcher in the decrypted binary with Ghidra,
   to confirm the hook target and to see whether any detection runs from a constructor before the
   agent is in place.
