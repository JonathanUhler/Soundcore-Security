# The Working Injection Flow And The Crash Diagnosis

This file records the injection path that worked on iOS 26 and the diagnosis that got there. The
operational command sheet is `scripts/ios-frida/COMMANDS.md`. This note explains why the flow is
shaped the way it is, so the reasoning is not lost.

## Environment

- Device, iPhone18,5 on iOS 26.5.1, stock and non jailbroken.
- App, the re-signed `com.oceanwing.SoundCore.G8AW4BQ7RV` build from Sideloadly with a free account.
  The re-sign adds `get-task-allow`, which makes the app debuggable.
- Host, an Intel Mac with no Xcode. This ruled out `devicectl` and the Xcode device tools, and
  forced `pymobiledevice3` for the developer image and the tunnel.
- Frida, `frida-tools` 17.17.0. The cache gadget and any embedded gadget must match this version.

## The Embedded Gadget Is A Dead End On iOS 26

The plan called for a Frida Gadget in the app bundle. Getting the gadget's `.config` into the bundle
was itself a detour. Sideloadly's inject box only accepts `.dylib`, `.deb`, and `.bundle`, not the
`.config` sidecar the gadget reads at load. The fix was to package the gadget as a `.framework`
folder, because a framework carries the config inside it, and to use Sideloadly's Add Framework
button. The `FridaGadget-Info.plist` template and that packaging are kept for the older device
fallback.

With the framework built and `on_load` set to `wait`, the app still crashed at launch. Two crash
reports settled the cause.

### Crash One, The arm64e Slice

`SoundCore-2026-09-01-200614.000.ips`. The process died about 30 milliseconds after launch with
`EXC_BREAKPOINT`, signal `SIGTRAP`, indicator `Trace/BPT trap: 5`. The instruction at the crash
address decoded to `BRK #0x539`, an explicit software breakpoint. The faulting thread was the main
thread, and the whole backtrace sat inside `FridaGadget`, called from dyld's
`findAndRunAllInitializers` through `runInitializersBottomUp`. In other words the gadget trapped
itself while dyld was still running its constructor, before the app reached `main`.

The image list showed the reason to suspect arch. The gadget loaded as arm64e while the main binary
and all 125 other images were arm64. The universal gadget's arm64e slice had been selected into an
arm64 process. The fix was to thin the gadget to arm64 with `lipo`.

### Crash Two, The Real Cause

`SoundCore-2026-09-01-202925.ips`. After thinning, the gadget image was arm64, confirmed in the new
report, so the slice mismatch was gone. The crash was identical, `EXC_BREAKPOINT`, `BRK #0x539`, the
same all `FridaGadget` stack under dyld's initializer phase. The arch was a real bug but a side
issue, not the root cause.

This signature is Frida issue 3770, the embedded gadget crashing in the dyld initializer on iOS 26,
reported on 26.2 as issue 3650. The cause is iOS 26's stricter debugger mapping and code signing
rules, which gum trips during its early setup. It is unresolved. The documented config workaround,
`code_signing` set to `required`, did not help, matching the issue reporters. The app's own anti
tamper SDK was never reached in either crash, so it is not implicated in these launches.

## Why Jailed Spawn Works

On a jailed device gum's Interceptor runs only if a debugger attaches before the gadget
loads. Launching the app under `debugserver` relaxes its code signing state, and that relaxed
state is sticky once set. Frida's jailed spawn does exactly this. It launches the app under the
debugger, then injects its agent into the already relaxed process. The same gum code that trapped
during a normal launch runs fine, because the enforcement that produced `BRK #0x539` is no longer in
effect.

This is why the maintainers point to jailed spawn on iOS 26, and why the same gadget binary that
crashes when embedded works when Frida injects it after the debugger attaches.

## The Prerequisites The iOS 17+ Model Adds

Jailed spawn on iOS 17+ needs more than a version matched Frida. The order that worked, with
the failure that flagged each step.

1. A debuggable app. The Sideloadly re-sign already adds `get-task-allow`, confirmed by
   `CS_GET_TASK_ALLOW` in both crash reports. Sideload the unmodified IPA with an empty inject box.
2. Developer Mode on the device, enabled and confirmed after a reboot.
3. The cache gadget. Jailed injection reads its own gadget from `~/.cache/frida/gadget-ios.dylib`.
   The error `need Gadget to attach on jailed iOS` names this exact path. Place a version matched
   universal gadget there. Frida selects the arm64 slice itself.
4. A mounted developer disk image. Spawning needs `debugserver` from the image. The error was
   `requires an iOS Developer Disk Image to be mounted`. On iOS 17+ the image is personalized and
   mounted over the tunnel, so `ideviceimagemounter` does not apply. `pymobiledevice3 remote
   tunneld` with sudo, then `pymobiledevice3 mounter auto-mount`, mounted it and downloaded the
   correct image without Xcode.

The tunnel and the mount do not survive a reboot, so steps 2 through 4 are partly per boot.

## The Command That Worked

```bash
frida -U -f com.oceanwing.SoundCore.G8AW4BQ7RV -l scripts/ios-frida/recon.js
```

Frida launched the app under the debugger, injected the agent, and `recon.js` ran to completion with
the app alive. The bundle ID came from `frida-ps -Uai`, since Sideloadly's auto bundle ID appends
the team ID.

## What Recon Showed

The `recon.js` session confirmed the injection and mapped the crypto surface. The full OpenSSL and
CommonCrypto primitive set is resolvable, `HMAC`, `SHA256`, `ECDH_compute_key`, `EVP_PKEY_derive`,
`CCHmac`, and `CC_SHA256`, so the recovered ECDH plus HMAC signer can be observed at the primitive
level even without naming the app's own signer class. The app exposes many Swift classes as
`SoundCore.*`, including OTA and firmware types like `CMDOTA`, `JLOtaHelper`, and
`S2DeviceFirmwareModel`, useful for Goal 2. The app's own signing classes and the `JM` anti tamper
symbols do not appear as ObjC classes, so they are Swift free functions or native code, hooked by
symbol or address rather than through the ObjC runtime.

The session also captured the anti tamper response. Recon ran to completion during the spawn pause,
then the process terminated the instant the main thread resumed. See the Runtime Observation section
of `Anti-Tamper-Surface.md`. This makes the `JMSafeExit` bypass the immediate next task before any
capture session can run.
