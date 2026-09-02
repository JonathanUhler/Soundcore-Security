# Notes: iOS Frida Injection

These notes correspond to the plan in
`research/plans/2026-09-01_iOS-Frida-Injection/Problem-Statement.md`. That plan set out to
instrument the re-signed iOS Soundcore build with Frida, so the request signing material and the
firmware download flow can be observed live. Goal 0 was to produce a Frida build and confirm
attachment.

## Status

Goal 0 is resolved, but not by the method the plan assumed. The plan's chosen method, a Frida Gadget
embedded in the app bundle, is a dead end on iOS 26. It crashes at launch before any app code runs.
The working method is jailed spawn injection, where Frida launches the app under `debugserver` and
loads its own agent into the debuggable process. `recon.js` attaches, prints the process facts, and
the app stays alive through recon.

Goals 1 and 2 are blocked on the anti tamper SDK. The first recon session showed the process
terminating the instant the main thread resumed, which the anti tamper note reads as the SDK firing.
The signing capture and the firmware pull need that bypass first, then a driven session with
the network and crypto hooks. See the anti tamper note.

## Files In This Note

- `Summary.md`: this file. Status, the corrected injection model, and next steps.
- `Working-Injection-Flow.md`: the flow that worked end to end, the crash diagnosis that ruled out
  every wrong turn, and the environment facts. The operational command sheet is
  `scripts/ios-frida/COMMANDS.md`.
- `Anti-Tamper-Surface.md`: a static finding. The main binary links a reinforcement SDK with an
  explicit injection, hook, and tamper detection taxonomy, funneled through one kill switch. This is
  the expected next hurdle once app code runs.

## Headline Findings

- The embedded gadget is unusable on iOS 26. It dies with `EXC_BREAKPOINT`, `BRK #0x539`, inside its
  own dyld initializer, matching Frida issue 3770. The app's own code never executes.
- Two candidate causes were tested and eliminated. The gadget first loaded as arm64e in an all arm64
  process, a real slice mismatch that was fixed by thinning to arm64. The crash persisted, which
  proved the arch was a side issue, not the root cause.
- Jailed spawn works where embedding fails. Frida attaches `debugserver` first, which relaxes code
  signing in a way that is sticky, and loads the agent after. The same gum code that trapped during
  a normal launch runs fine once code signing is relaxed.
- The iOS 17+ connection model added two prerequisites the plan did not anticipate, Developer Mode
  and a mounted personalized developer disk image over the RemoteXPC tunnel. Both were handled on an
  Intel Mac with no Xcode, using `pymobiledevice3`.
- The anti tamper SDK fires at runtime. A scan found a reinforcement SDK with injection, hook,
  and signature tamper detection. The first recon session then showed the process terminating the
  instant the main thread resumed, only with the Frida agent present, which is the expected response
  of that SDK reaching its `JMSafeExit` kill switch. This is the active blocker for Goals 1 and 2.

## The Working Flow In One Paragraph

Sideload the unmodified IPA, which the free account re-sign makes debuggable through the
`get-task-allow` entitlement. Enable Developer Mode. Place a version matched Frida gadget at
`~/.cache/frida/gadget-ios.dylib`, where jailed injection reads it. Mount the developer disk
image with `pymobiledevice3 mounter auto-mount` after starting `pymobiledevice3 remote tunneld`.
Then spawn with `frida -U -f com.oceanwing.SoundCore.G8AW4BQ7RV -l recon.js`. Frida launches the app
under the debugger, injects the agent into the relaxed code signing state, and recon runs.

## Correction To The Plan And Memory

The plan's Injection Approach section describes a Frida Gadget added to the bundle with an
`LC_LOAD_DYLIB` command through Sideloadly. That approach does not work on this iOS 26 device. The
plan is left unedited as the original intent. This note is the record of what actually worked.

The memory note `ios-ipa-dynamic-vehicle` says pinning is not visible. That was true for a string
scan of named pinning libraries, but the reinforcement SDK carries its own certificate check,
`JMCheckHttpsCer`, and an embedded proxy CA name. Pinning is present, just
not through a named third party library. See `Anti-Tamper-Surface.md`.

## Recommended Next Steps

1. Neutralize the anti tamper SDK. The recon session showed the termination on resume, so the
   next task is the bypass, not more confirmation. The spawn pause lands before app code runs, which
   is the window to hook `JMSafeExit`, the single choke point, plus `exit` and `abort` as fallbacks.
   Confirm the exact target and call site in the decrypted binary with Ghidra, then write the hook
   into a new `scripts/ios-frida/anti-tamper.js` loaded before resume.
2. Pin down the terminating frame to be certain. Hook `exit`, `abort`, and `JMSafeExit`, resume, and
   read the backtrace at termination, or pull a fresh crash report and confirm the frame is in the
   app rather than in the agent.
3. With the app alive and hooked, run the network and crypto hooks, log in, and trigger a check for
   update to capture the signing material for Goal 1 and the firmware URL and md5 for Goal 2.
