# Problem Statement: iOS Anti Tamper Bypass

This plan continues the iOS Frida Injection session, written up in
`research/notes/2026-09-01_iOS-Frida-Injection/`. Read that `Summary.md` first, then
`Working-Injection-Flow.md` and `Anti-Tamper-Surface.md`. That session got a jailed spawn Frida
session attaching to the app on iOS 26. The app then self terminates the instant its own code runs.
The goal now is to defeat the anti tamper SDK so the app runs under Frida to the firmware
upgrade screen, the point where the signing material and the firmware download can be captured.

## Background

Facts carried over from the prior session. See the referenced notes for detail.

- Injection works through jailed spawn, not an embedded gadget. Frida launches the app under
  `debugserver`, which relaxes code signing, then loads its agent. The embedded gadget is a dead end
  on iOS 26. The operational steps are in `scripts/ios-frida/COMMANDS.md`.
- The runtime symptom is a clean kill on resume. `recon.js` enumerates the whole process during the
  spawn pause and finishes. The moment the main thread resumes, the process terminates. The
  unmodified app stays up, so this is the anti tamper SDK responding to the Frida agent.
- The SDK is statically linked into the main binary. It exposes a detection taxonomy of `APP_FIRM_`
  codes, including `LIBRARY_INJECTION` and `HOOK_ATTACK`, funneled through one Swift kill switch,
  `JMSafeExit`. It also carries `JMCheckHttpsCer` pinning and an Anker `ACSafety` and `ACJailBreak`
  layer. It is most likely the ijiami iOS reinforcement product, an inference from the `JM` naming.
- The binary is arm64, `MH_EXECUTE`, PIE, preferred base `0x100000000`. The `JM` functions are
  stripped from the symbol table, so their names survive only in Swift reflection metadata and
  `__cstring`. The exit family imports `_exit`, `_abort`, `_kill`, `__Exit`, and C++ terminate are
  present and are the anchors for finding the kill path.
- The crypto surface is fully hookable. `recon.js` resolved the OpenSSL and CommonCrypto HMAC,
  SHA256, and ECDH primitives with addresses, so the recovered signer can be observed once the app
  runs.

## The Ghidra Project

The main app executable `Payload/SoundCore.app/SoundCore` is imported into Ghidra and auto analyzed,
and the `ghidra` MCP server reaches it. The Swift demangler analyzer crashed on some symbols and did
not fully run. This is acceptable. The kill switch is found through string cross references and exit
import callers, none of which need demangling, because the `JM` names are not mangled symbols in the
first place. They are plain strings in the reflection metadata. Targeted demangling of a single
symbol can be done by hand through the MCP later if one matters.

## Strategy

Two tracks that feed each other.

- Static, in Ghidra. Locate `JMSafeExit`, the dispatcher that maps a detection result to the exit,
  and the detection call sites. This says exactly what to hook and whether one hook is enough.
- Dynamic, in Frida. Install the hook during the spawn pause, before app code runs, then resume and
  observe. The spawn pause is the safe window because the prior session proved detection runs after
  resume, not at agent load.

## Goal 0: Locate The Kill Switch In Ghidra

Find `JMSafeExit` and the detection dispatcher. Method:

- Cross reference the `APP_FIRM_` result strings and the `JMSafeExit`, `JMDetectionResult`, and
  `JMExitAlertType` strings to their referencing functions.
- Enumerate callers of `_exit`, `_abort`, `_kill`, `__Exit`, and `std::terminate`. The function that
  references the `APP_FIRM_` codes and reaches an exit primitive is the dispatcher.
- Name the functions and record the address of `JMSafeExit`, the dispatcher, and each
  detection routine. Convert to runtime form with `runtime = ghidra - 0x100000000 + module base +
  slide`.

Success is a confirmed `JMSafeExit` address and a clear picture of how many code paths reach it.

## Goal 1: Prove The Runtime Kill Path

Turn the strong evidence into proof. Hook `exit`, `_exit`, `abort`, `kill`, and the candidate
`JMSafeExit` address, resume the spawned app, and read the backtrace at the moment of termination.
This confirms which function terminates the process, that it is reached from the app rather than the
agent, and that the Ghidra target matches the running binary.

## Goal 2: Build The Bypass

Write `scripts/ios-frida/anti-tamper.js`. Neutralize `JMSafeExit` to return without exiting, with
`exit`, `_exit`, `abort`, and `kill` hooked as a backstop, all installed during the spawn pause
before resume. Validate that the app survives resume, reaches its home screen, and stays alive.

If a single choke point is not enough, fall back to the dispatcher or to the individual detection
routines named in Goal 0, or block the exit primitives only for callers inside the app text range.

## Goal 3: Reach The Firmware Upgrade Screen

With the bypass active, drive the app by hand. Log in, open the paired device, and navigate to the
firmware or OTA screen. Confirm the app survives the check for update. This is the headline
goal, a live Frida session sitting on the upgrade screen.

It's possible to use the app without logging in to an account, so it may be possible to drive this
step without one as well.

## Goal 4: Capture, Handoff To The Original Goals

With the app stable on the upgrade screen, load `network-hooks.js` and `crypto-hooks.js`, trigger a
check for update, and capture the signed request, the ECDH and HMAC material, and the firmware URL
and md5. This reconnects to Goals 1 and 2 of the prior plan and may run as its own session.

## Risks

- One hook may not be enough. Detection may call an exit primitive, or re run on a timer. If
  the app dies later rather than on resume, a periodic re check is firing and the hook must cover
  every path, which is why Goal 0 enumerates all of them.
- The SDK may check its own code for hooks. `HOOK_ATTACK` implies an integrity check that could
  notice an inline patch on `JMSafeExit`. Prefer replacing the function whole, or hook a caller or
  the exit primitive, and watch for a second kill after the first is defeated.
- Early detection. If any check runs from a Swift static initializer before the spawn pause hands
  off, the hook lands too late. The prior session makes this unlikely, as the process survived the
  pause, but confirm in Goal 1.

## Deliverables

- Named functions and plate comments in Ghidra for `JMSafeExit`, the dispatcher, and the detection
  routines. These are all `FUN_` names now, so no existing names are overwritten.
- `scripts/ios-frida/anti-tamper.js`, loadable before resume.
- Notes in `research/notes/2026-09-02_iOS-Anti-Tamper-Bypass/` covering the dispatcher logic, the
  hook, and the walkthrough to the upgrade screen.
