# Notes: iOS Anti Tamper Bypass

These notes correspond to the plan in
`research/plans/2026-09-02_iOS-Anti-Tamper-Bypass/Problem-Statement.md`. The plan set out to defeat
the JM/ijiami reinforcement SDK so the re-signed iOS Soundcore app runs under Frida to the firmware
upgrade screen, where the signing material and firmware download can be captured.

## Status, Closed

The Frida bypass is abandoned. Eight device runs proved that a reactive bypass cannot work on this
target, and the session then pivoted to extracting the signing material another way. The full run by
run history is in `Bypass-And-Walkthrough.md`. The pivot and its findings are in
`Pivot-To-Signing-Extraction.md`. The follow on work is planned in
`research/plans/2026-09-03_iOS-Signing-Dylib-Extraction/Problem-Statement.md`.

The core reason the bypass fails is structural. The SDK does not kill with a function call. On
detecting the gum agent it strips execute permission from its own hook trampoline pages, so every
call routed through them faults as an instruction fetch, on every thread, and a watchdog re-strips
them. Recovering the pages is impossible on this process, because iOS AMFI refuses to execute
unsigned or re-armed memory and the sideloaded app has no JIT entitlement. So the faults cannot be
patched into a boot. The only way through is to stop the detection, and the detection vector is not
one we could neutralize from inside a Frida session.

## Files In This Note

- `Summary.md`, this file. The closed out status and the corrected headline findings.
- `Kill-Switch-Analysis.md`, the static Ghidra findings on `showAJMSafeExit`, the alert type mapping,
  the countdown alert, the jailbreak scanner, and the detector to dispatcher model.
- `Bypass-And-Walkthrough.md`, the design of `anti-tamper.js` and the eight run history that led to
  the abandonment, each result and the change it forced.
- `Pivot-To-Signing-Extraction.md`, the pivot to pulling the firmware by a signed API call. The iOS
  KMP signing structure, the failed dynamic capture, the detection surface, and the assessment that a
  passive custom dylib is the viable path.

## Corrected Headline Findings

The early Summary made two claims that later runs disproved. They are corrected here.

- The instant kill is not a direct `exit` in native code. It is an execute permission strip on the
  SDK's own import trampoline pages, seen at runtime as instruction fetch faults on non executable
  pages. No libc terminator is called. This is why hooking `exit`, `abort`, `kill`, and the Mach
  terminators never caught it.
- Injection detection is not primarily the dyld image list. Frida's gum agent is not a dyld image at
  all, only `libffi-trampolines.dylib` shows as foreign, yet the app still detects it. The detection
  reads process memory with `_vm_region_64` and enumerates threads with `_task_threads` and
  `_thread_info`. It also resolves `_dyld_get_image_name`, `_dyld_image_count`, and `_dladdr`, so it
  can walk the image list too, but the image list is not what catches jailed spawn gum.

What still holds from the early findings.

- The named kill switch is `showAJMSafeExit(type:handler:)` on `SoundCore.DKAlertCountDownView`, not a
  bare `JMSafeExit`. It is the graceful UI countdown alert, a secondary path, not the instant kill.
- The SDK is a detector to result flag to dispatcher pipeline, with obfuscated native ObjC detectors
  and decoy class names like `GNPaymentProcessor`. The real classes are `SCJMConfig`,
  `JMCheckHttpsCer`, `JMExpection`, `IJMRLog`, `ACSafety`, and `ACJailBreak`.

## What The Session Produced

- Named functions and plate comments in the Ghidra project for `showAJMSafeExit`, its @objc thunk,
  the countdown alert builder, the jailbreak path scanner, and the jailbreak result global.
- `scripts/ios-frida/anti-tamper.js`, the full layered bypass. It does not defeat the anti tamper, but
  it is a complete record of every mechanism tried, the exception handler exec memory rescuer, the
  anti anti debug hooks, the terminator net, and the protection guards.
- `scripts/ios-frida/capture-signing.js`, address only hooks on the KMP config and signer, for the
  race capture attempt.
- The signing structure recovered from the iOS binary, and the custom dylib viability assessment. See
  `Pivot-To-Signing-Extraction.md`.

## The Deliverables That Did Not Land

Goals 1 through 4 of the plan, a live Frida session on the upgrade screen and the captured signing and
firmware material, were not achieved. The anti tamper is a hard wall for the Frida path on this
device. The signing material is instead pursued by the custom dylib plan, and the firmware file itself
remains reachable by the hardware dump shortcut in
`../2026-08-31_Ijiami-Buffer-Scrape/Firmware-Encryption-Analysis.md` if the software path stalls.
</content>
