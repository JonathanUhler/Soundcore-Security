# The Kill Switch And The Detection Structure

This is the static Ghidra finding for Goal 0. It locates the named kill switch, corrects its name,
and maps the SDK's detector to dispatcher to terminate structure. All addresses use the Ghidra
preferred base of `0x100000000`. Runtime addresses are `ghidra - 0x100000000 + module base + slide`,
which reduces to `main image base + offset` because the preferred base is `0x100000000`.

## The Named Kill Switch Is showAJMSafeExit

A string search for `JMSafeExit` returns only two hits, and both are `showAJMSafeExit`, not a bare
`JMSafeExit`. The research memory `ios-anti-tamper-sdk` recorded the name as `JMSafeExit`. The
accurate name is `showAJMSafeExit(type:handler:)`, a Swift static method on the class
`SoundCore.DKAlertCountDownView`. The leading `A` is an Anker prefix that also appears on the
`AJMExitAlertType` enum and the `AC` safety layer.

The relevant addresses, all previously `FUN_` names and now renamed in the Ghidra project.

| Address (ghidra) | Offset    | Name                                       | Role                        |
|------------------|-----------|--------------------------------------------|-----------------------------|
| `0x100188e94`    | `0x188e94`| `SC_DKAlertCountDownView_showAJMSafeExit`  | Swift impl of the funnel    |
| `0x100188fe8`    | `0x188fe8`| `-[DKAlertCountDownView showAJMSafeExitWithType:handler:]` | @objc thunk  |
| `0x100188948`    | `0x188948`| `SC_DKAlertCountDownView_countdownAlert_init` | Countdown alert builder  |
| `0x101f288d4`    | `0x1f288d4`| `JM_jailbreakPathScan`                    | Native JB path scanner      |
| `0x1053db8f8`    | n/a       | `g_abJmJailbreakScanResult`                | Jailbreak verdict global    |

The @objc thunk was reached from the class method list at `0x10460d1c8`, a classic non relative
`method_t` triple of name, types, and imp. The name pointer is the selector string
`showAJMSafeExitWithType:handler:`, the types string is `v32@0:8q16@?24`, and the imp is the thunk.
The type encoding decodes to a void method taking an `NSInteger` type at offset 16 and a block at
offset 24, matching `showAJMSafeExit(type: AJMExitAlertType, handler: (() -> ())?)`.

## What showAJMSafeExit Does

The Swift impl maps the `AJMExitAlertType` enum to a localized risk dialog string, then builds a five
second countdown alert.

- type 0, `dialog_risk_network_proxy_des`, the HTTP or VPN proxy risk, which pairs with
  `APP_FIRM_HTTP_DETECTION` and `APP_FIRM_VPN_DETECTION`.
- type 1, `dialog_risk_app_resign_des`, the re-sign or signature tamper risk, `APP_FIRM_SIGNATURE_TAMPER`.
- type 2, `dialog_risk_system_env_des`, the jailbreak or system environment risk.
- default, a Swift `diagnoseUnexpectedEnumCaseValue` trap.

`SC_DKAlertCountDownView_countdownAlert_init` at `0x100188948` sets `countdownTime` to 5 and stores a
`handlerBlock`. The countdown timer fires the stored handler when it reaches zero. The handler is the
caller supplied closure, and it is the handler that terminates the app. There is no exit primitive in
the `0x10018xxxx` cluster, so `showAJMSafeExit` itself does not call `exit`. It shows UI and defers
the actual termination to the closure that the detection code passed in.

This matters for the bypass. `showAJMSafeExit` is the graceful path. It needs a key window to present
the alert, and it waits five seconds. The prior session saw an instant clean kill on resume with no
dialog. So the first kill on resume is almost certainly a direct `exit` or `_exit` in native
detection code that runs before the UI is ready, not this alert. The bypass must therefore cover the
exit primitives, and treat `showAJMSafeExit` as a secondary funnel that fires later in the lifecycle.

## The Detection Taxonomy

The binary contains the full `APP_FIRM_` result code set as plain strings, referenced from a data
table near `0x104351c00` that reads as a logging or reporting map rather than the dispatcher itself.

`APP_FIRM_LIBRARY_INJECTION`, `APP_FIRM_HOOK_ATTACK`, `APP_FIRM_DEBUG`, `APP_FIRM_FUNC_DEBUG`,
`APP_FIRM_SIGNATURE_TAMPER`, `APP_FIRM_MODIFY_CODE`, `APP_FIRM_SOURCE_FILE_MODIFIED`,
`APP_FIRM_NON_APPSTORE_DOWNLOAD`, `APP_FIRM_OBSTRUCT_JAIL_DECT`, `APP_FIRM_HTTP_DETECTION`,
`APP_FIRM_VPN_DETECTION`. The two that target Frida jailed spawn are `LIBRARY_INJECTION`, an injected
dylib, and `HOOK_ATTACK`, an inline or ObjC hooking runtime.

## The Detector To Dispatcher To Terminate Model

`JM_jailbreakPathScan` at `0x101f288d4` is a clean example of a detector. It probes classic jailbreak
artifacts, `fopen` on `/bin/bash`, `/Applications/Cydia.app`,
`/Library/MobileSubstrate/MobileSubstrate.dylib`, `/usr/sbin/sshd`, and `/etc/apt`, a `stat` on
Cydia, a `getenv` on `DYLD_INSERT_LIBRARIES`, `NSFileManager` and `NSURL` existence checks for
panguaxe, xuanyuansword, Cydia, MobileSubstrate, bash, sshd, and apt, and a write probe to
`/private/jailbreak.txt`. It does not terminate. It records the verdict in the global
`g_abJmJailbreakScanResult` at `0x1053db8f8` and returns. A separate dispatcher consumes the verdict.

This confirms the SDK shape. Detectors set flags or return codes. A dispatcher maps a positive result
to a termination, either the graceful `showAJMSafeExit` alert when UI is available or a direct exit
when it is not. The detectors are obfuscated native ObjC reached through `objc_stub` thunks, so a
static patch cannot cleanly cover every one. The bypass targets the shared endpoint, the exit
primitives, instead.

## Obfuscation And The Injection Check

The Objective C class name table at `0x103efa400` interleaves the real reinforcement classes with
fake e-commerce decoys, `GNTaxCalculator`, `GNEmailSender`, `GNSensorManager`, `GNNetworkClient`,
`GNPaymentProcessor`, `GNAuctionPlatform`, `GNMarketplacePlatform`, and more. The real classes hidden
among them are `SCJMConfig`, `JMCheckHttpsCer`, `JMExpection`, `IJMRLog`, `DetectFakeLocation`,
`ACSafety`, and `ACJailBreak`. Decoy class names are a known ijiami tactic.

The injection detection reads the loaded image list rather than matching tool names. The binary
carries `_dyld_get_image_name`, `_dyld_get_image_header`, and `_dyld_get_image_vmaddr_slide` as
strings that are resolved dynamically, which is how `APP_FIRM_LIBRARY_INJECTION` spots an injected
dylib such as Frida's gum agent. There are no literal `frida` or `cycript` strings. The consequence
for the bypass is that hiding the Frida image from the dyld enumeration is possible but optional. It
makes the process cleaner, but blocking the exit primitives already defuses the response.

## Pinning

`JMCheckHttpsCer` is the SDK's own certificate check, and the binary embeds a `Test Untrusted Root CA`
marker. This is the same SDK that raises `APP_FIRM_HTTP_DETECTION`, so one component gates both the
Frida path and a naive mitmproxy path. This corrects the memory note `ios-ipa-dynamic-vehicle`, which
reads pinning as not visible. A named pinning library is absent, but the reinforcement SDK does its
own certificate check. The Frida capture path reads plaintext inside the process, so it sidesteps the
pin regardless.
</content>
