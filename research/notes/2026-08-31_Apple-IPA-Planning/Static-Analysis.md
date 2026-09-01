# Static Analysis Of The iOS IPA

These notes correspond to the plan in
`research/plans/2026-08-31_Apple-IPA-Planning/Problem-Statement.md`. This file records the read only
analysis of `ipa/com.oceanwing.SoundCore_5.0.02_und3fined.ipa`. Every finding below came from
parsing the archive and the Mach O structures. The app was never executed or modified during this
work.

## Method And Tooling

The research host had no `unzip`, `otool`, `codesign`, `lipo`, or `macholib`. An IPA is a plain zip,
so the archive was read with Python `zipfile`, and the Mach O headers, load commands, and code
signature blobs were parsed by hand with `struct`. Everything here is reproducible from the IPA file
alone, with no Apple or third party tooling required.

## Archive Integrity

The archive is structurally sound. It holds 4788 entries and every entry passes its CRC check, so the
download is neither truncated nor corrupt. The only package level oddity is a 9 byte file at
`Payload/decrypt.day` whose contents are the ASCII string `und3fined`. This is a marker left by the
decryption and repack tool. It is the first of two independent signals that the app binaries are no
longer FairPlay encrypted.

## Bundle Identity

Read from `Payload/SoundCore.app/Info.plist`.

| Field | Value |
| --- | --- |
| `CFBundleIdentifier` | `com.oceanwing.SoundCore` |
| `CFBundleShortVersionString` | `5.0.02` |
| `CFBundleVersion` | `2` |
| `MinimumOSVersion` | `13.0` |
| `DTPlatformName` / `DTSDKName` | `iphoneos` / `iphoneos26.2` |
| `DTXcode` / `DTXcodeBuild` | `2620` / `17C52` |
| `UIDeviceFamily` | `[1]` (iPhone only) |
| `NSAppTransportSecurity` | `NSAllowsArbitraryLoads = true` |

The build is recent. It was compiled against the iOS 26.2 SDK with Xcode 26, while still supporting
iOS 13.0 and up. The low minimum deployment target matters for hardware choice, since an older iPhone
on iOS 14 to 16 is a valid and easier target than a current iOS 26 device.

## The Binaries Are FairPlay Decrypted

This is the central finding. Every Mach O executable in the package carries
`LC_ENCRYPTION_INFO_64` with `cryptid` set to `0`, which means the FairPlay encryption has already
been stripped. The `und3fined` marker and the `cryptid` values agree, so the decryption is confirmed
by two independent signals.

| Executable | Architecture | `cryptid` | `cryptsize` |
| --- | --- | --- | --- |
| `SoundCore` (main) | arm64, PIE, `MH_EXECUTE` | `0` decrypted | `67616768` |
| `PlugIns/SoundCoreWidget.appex` | arm64 | `0` decrypted | `1671168` |
| `PlugIns/pushService.appex` | arm64 | `0` decrypted | `32768` |
| `PlugIns/SoundCoreWidgetExtensionExtension.appex` | arm64 | `0` decrypted | `1474560` |
| `Frameworks/App.framework/App` | arm64 | `0` decrypted | `22413312` |
| `Frameworks/Flutter.framework/Flutter` | arm64 | `0` decrypted | `8896512` |

The main binary is a single architecture arm64 thin Mach O, not a fat binary, which is expected for a
modern thinned App Store download. It is position independent and reports `LC_BUILD_VERSION` platform
iOS, minimum `13.0.0`, SDK `26.2.0`. A decrypted binary is what makes this IPA useful. Static
disassembly reads real instructions, patching is possible, and a Frida gadget can be injected.

There are no injected instrumentation dylibs in the package. A scan for gadget, frida, substrate,
cydia, and substitute artifacts across all 4788 entries found nothing, so this is a clean decrypted
dump rather than an already tampered build.

## Code Signature And Provisioning

The package contains no `embedded.mobileprovision` anywhere. That is normal for an App Store build,
since store distribution apps are signed by Apple and carry no provisioning profile. Apple
`_CodeSignature/CodeResources` seals are present for the app and every framework.

The practical consequence is covered in `Install-Path-Decisions.md`. The short version is that
FairPlay decryption alters the `__TEXT` pages that the original Apple signature sealed, so that
signature no longer validates, and with no profile in the package the app cannot install on a stock
device without being re-signed.

## Requested Entitlements

The entitlements were recovered by parsing the embedded entitlements blob, magic `0xfade7171`, out of
the main and extension code signatures. The original signing team is `BVL93LPC7F`, which is Anker and
Oceanwing.

Main app `SoundCore`:

| Entitlement | Value |
| --- | --- |
| `com.apple.developer.healthkit` | true |
| `com.apple.developer.applesignin` | `Default` |
| `aps-environment` | `production` |
| `com.apple.developer.networking.wifi-info` | true |
| `com.apple.developer.networking.HotspotConfiguration` | true |
| `com.apple.security.application-groups` | `group.com.oceanwing.SoundCore` |
| `com.apple.developer.device-information.user-assigned-device-name` | true |
| `application-identifier` | `BVL93LPC7F.com.oceanwing.SoundCore` |

The `pushService` extension requests `aps-environment`, and the widget extension requests the
`group.com.oceanwing.SoundCore` App Group. These entitlements drive the re-signing plan, since a free
Apple account cannot sign any of HealthKit, Sign in with Apple, push, WiFi info, Hotspot
Configuration, or App Groups.

## Transport Security And Certificate Pinning

App Transport Security is fully disabled. `Info.plist` sets `NSAllowsArbitraryLoads` to true, so the
app permits non ATS TLS and cleartext at the OS layer. A trusted proxy certificate therefore passes
ATS with no obstacle.

A string scan for common pinning implementations was favorable but not conclusive. The main binary
and the Alamofire framework contain only `SecTrustEvaluate`, which is the default system trust API,
not evidence of pinning. There were no hits for `TrustKit`, `AFSecurityPolicy`, `ServerTrustManager`,
`PinnedCertificatesTrustEvaluator`, `PublicKeysTrustEvaluator`, or `pinnedPublicKey`. The Dart AOT
image in `App.framework` produced no pinning keyword hits either, though Dart strings can be split or
obfuscated in an AOT build, so absence there is weaker evidence.

The takeaway for interception is that a plain trusted CA attempt with mitmproxy has a good chance of
working with no binary patching, especially for the native networking path. The one caveat is that
Dart `dart:io` does not always honor user installed CAs, so any traffic routed through Flutter may
still need an SSL bypass. The Android request signer was recovered in Kotlin `aknetwork`, which
suggests the iOS OTA calls are native rather than Dart, which is the favorable case.

## Frameworks Of Interest

The bundle ships 124 framework bundles. The app is a hybrid of native iOS and Flutter. The Flutter
side is `Flutter.framework` plus `App.framework`, where `App.framework` holds the compiled Dart AOT
image. Networking relevant native frameworks include Alamofire, Moya, Starscream, and OpenSSL. The
absence of a dedicated pinning library among these is consistent with the string scan above.

## FairPlay Metadata Leftovers

Each code bearing bundle still carries an `SC_Info` directory with FairPlay license files, the
`.sinf`, `.supp`, `.supf`, and `.supx` blobs. These are vestigial now that the binaries are
decrypted. They can be left in place or removed before re-signing. A re-sign regenerates
`_CodeSignature/CodeResources` regardless, so they have no effect on the running app.

## Summary Of The Read Only Verdict

The IPA is clean, complete, and decrypted. Nothing in it is corrupt or broken. It cannot install on a
stock device untouched, not because of any damage, but because decryption invalidated Apple's
signature and no provisioning profile is present. That is a re-signing task, not a repair task, and
it is handled in `Install-Path-Decisions.md`.
