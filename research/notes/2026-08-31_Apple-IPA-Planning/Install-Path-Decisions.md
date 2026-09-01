# Install Path Decisions And Verification

This file records how the IPA was loaded onto hardware, the constraints that shaped the choice, and
how the run was verified. It answers Goal 0 of
`research/plans/2026-08-31_Apple-IPA-Planning/Problem-Statement.md`. The static findings it relies on
are in `Static-Analysis.md`.

## Why This Path Existed At All

The project reached the iOS IPA after the Android dynamic path stalled. The Soundcore Android app is
packed by ijiami with per method extraction, and the emulator kills itself before the signing methods
run, so the request signing bytecode is never present in a RAM dump. See
`../2026-08-30_App-Dex-Analysis` and `../2026-08-31_Ijiami-Buffer-Scrape`. The iOS build has no such
packer, so it is a more accessible target for both proxy capture and Frida.

## The Unmodified Constraint

The problem statement hoped the IPA could run unmodified. Static analysis showed that is only partly
possible. The binaries are FairPlay decrypted, which rewrites the `__TEXT` pages that Apple's original
code signature sealed, so that signature no longer validates. The package also carries no provisioning
profile. Two consequences follow.

On a stock device the app cannot install untouched and must be re-signed. Re-signing replaces the code
signature and the bundle identifier only, and it leaves the decrypted code bytes unchanged, so the
running code is still the shipped code. A truly untouched install is possible only on a jailbroken
device with a signature check bypass such as AppSync Unified. The project device is stock, so
re-signing was accepted as the path, and the word unmodified is understood here as the code being
unaltered rather than the package being byte identical.

## Options Considered

Three routes were evaluated.

- Linux host on Ubuntu 22.04, using either AltServer-Linux with AltStore, or `zsign` with
  `ideviceinstaller`. This is scriptable and Linux native, and `zsign` is convenient for the later
  Frida repack. The blocking gotcha is that the apt `libimobiledevice` on 22.04 is version 1.3.0 from
  2020, which is too old to pair with modern iOS. It needs an upstream or nightly build first.
- Mac with Xcode, doing a manual `codesign` re-sign driven by an Xcode provisioned free certificate
  and profile, then installing with `xcrun devicectl`. Fully official, but tedious, since all 124
  frameworks must be signed inside out by hand.
- Sideloadly on the Mac. Third party, but it wraps the Xcode certificate machinery and automates the
  free account login, device registration, entitlement reduction, bundle id rewrite, extension
  removal, and the recursive re-sign.

## Free Apple Account Constraints

The account available is a free personal team. A free team cannot sign these entitlements, all of
which the app requests, HealthKit, Sign in with Apple, push `aps-environment`, WiFi info, Hotspot
Configuration, and App Groups. That forces two changes at re-sign time.

- Reduce the app entitlements to `application-identifier`, `com.apple.developer.team-identifier`, and
  `get-task-allow`. Keeping `get-task-allow` is deliberate, since it lets a debugger and later Frida's
  debugserver attach.
- Remove the `pushService` and widget app extensions. They depend on push and the App Group and
  cannot be signed on a free account on their own. Neither the entitlement reduction nor the extension
  removal touches the firmware update code path, so the research target is unaffected.

Two further free account limits apply. The signed app expires after 7 days and must be refreshed, and
a free account may hold at most 3 sideloaded apps at once.

## Path Taken

Sideloadly on the Mac was chosen and it succeeded. Even on slow hardware it was the lowest effort
route, and it still relies on the official Apple developer services under the account. The relevant
Sideloadly settings were the Remove app extensions option, an auto generated unique bundle
identifier, and an app specific password to satisfy the mandatory Apple ID two factor step. Sideloadly
then created the free development certificate, registered the device, generated the profile,
re-signed the app and all frameworks, and installed the result.

## Verification

The user confirmed the app installs and runs from the Mac by way of Sideloadly. The intended
acceptance criteria for Goal 0 were that the app reaches the Flutter home screen without an immediate
crash, which proves the decrypted main binary and the Dart `App.framework` execute, and that it can
pair the P20i and open the check for update screen, which proves the network path runs. iOS has no
ijiami packer and no emulator self kill, so unlike the Android path this ran without a fight.

## Carry Forward For The Next Goals

The install path already prepares the ground for the two follow on goals.

- For mitmproxy, try the plain trusted CA route first, since ATS is disabled and no pinning library is
  evident. Keep an SSL bypass in reserve for any Dart routed traffic. The recovered Android signing
  scheme is app layer and lives inside the TLS body, so a proxy will see the signed requests, though
  replaying or modifying them still needs a valid signature.
- For Frida, the decrypted binary means a gadget repack works. Sideloadly's injection field accepts a
  dylib, so injecting `FridaGadget.dylib` is the same install flow used here, and `get-task-allow` is
  already retained for a debugserver based attach as an alternative.
