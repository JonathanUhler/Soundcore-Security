# Notes: Apple IPA Planning

These notes correspond to the plan in
`research/plans/2026-08-31_Apple-IPA-Planning/Problem-Statement.md`. The plan obtained an iOS IPA of
the Soundcore app after the Android dynamic path stalled, and asked first to verify that the IPA can
run unmodified, and to do read only analysis to confirm it is not corrupt.

## Status

Goal 0 is resolved. The IPA was analyzed statically without modification, found clean and decrypted,
re-signed with a free Apple account through Sideloadly on a Mac, and confirmed running on hardware by
the user. The project now has a working iOS dynamic testing vehicle, which replaces the blocked
Android emulator path.

## Files In This Note

- `Summary.md`: this file. Status, the headline findings, and next steps.
- `Static-Analysis.md`: the read only analysis of the IPA. Archive integrity, bundle identity, the
  FairPlay decryption proof, the code signature state, the recovered entitlements, and the transport
  security and pinning scan.
- `Install-Path-Decisions.md`: the decision log for loading the IPA. The unmodified constraint, the
  options considered, the free account entitlement constraints, the Sideloadly path taken, and the
  verification.

## Headline Findings

- The archive is intact. All 4788 entries pass their CRC checks. Nothing is corrupt or truncated.
- The app is FairPlay decrypted. Every Mach O executable, the main binary, all three app extensions,
  and both Flutter binaries, has `cryptid` 0. A `Payload/decrypt.day` marker reading `und3fined`
  agrees. A decrypted binary is what makes static analysis, patching, and Frida injection possible.
- It cannot install on a stock device untouched. Decryption invalidated Apple's signature and there
  is no provisioning profile in the package. This is a re-signing task, not a repair task. The code
  itself is intact.
- The main binary is single architecture arm64, built against the iOS 26.2 SDK, with a minimum
  deployment target of iOS 13.0.
- App Transport Security is disabled by `NSAllowsArbitraryLoads`, and no dedicated certificate pinning
  library is evident, which is favorable for a mitmproxy attempt.
- The original signing team is `BVL93LPC7F`, Anker and Oceanwing. The app requests entitlements a free
  account cannot sign, which forced entitlement reduction and removal of the push and widget
  extensions at re-sign time.

## What Runs Now

A free account re-sign through Sideloadly on the Mac, with app extensions removed and entitlements
reduced to `application-identifier`, `team-identifier`, and `get-task-allow`. The app installs and
launches on the stock device. The 7 day free account expiry and the 3 app limit apply, so the install
will need periodic refreshing.

## Recommended Next Steps

These follow the two later goals named in the problem statement, now unblocked by a running app.

1. Attempt mitmproxy interception of the check for update flow with only a trusted proxy CA installed
   on the device. ATS is off and no pinning library is visible, so the native networking path is
   likely interceptable without patching. Keep an SSL bypass in reserve for any Flutter Dart traffic.
2. Confirm the recovered Anker request signing scheme against a real captured request. The scheme is
   documented in `../2026-08-31_Ijiami-Buffer-Scrape/Signing-Scheme-Static-Recovery.md`. It lives
   inside the TLS body, so a working proxy will expose one real request, which is enough to validate a
   reimplemented signer.
3. Build a Frida enabled variant by injecting `FridaGadget.dylib` at the same Sideloadly install step.
   The decrypted binary and the retained `get-task-allow` entitlement make both gadget and debugserver
   based attachment viable.
