# Problem Statement: iOS Frida Injection

This plan continues the Apple IPA Planning session, written up in
`research/notes/2026-08-31_Apple-IPA-Planning/`. Read that `Summary.md` first. It established a
running, re-signed iOS build of the Soundcore app on a stock iPhone. The goal now is to instrument
that build with Frida so the request signing material and the firmware download flow can be observed
live and, if useful, driven directly.

## Background

Key facts carried over from prior sessions. See the referenced notes for detail.

- The IPA in `ipa/com.oceanwing.SoundCore_5.0.02_und3fined.ipa` is FairPlay decrypted, arm64,
  minimum iOS 13, built against the iOS 26.2 SDK. All six Mach O executables report `cryptid` 0. See
  `research/notes/2026-08-31_Apple-IPA-Planning/Static-Analysis.md`.
- The app is running on a stock, non jailbroken iPhone, re-signed with a free Apple ID through
  Sideloadly on a Mac. App extensions were removed and entitlements reduced to
  `application-identifier`, `team-identifier`, and `get-task-allow`. See
  `research/notes/2026-08-31_Apple-IPA-Planning/Install-Path-Decisions.md`.
- App Transport Security is disabled by `NSAllowsArbitraryLoads`. A static string scan found no named
  pinning library, only `SecTrustEvaluate`, which is also how a custom pin would be built, so pinning
  is not ruled out.
- The Android firmware status host `speaker.eufylife.com` is served from an APISIX gateway and is
  certificate pinned in the app. The signing artifacts observed there are `gToken`, `signKey`,
  `app_key`, `token`, `timestamp`, `nonce`, and `sign`. See
  `research/notes/2026-08-29_OTA-API-Reconstruction/`.
- A separate, newer scheme was recovered statically, an ECDH P-256 exchange with two tier
  HMAC-SHA256 signing at `/openapi/oauth/key/exchange`. See
  `research/notes/2026-08-31_Ijiami-Buffer-Scrape/Signing-Scheme-Static-Recovery.md` and the memory
  note `anker-signing-scheme-recovered`.
- The firmware download itself carries only an `md5` checksum in the API response, so the file URL is
  most likely a plain unauthenticated CDN GET once the signed check for update call returns it. See
  `research/notes/2026-08-31_Ijiami-Buffer-Scrape/Firmware-Encryption-Analysis.md`.

## Why Frida And Not The Proxy First

Hooking runs inside the process, above TLS. It reads the plaintext request and response objects and
the raw key and MAC buffers regardless of certificate pinning. That defeats the `speaker.eufylife.com`
pin without a bypass, and it exposes the signing inputs that a proxy alone cannot show. The proxy path
remains a useful parallel cross check, but Frida is the primary tool for the signing material.

## Injection Approach

The chosen method is the Frida Gadget, a signed dylib added to the app bundle with a matching
`LC_LOAD_DYLIB` load command, so dyld loads it at launch. `frida-server` is not an option on a stock
device. The decrypted binary and the same team re-sign satisfy iOS library validation.

The injection is performed with Sideloadly, reusing the known good signing flow. The gadget dylib is
dropped into Sideloadly's dylib injection box, and Sideloadly copies it into `Frameworks/`, adds the
load command, and signs it during the normal re-sign. The exact commands and settings are in
`scripts/ios-frida/COMMANDS.md`.

The instrumentation scripts live in `scripts/ios-frida/`.

- `recon.js` confirms the gadget loaded and maps the crypto surface, the loaded modules, the relevant
  ObjC classes, and the OpenSSL and CommonCrypto exports.
- `network-hooks.js` captures TLS decrypted requests and responses at the `NSURLSession` layer.
- `crypto-hooks.js` logs the HMAC, SHA, and ECDH primitives in CommonCrypto and OpenSSL, plus a
  template for hooking the app's own signing methods once recon names them.

## Goal 0: Produce And Load The Frida Build

Inject the gadget, re-sign through Sideloadly, install, and confirm attachment. Success is
`frida-ps -U` listing the `Gadget` process and `recon.js` printing the process architecture and the
module list from the device.

## Goal 1: Capture The Signing Material And The Update Check

With hooks in place, exercise the app through login and a manual check for update. Capture the full
signed request for the key exchange and the check for update call, the derived ECDH shared secret, the
HMAC keys and outputs, and the assembled headers. Confirm which signing scheme the iOS build actually
uses, the gateway `gToken` and `sign` family, the newer ECDH and HMAC family, or both.

## Goal 2: Obtain The Firmware Binary

Read the firmware file URL and `md5` out of the check for update response. Then either let the app
download it and pull the file from the app container, or replay the captured signed request from a
script to fetch the URL directly. Confirm the file is a Jieli update image and hand it to the
descrambler path already scoped in the Ijiami Buffer Scrape notes.

## Risks

- Gadget and `frida-tools` version mismatch is the most common failure. Pin both.
- The app is a Flutter and native hybrid. If the networking or crypto runs through Dart rather than
  native `NSURLSession` and OpenSSL, the ObjC hooks will miss it, and hooking shifts to the Dart or
  the app's own wrapper classes named by recon.
- Anti debug or jailbreak detection is possible though unlikely on a consumer iOS build. Recon checks
  for `ptrace` and `sysctl` guards, and an early bypass can be added to the gadget config if needed.
- Free account churn. The build expires in 7 days and counts against the 3 app limit, so keep the
  Frida build as the primary install and keep the Sideloadly recipe to hand.
