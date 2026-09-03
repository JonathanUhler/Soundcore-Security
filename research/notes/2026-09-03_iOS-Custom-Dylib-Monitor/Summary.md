# Notes: iOS Custom Dylib Monitor

These notes correspond to the plan in
`research/plans/2026-09-03_iOS-Custom-Dylib-Monitor/Problem-Statement.md`. The
plan pivots the capture vehicle away from Frida to a passive custom dylib added
to the Soundcore bundle at re-sign time. This file is the index and the
feasibility record. The full end of session state, what was proven, what failed,
and the next direction, is in `Session-Status-And-Blockers.md`. Read that first.

## Status

- Feasibility, viable and proven on device. Reasoning below.
- Goal 1, passed. The passive dylib loads, the app boots, and the marker is
  recoverable, so there is no load time library whitelist.
- Goal 2, partly done and currently blocked. The signing scheme and the static
  credentials were recovered, and a host side signed client was written. A
  replayed firmware check returns `406 Access token expired`, and it is not yet
  resolved whether that is a missing `gtoken` or a wrong signature. The decided
  next step is offline reversing to nail the exact signature. See
  `Session-Status-And-Blockers.md`.

## Feasibility Assessment

The plan is feasible, and Goal 1 is the correct minimal experiment to isolate the
one open question. The assessment rests on facts already established in the two
prior iOS sessions.

Why Frida is out. The reinforcement SDK detects the gum agent and branches onto a
sabotage path that strips execute permission from its own trampoline pages in a
loop. On a sideloaded app with no JIT entitlement, AMFI refuses to execute
Frida allocated or re-armed pages, so reactive recovery cannot reach a boot. This
was proven across eight runs, see
`../2026-09-02_iOS-Anti-Tamper-Bypass/Bypass-And-Walkthrough.md`. The detection
fires purely from the agent being loaded, since a zero hook recon session still
triggered it.

Why a passive dylib is different. A code signed dylib added to the bundle at
re-sign time is loaded by dyld as an ordinary image carrying the app's own
signature. It has none of the footprint the SDK's real detectors catch, which the
detection surface in
`../2026-09-02_iOS-Anti-Tamper-Bypass/Pivot-To-Signing-Extraction.md` lists.

- The `_vm_region_64` memory scan looks for anonymous executable memory with no
  backing file, which is what catches jailed spawn gum. A file backed dylib is
  not that.
- The `_task_threads` and `_thread_info` thread scan looks for agent threads. A
  passive constructor spawns none.
- A passive dylib patches no code, so it does not trip the `HOOK_ATTACK` or code
  integrity checks, and the `_dladdr` based checks target code redirection, not
  loaded images.

The one residual risk. `APP_FIRM_LIBRARY_INJECTION` enumerates the dyld image
list, per `../2026-09-02_iOS-Anti-Tamper-Bypass/Kill-Switch-Analysis.md`, and a
dylib is a dyld image, so it can be seen. The question is whether being seen is
fatal. Two facts argue no.

- There is no evidence of a per image hash or signature baseline. The app
  already boots after Sideloadly re-signs the main binary and every framework
  with a free account cert, and it runs fine without Frida. Re-signing already
  changes the main binary and its signature, and the SDK tolerates it, so the
  `SIGNATURE_TAMPER`, `NON_APPSTORE_DOWNLOAD`, `MODIFY_CODE`, and
  `SOURCE_FILE_MODIFIED` categories are not hard failing on this device in the
  working baseline. Adding one more `LC_LOAD_DYLIB` is the same class of change,
  covered by the same re-sign.
- The runtime image count is about 1277 and varies by iOS version, and the
  binary loads 127 plus `@rpath` frameworks, so a hardcoded whitelist or count
  check would be too brittle to be likely. That leaves a name scan, which a
  benign dylib name evades, and there is no `DYLD_INSERT_LIBRARIES` involved
  because the load is a bundle `LC_LOAD_DYLIB`, not an env insert.

So the residual risk is real but narrow, and it is exactly what Goal 1 tests
cheaply. This is the single open question static analysis cannot close, because
the image list detector is dynamically resolved and obfuscated.

## Goal 1 Artifact

`scripts/ios-dylib/scprobe.c` is the probe. Its constructor announces that it ran
and does nothing else, which keeps it passive so the test isolates the load itself
rather than any behavior after load.

- Primary proof channel, `os_log` to a `com.soundcore.research` subsystem and to
  `OS_LOG_DEFAULT`, with the ASCII marker `SCPROBE_HELLO_WORLD`. This reaches the
  unified log and is readable over USB with `pymobiledevice3 syslog live`, so the
  read needs no debugger, jailbreak, or Frida. That matters, a debugger attach is
  what put the app into the relaxed state Frida needed, and this test must be a
  plain launch to be meaningful.
- Secondary channel, a marker file in the app sandbox `TMPDIR`, pullable with
  house_arrest only if the app exposes file sharing. It is a fallback, not the
  primary proof.
- It links only libSystem, resolves its own image path with `dladdr` to confirm
  a file backed load, and targets arm64 to match the app and all its images.
  arm64e would be the same slice mismatch that broke the Frida gadget.

`scripts/ios-dylib/build.sh` cross compiles it on the operator Mac, which has
only the Command Line Tools and no full Xcode. The only prerequisite is an
iPhoneOS SDK, found automatically with Xcode or supplied through `SDK=` from a
Theos install. The dylib is left unsigned because Sideloadly signs the injected
dylib with the app's re-sign identity.

## Interpreting The Goal 1 Run

- App boots and the marker appears. There is no load time library whitelist, the
  passive dylib path is viable, and the session proceeds to Goal 2.
- App crashes at launch. The SDK reacted to the added image. Pull a crash report,
  read the terminating frame, and if it is the image list vector the next step is
  a benign rename or a static neutralization of the detector, anchored at the
  `didFinishLaunching` Swift body `FUN_100d57350`.
- App boots but no marker. The dylib did not load or the log did not surface.
  Confirm the `LC_LOAD_DYLIB` with `otool -l`, confirm the arm64 slice, and try
  the tmp file fallback.

## What Goal 2 Will Need

If Goal 1 passes, the reader dylib resolves the main image base, computes the
network config singleton at Ghidra `0x105446558`, which is `main base + 0x5446558`
at runtime, polls until the credentials populate, then reads `clientId`,
`clientSecret`, and the bootstrap secret at `*(config + 0x10) + 0x48`, set by
`initConfig`. Addresses are from
`../2026-09-02_iOS-Anti-Tamper-Bypass/Pivot-To-Signing-Extraction.md`. Those three
values are the only missing input to the already recovered signing scheme, so with
them `scripts/probe_firmware_endpoint.py` can be extended from an unsigned probe to
a signed call for the P20i firmware URL. The alternative approach, driving the API
from inside the dylib and exfiltrating the firmware image directly, is the Goal 2
decision recorded in the plan.

## Files In This Note

- `Summary.md`, this file. The index and the feasibility and Goal 1 record.
- `Session-Status-And-Blockers.md`, the end of session state, the blocker, the
  decided next direction, and the Ghidra reference map. The resume point.
- `Goal2-Credential-Reader.md`, the passive reader design and the config read
  chain.
- `Signing-Scheme-iOS-Recovery.md`, the full signing scheme and the credentials,
  recovered from the iOS binary.
- `Firmware-URL-Harvest-Pivot.md`, the `406` finding and the pivot to letting the
  app make the call.

The artifacts live under `scripts/ios-dylib/`, with `README.md` as the operator
command sheet, `build.sh` the cross compiler, and the dylibs `scprobe.c` (Goal 1
probe), `screader.c` (config reader), `scharvest.c` (URL harvester and version
forcer), and `scheaders.c` (header value capture). The host side signed client is
`scripts/sign_firmware_request.py`.
