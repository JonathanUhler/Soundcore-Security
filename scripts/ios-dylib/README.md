# Custom Dylib Monitor, Operational Sheet

Operator steps for the iOS Custom Dylib Monitor plan. The reasoning and the
feasibility assessment are in
`research/notes/2026-09-03_iOS-Custom-Dylib-Monitor/Summary.md`. This file is the
command sheet.

The idea is a passive, file backed, app signed dylib added to the Soundcore
bundle at re-sign time, instead of a Frida agent. Frida is dead on this device
because the reinforcement SDK detects the gum agent and sabotages the boot, and a
non JIT process cannot recover executable memory. A normal dyld image with the
app's own signature has none of that footprint. See the research note.

## Goal 1 Artifact

`scprobe.c` is the Goal 1 probe. Its constructor logs a `SCPROBE_HELLO_WORLD`
marker to the unified log and drops the same marker in the app sandbox tmp dir.
It links only libSystem and patches no code, so it is passive. Goal 1 passed on
device, so the passive reader path is open.

## Goal 2 Artifact

`screader.c` is the credential reader. It polls the network config singleton the
app's own signer reads, then dumps its string fields to the unified log under the
`SCREAD` marker, so the host can reproduce a signed firmware check. It reads only
through `mach_vm_read_overwrite`, so a bad pointer cannot crash the app, and it
hooks nothing. Build it with `SRC=screader.c`, inject and verify the same way,
and grep the log for `SCREAD`. See
`research/notes/2026-09-03_iOS-Custom-Dylib-Monitor/Goal2-Credential-Reader.md`.

```bash
SRC=screader.c scripts/ios-dylib/build.sh
pymobiledevice3 syslog live | grep SCREAD
```

## Build

The build host is the same Mac used for Sideloadly, an Intel Mac with only the
Command Line Tools. `build.sh` cross compiles an arm64 dylib.

```bash
scripts/ios-dylib/build.sh
```

The one prerequisite is an iPhoneOS SDK. With full Xcode it is found
automatically. Without Xcode, pass a standalone SDK, for example from a Theos
install.

```bash
SDK=$THEOS/sdks/iPhoneOS16.5.sdk scripts/ios-dylib/build.sh
```

The output `scprobe.dylib` must be arm64, not arm64e, to match the app and its
images. `build.sh` prints `file scprobe.dylib` so this can be confirmed. Leave it
unsigned. Sideloadly signs it during the re-sign.

Build note. The iOS SDK gates `<mach/mach_vm.h>` behind
`#error "mach_vm.h unsupported."`, so a source that includes it fails to compile.
The function is still in libSystem and works on iOS for our own task, so the fix
is to declare the prototype directly and not include the gated header, which is
what `screader.c` does.

## Inject And Install

1. Open Sideloadly and load the unmodified IPA,
   `ipa/com.oceanwing.SoundCore_5.0.02_und3fined.ipa`, the same known good build
   from `scripts/ios-frida/COMMANDS.md` section 2.
2. In the dylib inject box, add `scprobe.dylib`. This is the box that was left
   empty for the Frida flow. Sideloadly copies the dylib into the bundle, adds an
   `LC_LOAD_DYLIB`, and signs the dylib with the re-sign identity.
3. Keep the same Remove app extensions and auto bundle ID settings as the known
   good build.
4. Install to the device. No developer image, no tunnel, no Frida gadget. This is
   a plain launch, which is the point.

## Verify

Launch the app normally by tapping it. Stream the device log over USB and grep
for the marker.

```bash
pymobiledevice3 syslog live | grep SCPROBE_HELLO_WORLD
```

`idevicesyslog | grep SCPROBE_HELLO_WORLD` works too if libimobiledevice is
installed instead.

Record the outcome against the three cases.

- App boots and the marker appears. Goal 1 passes. No load time library
  whitelist, and the passive dylib path is viable. Proceed to Goal 2.
- App crashes or force closes at launch. The SDK reacted to the added image.
  Pull a fresh crash report and read the terminating frame, then see the note's
  discussion of the image list vector.
- App boots but no marker appears. The dylib did not load, or the log did not
  surface. Confirm the `LC_LOAD_DYLIB` is present with `otool -l` on the
  installed main binary, check the arm64 slice, and try the tmp file fallback.

## Recover The Fallback Marker File

If the log channel is unclear, the constructor also writes
`$TMPDIR/SCPROBE_HELLO_WORLD.txt` inside the app sandbox. It is pullable with
house_arrest only if the app exposes file sharing, so treat it as a secondary
check, not the primary proof.

```bash
pymobiledevice3 apps afc --bundle-id <installed bundle id> ls /tmp
```
