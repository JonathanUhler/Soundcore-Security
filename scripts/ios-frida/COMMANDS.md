# Frida Instrumentation Command Sheet (iOS 26, Non Jailbroken)

Operational steps that actually worked to instrument the Soundcore app on a stock iPhone running
iOS 26.5.1. The embedded Frida Gadget approach is a dead end on iOS 26, see section 0. The working
method is jailed spawn injection. Frida launches the app under `debugserver` and injects its own
agent, which is a different path from adding a gadget to the bundle.

Background and the full diagnosis are in
`research/notes/2026-09-01_iOS-Frida-Injection/Working-Injection-Flow.md`. All commands run on the
Mac with the iPhone connected over USB and trusted. The test host was an Intel Mac with no Xcode.

## 0. Why Not The Embedded Gadget

The Frida Gadget added to `Frameworks/` crashes at launch on iOS 26 before any app code runs. The
process dies with `EXC_BREAKPOINT`, `BRK #0x539`, inside the gadget's own dyld initializer. This is
Frida issue 3770 and it is unresolved. Two things were ruled out along the way, the arm64e versus
arm64 slice mismatch, which was real and fixed, and the app anti tamper SDK, which never got the
chance to run. See the research note for the crash log analysis.

The jailed spawn path below avoids the crash because Frida attaches `debugserver` first, which puts
the process into a relaxed code signing state that is sticky, and only then loads the agent. The
same gum code that trapped during a normal launch runs fine after code signing is relaxed.

Keep the embedded recipe only as a fallback for an older iOS 13 to 16 device, where the gadget bug
does not apply. The `FridaGadget-Info.plist` template in this directory supports that fallback.

## 1. Install Tools And Confirm Versions

```bash
python3 -m pip install --upgrade frida-tools pymobiledevice3
frida --version          # record this, e.g. 17.17.0
```

`pymobiledevice3` mounts the developer image and creates the iOS 17+ tunnel without Xcode. The
gadget placed in the cache in section 4 MUST match `frida --version` exactly.

## 2. Sideload The Unmodified IPA

Load `ipa/com.oceanwing.SoundCore_5.0.02_und3fined.ipa` in Sideloadly with an empty dylib and
framework injection box. No gadget, no `FridaGadget.framework`. The free account re-sign adds the
`get-task-allow` entitlement, which is the only thing needed here, because it makes the app
debuggable. Keep the same Remove app extensions and auto bundle ID settings as the known good build.

Sideloadly's auto bundle ID rewrites the identifier to include the team ID. The installed bundle ID
was `com.oceanwing.SoundCore.G8AW4BQ7RV`. Confirm yours in section 6 with `frida-ps -Uai`.

## 3. Enable Developer Mode

On the phone, Settings, Privacy and Security, Developer Mode, turn on, reboot, and confirm after the
reboot. This is required on iOS 16 and newer before a debugger can attach.

## 4. Place The Cache Gadget

Jailed injection uses Frida's own gadget from a fixed cache path, not a gadget in the app bundle.
The error `need Gadget to attach on jailed iOS` means this file is missing.

```bash
VER=$(frida --version)
mkdir -p ~/.cache/frida
curl -L -o /tmp/g.dylib.gz \
  "https://github.com/frida/frida/releases/download/${VER}/frida-gadget-${VER}-ios-universal.dylib.gz"
gunzip -c /tmp/g.dylib.gz > ~/.cache/frida/gadget-ios.dylib
```

The universal dylib is fine. Frida selects the arm64 slice for this arm64 app.

## 5. Mount The Developer Disk Image

Spawning needs `debugserver`, which lives in the developer image. On iOS 17+ the image is a
personalized bundle mounted over the tunnel, so the old `ideviceimagemounter` does not apply. Start
the tunnel daemon in one terminal and leave it running.

```bash
sudo python3 -m pymobiledevice3 remote tunneld
```

In a second terminal, mount the image and verify.

```bash
python3 -m pymobiledevice3 mounter auto-mount
python3 -m pymobiledevice3 mounter list
```

`auto-mount` downloads the correct image itself, so Xcode is not required. The mount does not
survive a reboot, so repeat section 5 after every reboot.

## 6. Spawn And Instrument

The relaxed code signing trick only holds if Frida launches the app, so spawn it, do not attach to a
copy that is already running. Kill the running app on the phone first.

```bash
frida-ps -Uai            # confirm the device and the exact bundle ID
frida -U -f com.oceanwing.SoundCore.G8AW4BQ7RV -l scripts/ios-frida/recon.js
```

Spawn pauses the app at its entry point before its own code runs, then waits for `%resume`. That is
the window to install an anti tamper bypass before the app's own detection can run.

## 7. Run The Hooks

Load recon first, read its output, then load the capture hooks.

```bash
frida -U -f com.oceanwing.SoundCore.G8AW4BQ7RV \
  -l scripts/ios-frida/network-hooks.js \
  -l scripts/ios-frida/crypto-hooks.js
```

Then drive the app by hand, log in, and trigger a check for update, while watching the console.

## Troubleshooting

- `Failed to spawn: EXC_BREAKPOINT / BRK #0x539` from an embedded gadget. The iOS 26 gadget bug.
  Switch to the jailed spawn flow above. Do not embed the gadget on iOS 26.
- Embedded gadget loads as arm64e in an arm64 process. Wrong slice. Thin it with
  `lipo FridaGadget.dylib -thin arm64`. This still leaves the iOS 26 bug, so prefer jailed spawn.
- `Failed to spawn: requires an iOS Developer Disk Image to be mounted`. Do section 5.
- `Failed to attach: need Gadget to attach on jailed iOS`. Cache gadget missing, see section 4.
- Black screen for about 20 seconds then a crash with code `0x8badf00d`. The launch watchdog killed
  a paused app. Attach and resume faster, or let the spawn resume on its own.
- App runs but hooks see no traffic. Networking may be routed through Dart, not `NSURLSession`. Fall
  back to the classes recon reports, or to the crypto primitives, or run mitmproxy in parallel.
