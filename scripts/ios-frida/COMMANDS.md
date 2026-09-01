# Frida Injection Command Sheet (iOS, Non Jailbroken)

Operational steps to inject the Frida Gadget into the stable Soundcore IPA with Sideloadly, install
it on the stock iPhone, and connect from the Mac. This backs the plan in
`research/plans/2026-09-01_iOS-Frida-Injection/Problem-Statement.md`.

All commands run on the Mac. The iPhone stays connected over USB with the computer trusted.

## 1. Install Frida Tools And Note The Version

```bash
python3 -m pip install --upgrade frida-tools
frida --version          # record this, e.g. 17.2.4
```

The gadget dylib version MUST match this exactly. Version mismatch is the most common failure.

## 2. Fetch The Matching Gadget Dylib

From the Frida releases page, download the iOS universal gadget for the version above.

```bash
VER=$(frida --version)
curl -L -o FridaGadget.dylib.gz \
  "https://github.com/frida/frida/releases/download/${VER}/frida-gadget-${VER}-ios-universal.dylib.gz"
gunzip FridaGadget.dylib.gz          # yields FridaGadget.dylib
```

The universal dylib contains arm64. Keep the file named `FridaGadget.dylib`.

## 3. Optional Gadget Config

Place a `FridaGadget.config` next to the dylib to control startup. Listen mode with `on_load` set to
`wait` pauses the app at launch until you attach, which is what we want so the hooks land before the
early key exchange runs.

```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_load": "wait"
  }
}
```

Switch `on_load` to `resume` later if you would rather the app start normally and attach on demand.
Sideloadly injects any file dropped alongside the dylib, so add the config to the same injection box.

## 4. Inject And Re-sign With Sideloadly

Reuse the exact settings from the working non Frida build.

1. Load `ipa/com.oceanwing.SoundCore_5.0.02_und3fined.ipa`.
2. Enter the Apple ID. Use the app specific password for the two factor prompt.
3. Advanced options, keep Remove app extensions, auto bundle ID, same as before.
4. Drag `FridaGadget.dylib` (and `FridaGadget.config` if used) into the dylib injection box.
5. Start. Sideloadly copies the dylib into `SoundCore.app/Frameworks/`, adds the load command, signs
   the dylib with the same cert, and installs.
6. Trust the developer certificate on the device if prompted.

## 5. Launch And Confirm Attachment

Launch the app on the phone. With `on_load` set to `wait` it will hang on a black or launch screen
until a client attaches. Then from the Mac:

```bash
frida-ps -U                     # expect a process named "Gadget"
frida -U Gadget -l scripts/ios-frida/recon.js
```

`frida -U` uses the usbmux USB transport, so no `iproxy` step is needed. If the app was paused by
`wait`, the Frida session resumes it once connected.

## 6. Run The Hooks

Load recon first, read its output, then load the capture hooks. Frida can load several scripts at
once.

```bash
# recon, to confirm the gadget and name the crypto classes and exports
frida -U Gadget -l scripts/ios-frida/recon.js

# live capture, request and response plus the crypto primitives
frida -U Gadget \
  -l scripts/ios-frida/network-hooks.js \
  -l scripts/ios-frida/crypto-hooks.js
```

Then drive the app by hand, log in, and trigger a check for update, while watching the console.

## Troubleshooting

- No `Gadget` in `frida-ps -U`. The dylib did not load or is unsigned. Re-check the Sideloadly
  injection and that the dylib version matches `frida --version`.
- Immediate crash on launch. Usually a signature or library validation problem. Confirm the gadget
  was signed by the same cert as the app, which Sideloadly should handle automatically.
- App runs but hooks see no traffic. The networking may be routed through Dart rather than
  `NSURLSession`. Fall back to the classes that `recon.js` reports, or to the crypto primitives, or
  run mitmproxy in parallel as a cross check.
- Build stopped working after a week. Free account signing expired. Re-run Sideloadly to refresh.
