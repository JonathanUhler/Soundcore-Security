# Notes: Anti-Tamper And Dynamic Analysis

These notes continue `Summary.md`. They cover the attempt to recover the packed Java code for the
P20i firmware flow by running the app on an emulator, and the ijiami anti-tamper that blocked it.

## Goal Of This Phase

The P20i firmware logic lives in the native Android dex, which ijiami packs (see `Summary.md`). The
plan was to run the app on an Android emulator so ijiami decrypts its dex, then either dump the dex
or capture the firmware API over the network. Both need the app to actually run.

## Emulator And Install Constraints

- ABI. The app ships `libapp.so` and `libflutter.so` for `arm64-v8a` and `armeabi-v7a` only. There
  is no x86 build. The emulator must expose `arm64-v8a` in `ro.product.cpu.abilist`, which means a
  native arm image or an x86_64 image with ARM translation.
- Page size. API 35 and newer system images use 16 KB memory pages. Native libraries built with 4 KB
  max page size fail to load there, which breaks some tools even though the app itself runs.
- Split install. The corpus has two byte identical base APKs (`-423.apk` and `-423-asset.apk`, same
  md5 `e02f1bf37cb9aa6a87e202d85af3b5af`) plus three real splits (`lib_asset`, `soundcoreso`,
  `config.xxhdpi`). Running `adb install-multiple *.apk` fails with "Split null was defined multiple
  times" because both bases carry `classes.dex`. Fix is to install one base plus the three splits.

The launcher activity is `com.oceanwing.soundcore/.activity.WelcomeActivity`.

## Protection Layers

| Component | Delivery | Role |
| --- | --- | --- |
| `s.h.e.l.l.S` | base `classes.dex` | ijiami stub Application. Bootstraps the packer. |
| `libexec.so`, `libexecmain.so` | decrypted at runtime into `/data/data/<pkg>/files/` | Core unpacker plus anti-debug and anti-Frida. Runs very early. |
| `libijmdetect-drisk.so` | APK `lib/` (obfuscated) | Dynamic risk checks. Anti-root and anti-Xposed and anti-debug. |
| `libijm-emulator.so` | APK `lib/` (packed) | Emulator detection. Runs late, after app init. |

## Crash Analysis Without Frida

A clean launch (pid 16234) got through full startup, including Firebase, GMS, ExoPlayer, MMKV, and
the app's own `SoApi` native loader. It then loaded `libijm-emulator.so`, and 6 ms later the process
sent itself `SIGKILL`.

```
47.071  Load .../lib/arm64-v8a/libijm-emulator.so ... : ok
47.077  Process : Sending signal. PID: 16234 SIG: 9
47.095  Zygote  : Process 16234 exited due to signal 9 (Killed)
```

The `Process : Sending signal` line is emitted by `android.os.Process`, so in the no Frida case the
kill runs through the Java framework after the emulator check. The decrypted dex was already loaded
by this point (logged as an `Anonymous-DexFile`, that is an `InMemoryDexClassLoader`).

## Crash Analysis With Frida

Frida attached and Java hooks were live, confirmed by a canary hook on `android.os.Process.myPid`
firing. Hooks on `Process.killProcess` and `Process.sendSignal` did not stop the crash. In the Frida
run (pid 16631) the process died much earlier, right after executing `files/libexec.so`, and with no
`Process : Sending signal` line. That means the kill came from native code (a direct `kill` from the
guest side under translation), not the Java framework path, so a Java hook cannot catch it.

Conclusions. Frida trips ijiami's anti-Frida layer in `libexec.so`, which kills earlier than the
emulator check and by a native path. Under the emulator's ARM translation, Frida native hooks into
the guest side libraries are also unreliable. Frida is the wrong tool for this target.

## Dumper Tools

- BlackDex. On an API 36 16 KB image its bundled native library is not 16 KB aligned and fails to
  load. On an API 34 image it cannot extract `classes.dex` for any app, so its dump path is broken
  on Android 14 ART. Not usable as is.
- LSPosed custom module. A small Xposed module was written to dump the decrypted dex by hooking
  every `InMemoryDexClassLoader` constructor, since ijiami loads its dex that way. It is in
  `hooks/lsposed-dexdump/`. It was not run yet. The risk is that `libijmdetect-drisk.so` detects
  Xposed and root before the hook fires.

## Static Analysis Of The Detection Libraries

Both detection libraries are obfuscated. `libijm-emulator.so` (166 KB) has no useful strings and
hides its imports.

Ghidra findings for `libijm-emulator.so` (image base `0x00100000`):

- Zero dynamic symbols and zero relocations. It resolves libc functions at runtime through `dlsym`,
  and the only leaked string is `__system_property_get`, which points to build property checks.
- The `INIT_ARRAY` at `0x138948` holds seven constructor pointers whose targets decode as garbage,
  not code.
- `DT_INIT` at `0x121be8` is a decompressor. It runs bit reader helpers into an output buffer, then
  issues `DC_CVAU` and `IC_IVAU` cache maintenance over that buffer, which is what code does when it
  writes instructions and then executes them.
- Sampling the payload region disassembles to incoherent instructions at misaligned offsets.

The library is therefore packed. The real detection code does not exist in the file. `DT_INIT`
inflates it into memory at load time. Static find and patch of the emulator check is not viable
without first reversing the decompressor and reproducing it offline, and a patched APK library would
also have to defeat ijiami signature and integrity checks.

## Conclusion On The Android Emulator Path

Every dynamic path on the emulator is gated by anti-Frida, anti-Xposed, or anti-emulator logic.
Every static path is gated by packing. The single linchpin was making the app run on the emulator,
and that was attempted through route A below and did not work.

### Route A Attempt And Outcome

The goal of route A was to hide the emulator and root so the app would launch, then capture the
firmware API over HTTPS. The full stack was set up.

- AVD on API 34 `google_apis` x86_64 with ARM translation, the oldest translated image available.
- Rooted with Magisk 30.6 through rootAVD, which patches the AVD ramdisk. Matching the app version
  to the ramdisk daemon version required a cold boot with `emulator -avd <name> -no-snapshot-load`,
  since a snapshot resume ignores ramdisk changes.
- Zygisk on, Shamiko installed, `com.oceanwing.soundcore` in the DenyList with Enforce DenyList off,
  for root hiding.
- MagiskHide Props Config set a real device fingerprint, plus a `post-fs-data.d` resetprop script
  scrubbed the `ro.kernel.qemu` and `qemu.*` property tells.

Result. The emulator detection still fired and killed the app. Root hiding and property or
fingerprint spoofing are not enough against `libijm-emulator.so`. It almost certainly also probes
QEMU device nodes such as `/dev/qemu_pipe` or the ARM translation layer, which property spoofing
cannot mask. These commercial packers are built to defeat exactly this Magisk and Shamiko setup.

Do not repeat the Android emulator hiding work. It is a dead end without either reversing the packed
`DT_INIT` unpacker (route B, high effort) or moving to real hardware.

### New Direction: MITM On Real Hardware

The chosen pivot skips the emulator and captures the firmware API from the real app on a physical
device, which removes emulator detection as a factor. The next session runs the Soundcore app on a
physical iPhone, taps the firmware update control for the paired P20i, and intercepts the HTTPS
traffic. The backend firmware API is expected to be the same across the iOS and Android apps, so an
iOS capture answers the Goal 2 questions about host, path, auth, and payload.

Setup notes for the iOS MITM session.

- Proxy. Run mitmproxy or Burp on a computer on the same network. Set the iPhone Wi-Fi HTTP proxy to
  point at it.
- Trust. Install the proxy CA on the iPhone through the profile flow, then enable full trust under
  Settings, General, About, Certificate Trust Settings.
- Pinning. The app may pin its certificate. If the OTA host shows TLS handshake failures in the
  proxy, pinning is active and needs a jailbroken device with an SSL bypass or a Frida hook. Try the
  unpinned capture first.
- Device. The P20i must be paired to the iPhone so the firmware check reports the real product code.
- Capture targets. Filter for hosts under Anker or Soundcore domains and paths containing `ota`,
  `firmware`, `fota`, `upgrade`, or `version`. Record the request host, path, headers, and any auth
  token, plus the response body with version metadata and download URLs.

## Tooling Created

- `hooks/anti_kill.js`. Frida script that blocks the Java kill path. Superseded, kept for reference.
- `hooks/lsposed-dexdump/`. LSPosed module that dumps the in memory dex. Held in reserve.

## Open Questions Carried Forward

1. Which model code identifies the P20i.
2. The firmware fetch host, path, and auth for the P20i.
3. Whether the firmware package is signed or encrypted, and whether metadata is a separate blob.
