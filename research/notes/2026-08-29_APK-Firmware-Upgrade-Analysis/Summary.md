# Notes: APK Firmware Upgrade Analysis

These notes correspond to the plan in
`research/plans/2026-08-29_APK-Firmware-Upgrade-Analysis/Problem-Statement.md`.

## Status

Goal 1 (understand the APK structure and choose an analysis approach) is complete. The chosen
approach was executed: `libapp.so` was reconstructed with blutter. Setup and reproduction steps are
in `Blutter-Setup.md`. Goal 2 (understand the firmware upgrade API) is in progress. A pivotal
finding is that the P20i firmware path is not in the Dart layer, so it must be reached through the
packed native code. See "Goal 2 Preliminary Findings".

Work then moved to dynamic analysis, trying to run the app on an emulator to unpack its dex or
capture its traffic. That is blocked by ijiami anti-tamper, detailed in
`Anti-Tamper-And-Dynamic-Analysis.md`. Route A, hiding the emulator and root with Magisk, Shamiko,
and property spoofing, was attempted in full and failed. The emulator detection still killed the
app. The Android emulator path is abandoned.

The next step is MITM capture on real hardware. Run the Soundcore app on a physical iPhone with the
P20i paired, tap the firmware update control, and intercept the HTTPS traffic through a proxy. The
firmware API should match the Android app, so this answers Goal 2 without defeating the packer.

## Files In This Note

- `Summary.md`: this file. Goal 1 answers and Goal 2 preliminary findings.
- `Blutter-Setup.md`: reproducible blutter build and the `libapp.so` reconstruction output.
- `Anti-Tamper-And-Dynamic-Analysis.md`: the emulator run attempts, the ijiami protection layers,
  and why static patching of the detection is not viable.
- `MITM-Analysis.md`: the iPhone proxy capture, the P20i product code and hosts, and the analysis
  of the leaked telemetry.
- `Prior-Work.md`: existing public reverse engineering of the Anker and eufy API and the Soundcore
  Bluetooth protocol, with the OTA endpoint and signing patterns it suggests.

## Goal 1: APK Structure

### Summary Answers

1. How is the APK structured? A split (App Bundle) install of the Soundcore Android app, version
   `5.0.21` (versionCode `423`), package `com.oceanwing.soundcore`. It is a Flutter release build
   whose Dart code is AOT compiled into `libapp.so`. The Java/Kotlin dex is packed by the ijiami
   (爱加密) app hardening product, so JADX only recovered the ijiami shell and bundled
   third-party libraries, not Soundcore's own Java classes.
2. Where does the main app code live? In `libapp.so` (Dart AOT snapshot, arm64 is 20.9 MB). The
   firmware upgrade user interface and logic strings are present there. Soundcore's Java code is
   not available in the decompilation because it is packed (see ijiami section).
3. Best approach for analysis? Reconstruct the Dart from `libapp.so` with a Flutter AOT tool
   (blutter is the recommendation) and drive Ghidra from its output. Use JADX and the manifest for
   the native Android surface. Details and rationale are in "Recommended Analysis Approach".

### Split APK Set

The corpus in `apk/` holds one installable base plus configuration and asset splits.

| File | Contents |
| --- | --- |
| `com.oceanwing.soundcore-423.apk` | Base module. `classes.dex`, `res/`, `assets/`, and arm64-v8a plus armeabi-v7a native libs. 9803 entries. |
| `com.oceanwing.soundcore-423-asset.apk` | Same entry set as the base (9803 entries). Treat as the base module. |
| `com.oceanwing.soundcore-423-lib_asset.apk` | Asset pack. Audio and animation assets plus `assets/resource.zip` (20 MB). No dex. |
| `com.oceanwing.soundcore-423-soundcoreso.apk` | Native lib pack. Extra `.so` files delivered under `assets/lib/<abi>/`, including x86 and x86_64 and on-demand libs (`libaitd_audio_algo.so`, `libsqlcipher.so`, `libpag.so`, filament, and others). No dex. |
| `com.oceanwing.soundcore-423-config.xxhdpi.apk` | Density resource split. `res/` and `resources.arsc`. No dex. |

The JADX decompilation lives in `apk/com.oceanwing.soundcore-423/` with `sources/` (Java) and
`resources/` (manifest, res, assets, and `lib/`).

### Flutter And Dart Versions

- Engine string in `libflutter.so`: Dart `3.4.4 (stable)`, built `2024-06-12`, target
  `android_arm64`. Dart SDK 3.4.4 ships with Flutter 3.22.x.
- Dart snapshot version hash (from `libapp.so`): `d20a1be77c3d3c41b2a5accaee1ce549`.
- Snapshot feature flags: `product`, `arm64`, `android`, `compressed-pointers`, `null-safety`,
  `dedup_instructions`, no dwarf stack traces, no asserts.
- `libapp.so` is a normal unpacked AArch64 ELF (magic `\x7fELF`, machine 183). It exports the
  standard Flutter snapshot symbols (`_kDartVmSnapshotData`, `_kDartVmSnapshotInstructions`,
  `_kDartIsolateSnapshotData`, `_kDartIsolateSnapshotInstructions`, `_kDartSnapshotBuildId`).
- The Dart symbols are not obfuscated. 2454 distinct readable `package:` library URIs are present,
  which means a reconstruction tool will recover real class and library names.

### ijiami Hardening

The Java layer is protected, which is why JADX shows almost no Soundcore code.

- The manifest `application android:name` is `s.h.e.l.l.S`. That class
  (`sources/s/h/e/l/l/S.java`) is the ijiami stub Application. It uses reflection, native loads,
  and CRC checks to decrypt and load the real dex at runtime.
- Encrypted payloads live in `resources/assets/`: `ijiami.dat` (29.9 MB), `ijiami.ajm` (8.6 MB),
  `IJMDal.Data` (0.8 MB), plus `af.bin`, `signed.bin`, and a `dexopt/` directory.
- ijiami native components ship as `libijmdetect-drisk.so` and `libijm-emulator.so` (root and
  emulator detection) and unpack helpers under `assets/ijm_lib/<abi>/`.
- Only one `classes.dex` exists and it is the shell. The real `com.oceanwing.soundcore.*` classes
  are absent from `sources/` (only `R.java` survives). The manifest still declares them, so the
  class names are visible even though the code is not.

### Native Android Surface

The manifest declares a per-product-model `MainActivity` for 72 distinct `A3xxx` model codes (for
example `A3133MainActivity`, `A3201MainActivity`, `SoundCoreMainActivity`). This shows the app has
a large native Android component in the packed dex in addition to the Flutter layer. The exact
`A3xxx` code for the P20i was not confirmed. The literal string `p20i` does not appear in
`libapp.so` or the Flutter assets, so the app refers to the product by model code, not marketing
name. Resolving the P20i code is a Goal 2 task (candidate approach: read the product code the
earbuds report over Bluetooth, see `_getBindingDeviceProductCode` below).

### Native Libraries Of Interest

Bundled in `resources/lib/arm64-v8a/` (also armeabi-v7a):

- `libapp.so`, `libflutter.so`: the Flutter app and engine.
- `libscsecurity.so`, `libcrypto-security.so`: Soundcore or Anker crypto helpers. Worth checking
  during Goal 2 for firmware signature or payload crypto.
- `libscnativelib.so`, `libhid_app.so`: HearID and LED light-effect helpers. JNI exports are
  `Java_com_anker_hearid_*` and `Java_com_anker_scnativelib_*`. These look audio and UI related,
  not firmware, so they are low priority for the OTA question.
- `libsqlcipher.so`: encrypted SQLite. Local storage, likely not OTA.
- Media stack: `libavcodec`, `libavformat`, `libffmpegkit`, `libpag`, `libjpeg`, `libturbojpeg`.

### Recommended Analysis Approach

Primary path for the firmware upgrade question:

1. Reconstruct the Dart AOT snapshot from `libapp.so` with blutter. Conditions are favorable
   because the snapshot is unobfuscated, uses standard exports, and the Dart version (3.4.4) is
   known so a matching Dart SDK and blutter build can be selected. blutter emits recovered class
   and method listings plus a Ghidra script and object annotations.
2. Load `libapp.so` into the project Ghidra with the blutter output so decompiled Dart functions
   carry real names. Use the MCP `ghidra` server for this.
3. Use `strings` on `libapp.so` for fast recon of endpoints, log lines, and Dart package names
   before and during the Ghidra work.

Supporting tools:

- JADX output stays useful for the manifest, the ijiami shell, the native activity list, and the
  bundled third-party libraries.
- For devices whose firmware logic lives in the packed Java dex rather than in Dart, unpacking
  ijiami is required. That needs a runtime dex dump from a rooted device or emulator, or a
  dedicated ijiami unpacker, because static extraction from `ijiami.dat` is not practical. The
  Goal 2 work below shows the P20i is one of these devices.

## Goal 2 Preliminary Findings

The `libapp.so` reconstruction was mined for the firmware upgrade path. The key result reshapes the
Goal 2 plan.

### App Is A flutter_boost Hybrid With One Dart Device Module

The app uses `flutter_boost`, so Flutter screens are embedded in the native Android app. The app's
own Dart code is `package:module_flutter/`. Its device specific code covers only one model,
`d3200`, under `module_flutter/d3200/`. All other product models, including the P20i, are driven by
the native Android layer that is packed by ijiami.

`d3200` is not the P20i. Object pool strings identify it as a WiFi connected device with cloud audio
sync and AI note taking (`D3200 WiFi`, `D3200CloudSyncManager`, `D3200AudioWaveManager`). The P20i
is a classic Bluetooth earbud, so its screens and its firmware flow are in native code, not in
`libapp.so`.

### d3200 Has A Full Dart OTA Implementation

The `d3200` module contains a complete firmware upgrade flow that is useful as a reference for
Anker's OTA architecture even though it is not the P20i path. Relevant files in the blutter output:

- `module_flutter/d3200/setting/manager/firmware_upgrade_manager.dart`, class
  `FirmwareUpgradeManager` with methods such as `needUpgrade`, `registerEventCallback`, and
  `_handleFirmwareUpgradeEvent`.
- `module_flutter/d3200/home/manager/d3200_ota_dialog_manager.dart`, class `D3200OtaDialogManager`.
- `module_flutter/d3200/setting/controller/d3200_setting_controller.dart`.

Related identifiers in the object pool: `deviceUpdateFirmware`, `firmwareUpdate`,
`firmwareVersion`, `d3200NeedUpdateFirmware`, `d3200OtaDialogStateChange`.

### Hosts Seen In The Dart Layer

Only three app hostnames appear in the object pool, and none is a firmware OTA API.

- `us.soundcore.com`: storefront and support pages.
- `speaker-oss.anker-in.com` and `d2htfo7ft368vg.cloudfront.net`: static media, guide GIFs, and
  disclaimer HTML, addressed by a `media/prod/<model>/...` path scheme.
- `ai.soundcore.com` (with `ai-qa` and `ai-ci` variants): backend for the d3200 AI note feature.

The firmware fetch API host for the P20i was not found in Dart, consistent with that path living in
the packed native layer. The `d3200` OTA manager references device events, not a direct download
URL, so even the d3200 metadata endpoint is likely provided by the native SDK or an API client that
was not located in this pass.

### Consequence For Goal 2

To answer the firmware fetch questions for the P20i, the Dart reconstruction is not enough. Options,
roughly in order of expected value:

1. Dynamic capture. Put the app through a firmware check for the P20i on the owned hardware and MITM
   the HTTPS traffic. This yields the real host, path, request, and response directly. Watch for
   certificate pinning.
2. Unpack the ijiami dex from a rooted device or emulator, then read the native OTA and API client
   in JADX.
3. Inspect the SoundCore native SDK shared libraries (for example `libscsecurity.so`) if the
   dynamic or dex work shows firmware crypto or transport is implemented there. This is the step
   most suited to Ghidra.

## Open Questions

1. Which model code identifies the P20i, and is it an `A3xxx` value or another scheme?
2. What is the firmware fetch host and path for the P20i, and what auth or signing does the request
   need?
3. Is the firmware package signed or encrypted, and is metadata split from the image?
4. Does the P20i OTA reuse the same Anker API contract visible in the d3200 Dart flow?
