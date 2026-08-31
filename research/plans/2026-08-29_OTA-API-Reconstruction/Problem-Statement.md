# Problem Statement: OTA API Reconstruction

This plan continues the APK Firmware Upgrade Analysis session. That work is written up in
`research/notes/2026-08-29_APK-Firmware-Upgrade-Analysis/`. Read `Summary.md` there first, then the
other notes it indexes.

The prior session established that the P20i firmware upgrade logic lives in the ijiami packed native
code. It is not reachable statically, not reachable by running the Android app on an emulator, and
the firmware status API is served from a certificate pinned host. A partial MITM capture on a real
iPhone still produced strong leads. The goal now is to reconstruct and drive the firmware API
directly, then obtain and analyze the P20i firmware image.

## Background

Key facts carried over from the prior session. See the notes for detail.

- The P20i product code is `A3949`. Both earbuds run firmware `14.43`.
- The firmware status API host is `speaker.eufylife.com`, behind the APISIX gateway, certificate
  pinned inside the app. The telemetry host `log.eufylife.com/push_log_hdfs` is not pinned and
  leaked device data. See `MITM-Analysis.md`.
- The OTA endpoint path exists only in the packed native dex. It is not in `libapp.so`, the other
  native libraries, the Flutter assets, or any observable traffic. Static extraction and
  unauthenticated gateway probing both failed. The APISIX gateway returns a uniform 404 for real and
  fake routes unless the request is properly signed.
- The request signing artifacts `gToken`, `signKey`, `app_key`, `token`, `timestamp`, `nonce`, and
  `sign` are present in the blutter reconstruction of `libapp.so`. Prior work says `gToken` is an
  MD5 of the encrypted `user_id`. The firmware check runs with an empty `user_id`, so it is app
  signed, not user bound.
- The serial number is derivable from the Bluetooth MAC. See `MITM-Analysis.md`.
- Public reverse engineering suggests OTA patterns such as `/v1/app/ota/get_app_version` and
  `device/firmware/{id}/{component}/update/{version}`, plus a `/speaker/` business group prefix. See
  `Prior-Work.md`.
- The blutter output lives in the session scratchpad and may be cleared. Regenerate it with the
  steps in `Blutter-Setup.md`.

## Goal 1: Reconstruct The Request Signing

This is the prerequisite for everything else. Without a valid signature the gateway will not route
requests, so the endpoint cannot be found or called.

Deliverables.

1. In the blutter reconstruction, find where `token`, `gToken`, `sign`, `timestamp`, and `nonce` are
   built. Identify the algorithm, MD5 or HMAC, the exact inputs and their order, and any hardcoded
   `app_key`, secret, or salt.
2. Reproduce the signing in a small script. Verify it against the captured telemetry request, which
   used the header `token` value `361ec02987361d207d05392b9f0d89e4` at `timestamp` `1788043091` for
   the body recorded in the `flows` file.
3. Document the app level signing used when no user is logged in.

## Goal 2: Recover The OTA Endpoint

With valid signing the APISIX 404 oracle works again. A real route reaches the backend and returns a
JSON response, while a wrong path returns the generic 404.

Deliverables.

1. Assemble a correctly signed request and enumerate a small, targeted set of OTA paths under the
   known conventions, especially the `/speaker/` prefix, the `/app/v1/` prefix, and the prior work
   patterns. Keep the probing minimal and respectful. This is a third party production gateway.
2. Identify the firmware status endpoint, its HTTP method, and its request and response schema.

## Goal 3: Fetch And Download The Firmware

Deliverables.

1. Query the endpoint with product code `A3949` and a spoofed low `firmware_version` such as `1.00`,
   so the server returns an available update even though the test device is already current.
2. Capture the response, including the latest version, the download URL, and any metadata such as
   size or hash.
3. Download the P20i firmware binary. It is likely served from an unpinned object storage or CDN
   host, so a plain request should work.

## Goal 4: Assess Firmware Protections

Deliverables.

1. Determine whether the firmware package is signed, encrypted, or split into separate header and
   body blobs. Prior work on an adjacent Anker product found no signature verification and a fully
   encrypted binary. Confirm or refute this for the P20i.
2. Run entropy analysis on the downloaded binary to distinguish encryption from compression.
3. Record the format findings to feed the next stage, which is understanding the firmware layout and
   the Bluetooth OTA transfer to the earbuds.

## Constraints And Fallbacks

- No jailbroken iPhone or patched IPA is available, so the pinned traffic cannot be observed
  directly. The Android app will not run because of ijiami emulator and root detection.
- If the signing cannot be reconstructed from the Dart layer, it may live in native code. In that
  case reconsider the packed dex unpacking route, or pivot to a Bluetooth side analysis of the OTA
  transfer.
- The project owns P20i hardware for Bluetooth dynamic testing. The device info frame is partly
  decoded in `MITM-Analysis.md`, and the CoreSound project documents the Soundcore RFCOMM protocol.
