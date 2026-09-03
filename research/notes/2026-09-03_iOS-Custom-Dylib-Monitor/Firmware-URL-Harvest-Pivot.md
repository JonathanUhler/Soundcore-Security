# The Access Token Gate And The Harvest Pivot

The signed replay in `Signing-Scheme-iOS-Recovery.md` was built and run. It returned
`406 Access token expired`, the same error the unsigned probe returns. That result reframed the
endpoint and moved the plan from replaying the request to harvesting the app's own result.

## The Endpoint Has Two Gates

The firmware update endpoint checks an access token and the HMAC signature independently. The signed
and unsigned requests returning the identical `406 Access token expired` means the token gate is
evaluated first and rejects before the signature is considered. So the recovered signature may well
be correct, but it cannot be confirmed until a token is present, and the missing input is a token,
not the signature.

The token is `gtoken`, the app level token, or `Authorization`, the user bearer token, both named in
the header set in `../2026-08-30_App-Dex-Analysis/Capture-Resolution-And-OTA-API.md`. "Expired"
implies a server issued lifetime, so it is a rotating credential, not a static literal like the
clientId and clientSecret. The client `scripts/sign_firmware_request.py` was extended with `--gtoken`
and `--authorization` for the case where a live token is captured, but the plan pivoted instead.

## The Pivot, Let The App Make The Call

Rather than capture or reproduce the rotating token, let the app make the firmware check itself. It
holds a valid token and signs correctly, so its request passes both gates. The dylib does two memory
level things and hooks nothing.

- Version forcing. The earbuds are already on the latest firmware, so a normal check returns no
  update and no URL. The dylib scans the writable heap for the current firmware version string and
  overwrites it in place with a lower value of the same length, a single `mach_vm_write` to a heap
  string. The app then sends a well formed, properly signed request with an old version, and the
  server returns a download URL.
- URL harvest. The dylib scans the writable heap for http URLs and logs the ones that look like a
  firmware package. The check response, parsed into a heap string, is where `lastPackage.url` lands.

This keeps the same passive footprint that Goal 1 proved safe, reads through `mach_vm_read_overwrite`,
and adds only one data write. It patches no code, so it stays clear of the hook and injection
detection. The artifact is `scripts/ios-dylib/scharvest.c`, marker `SCHARV`, documented in
`scripts/ios-dylib/README.md`.

## Operator Flow And The Safety Note

The operator sets the current version at the top of `scharvest.c`, builds, injects, and drives the
app to the firmware screen to tap check for update, then reads the `FWLIKELY` URL from the log and
downloads the firmware from the unpinned CDN outside the app. The one hazard is that a forced low
version could push a downgrade if download or install is tapped, so only the check for update is run.
The URL is in that response, the download never has to happen inside the app.

## If The Harvest Comes Up Empty

- No `FWLIKELY` line but the app checked. The URL may not carry a firmware marker. Re-read the plain
  `url` lines in the log for anything on a storage or CDN host.
- No version write logged. The displayed version and the sent version differ in format. Read the
  `SCHARV` log for the version strings present in memory and match the sent form, or find the device
  firmware model field in Ghidra and target it directly.
- Still `406` behavior, meaning the app itself cannot check. The app needs a valid session first, so
  the operator signs in or otherwise gets the app to a state where its own firmware check succeeds,
  then re-runs the harvest.
