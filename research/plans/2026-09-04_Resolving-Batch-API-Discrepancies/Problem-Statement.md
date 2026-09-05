# Problem Statement: Resolving Batch API Discrepancies

This session is a direct continuation of `2026-09-04_OTA-Batch-Request-Capture`, which should be
read in full to gather necessary context of what was found. In short:

- Using the `scbody` dynamic library, basic rewrites of JSON packets can be made (e.g. the device
  version number)
- Using the signing and encryption from the app with modified version numbers, the API always
  returns success, but claims that no update is available
- Forums online do talk about upgrading P20i firmware, so the most likely explanation is that the
  backend is pinning the version number against something rather than just trusting what the client
  request provides

Independent of the prior research session, the following things were added to `scbody.m`:

- Rewriting the device serial number
- Rewriting the device MAC address (which is used in the serial number)

However no combination of those rewrites changed the behavior of the API. That means the server is
not pinning the version check on those fields alone, if at all.

The goal of this research session is to resolve some discrepancies noticed in the `scbody` log files
that may reveal a path to a successful API call.

## Log Files

Logs from running `scbody` during the first launch (right after install) of a few different
iterations of the library are available here:

- `scbody_firstlaunch.log`: Version number and serial number were rewritten
- `scbody_firstlaunch_2.log`: Version number and serial number were rewritten
- `scbody_firstlaunch_3.log`: Version number, serial number, and MAC address were rewritten

## Discrepancy 1: Anti-Tamper Detection

When the app loads, four interesting JSON events are logged. The fourth is a collection of the first
three (plus some other telemetry). Each of the first three has an events[0].name field in the JSON
of:

- `APP_FIRM_NON_APPSTORE_DOWNLOAD`
- `APP_FIRM_SIGNATURE_TAMPER`
- `JMDetectionResultJailBreak`

The app runs fine and does not exhibit the crash/suicide behavior when running with Frida, but these
telemtry events imply that the `scbody` dynamic library *is* being detected. For whatever reason,
the app just doesn't care about it.

While the app runs and can connect to the P20i earbuds, it might be possible that the server sees
these flags and refuses to serve firmware binaries to a modified client as an anti-analysis measure.

## Discrepancy 2: Constant IDs

Almost all of the UUIDs observed in the JSON logs change with every installation of the app, except
for one (at least that have been noticed -- the "only one" claim should be verified).

The constant value is `"anonymous_id":"25175005-856F-4AAB-A276-01988F6459F5"`.

It could be possible that the server is pinning against this (maybe it takes the place of an account
ID for users that are logged in). If that were the case, the server might be able to perform
stricter checks on which devices the user is known to own.

## Discrepancy 3: Response Knowns True Version

When the app first connects to the earbuds over Bluetooth, a `src=resp` capture is made. Here's its
output from the `scbody_firstlaunch_3.log` file:

```text
2026-09-04 18:39:20.376370 SoundCore{scbody.dylib}[27440] <NOTICE>: SCBODY CAPTURE #35 src=resp url=(none) len=129 score=5 BEGIN
2026-09-04 18:39:20.376388 SoundCore{scbody.dylib}[27440] <NOTICE>: SCBODY #35 seg 1/1 {"firmware_list":[{"product_component":"ALL","version":"14.43","relation_sn":"","sn":"3949E7BDE52DB6F4","product_code":"A3949"}]}
```

Despite all `src=json-mod` packets before this using the rewritten version, serial number, and MAC
address, this packet somehow knows the true values. The source is claimed to be a response from the
server, in which case the server *must* be pinning against additional information (perhaps the
`anonymous_id`).

The possibility of `src=resp` packets *not* coming from the server should be analyzed rigorously.

## Deliverables

The goals of this research session are:

1. Read the prior research and the `scbody` log files as needed to gather context
2. Begin by giving your analysis and interpretations of the discrepancies before making any changes
3. Implement the changes below if you agree that they may produce meaninful results:
   - First clean up the `rewrite_version_and_sn` function to more cleanly rewrite several values
   - Silence, rewrite, or remove the anti-tamper telemetry
   - Determine where `anonymous_id` comes from and whether it is possible to rewrite it to hide the
     identity of the phone
