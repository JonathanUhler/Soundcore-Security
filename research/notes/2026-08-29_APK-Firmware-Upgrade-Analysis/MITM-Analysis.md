# MITM Analysis

These notes describe the behavior observed while running the Soundcore app on a real iPhone through mitmproxy.

## Setup

The proxy was set up with the following steps:

1. Temporarily allow traffic on the proxy host machine: `sudo ufw allow 8080/tcp && sudo ufw reload`
2. Find the LAN IP on the host machine: `ip route get 1.1.1.1 | awk '{print $7; exit}'`
3. Run the proxy: `mitmweb --listen-host 0.0.0.0 --listen-port 8080`
4. Set up the proxy on the phone: Settings -> WiFi -> current network (i) -> Configure Proxy -> Manual -> enter LAN IP and port 8080
5. Check for a firmware upgrade in the Soundcore app: Soundcore -> P20i -> Settings -> Update Firmware
6. Disable the firewall rule for security: `sudo ufw delete allow 8080/tcp && sudo ufw reload`

## Cert Pinning Issues

Many of the hosts that the firmware upgrade check contacts do validate the certificate against a known list, of which the mitm.it cert is not part of. This means the
full traffic can't be seen. The iPhone used for testing is not jailbroken, and probably can't be. Getting a legitimate IPA for the Soundcore app will be very difficult.

## Potential Positive Findings

Despite the certificate pinning issues, some flows did appear in the mitmproxy web GUI. They were all POST requests to `log.eufylife.com/push_log_hdfs` with JSON-like
octet stream payloads. The full flows file is available in this notes directory at `flows`, but here are some example payloads:

## Flow 1

```json
{
  "events": [
    {
      "value_string": "{\"firmware_version\":\"14.43\"}",
      "module": "OTA",
      "product_code": "A3949",
      "device_id": "",
      "time": "1788042477",
      "mac": "F4:B6:2D:E5:BD:E7",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_ENTER_OTA_WITH_NEED_UPDATE"
    },
    {
      "value_string": "{\"firmware_version\":\"14.43\"}",
      "module": "OTA",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788042479",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_ENTER_OTA_WITH_NEED_UPDATE"
    },
    {
      "value_string": "{\"firmware_version\":\"14.43\"}",
      "module": "OTA",
      "product_code": "A3949",
      "device_id": "",
      "time": "1788042480",
      "mac": "F4:B6:2D:E5:BD:E7",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_ENTER_OTA_WITH_NEED_UPDATE"
    },
    {
      "value_string": "{\"firmware_version\":\"14.43\"}",
      "module": "OTA",
      "product_code": "A3949",
      "device_id": "",
      "time": "1788042488",
      "mac": "F4:B6:2D:E5:BD:E7",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_ENTER_OTA_WITH_NEED_UPDATE"
    },
    {
      "value_string": "epZsi4vunUfFiPTCWCkeVS:APA91bEDZhamEOuAgDAiZSOlfsvRPv3k4UoeUzTktUg85DPZ1o29k2e_T0QgS5TRWP14I2fLrL5w_HsOUBA-_mCV-AymVFpJ3IB4X7t9151RitTUq8i7YHY",
      "module": "OTHER",
      "product_code": "none",
      "mac": "",
      "time": "1788043061",
      "device_id": "",
      "sn": "",
      "type": "1",
      "name": "REGISTRATION_MESSAGING_TOKEN"
    },
    {
      "value_string": "",
      "module": "APP_FIRM",
      "product_code": "none",
      "mac": "",
      "time": "1788043061",
      "device_id": "",
      "sn": "",
      "type": "1",
      "name": "APP_FIRM_HTTP_DETECTION"
    },
    {
      "value_string": "00010503000031342e343331342e343333393439453742444535324442364634000078787878787878780000000000000000000000000e016601660132013301210120ffffff610001ffffffffffffffffffffffffffffffbd",
      "module": "HOME_PAGE",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043065",
      "device_id": "",
      "sn": "",
      "type": "1",
      "name": "DEV_DATA_COMMAND_ALL_INFO"
    },
    {
      "value_string": "00010503000031342e343331342e343333393439453742444535324442364634000078787878787878780000000000000000000000000e016601660132013301210120ffffff610001ffffffffffffffffffffffffffffffbd",
      "module": "HOME_PAGE",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043065",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "DEV_DATA_COMMAND_ALL_INFO"
    }
  ],
  "country": "US",
  "sys_type": "iOS",
  "http_user_agent": "soundcore-iOS-5.0.21",
  "phone_model": "iPhone18,5",
  "uuid": "DFC3E714-0121-4B87-9187-22CBA056D1F7",
  "user_id": "",
  "phone_name": "Jonathan’s iPhone",
  "sys_version": "26.5.1",
  "phone_brand": "Apple"
}
```

## Flow 2

```json
{
  "events": [
    {
      "value_string": "",
      "module": "USERCENTER",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043075",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_USER_RESEARCH_IMPRESSION"
    },
    {
      "value_string": "{\"token\":\"epZsi4vunUfFiPTCWCkeVS:APA91bEDZhamEOuAgDAiZSOlfsvRPv3k4UoeUzTktUg85DPZ1o29k2e_T0QgS5TRWP14I2fLrL5w_HsOUBA-_mCV-AymVFpJ3IB4X7t9151RitTUq8i7YHY\",\"error\":\"Could not connect to the server.\"}",
      "module": "OTHER",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043075",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "UPLOAD_MESSAGING_TOKEN"
    },
    {
      "value_string": "",
      "module": "USERCENTER",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043075",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_USER_RESEARCH_IMPRESSION"
    },
    {
      "value_string": "",
      "module": "USERCENTER",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043075",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_USER_RESEARCH_IMPRESSION"
    },
    {
      "value_string": "00010503000031342e343331342e343333393439453742444535324442364634000078787878787878780000000000000000000000000e016601660132013301210120ffffff610001ffffffffffffffffffffffffffffffbd",
      "module": "HOME_PAGE",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043086",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "DEV_DATA_COMMAND_ALL_INFO"
    },
    {
      "value_string": "{\"type\":\"nps\"}",
      "module": "POP",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043086",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_POP_REQUEST"
    },
    {
      "value_string": "cancelled",
      "module": "POP",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043086",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_POP_REQUEST_FAIL"
    },
    {
      "value_string": "0000000005030000000000000200000000000c000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000073",
      "module": "COMMON",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043086",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "DEV_USE_INFO"
    }
  ],
  "country": "US",
  "sys_type": "iOS",
  "http_user_agent": "soundcore-iOS-5.0.21",
  "phone_model": "iPhone18,5",
  "uuid": "DFC3E714-0121-4B87-9187-22CBA056D1F7",
  "user_id": "",
  "phone_name": "Jonathan’s iPhone",
  "sys_version": "26.5.1",
  "phone_brand": "Apple"
}
```

## Flow 3

```json
{
  "events": [
    {
      "value_string": "{\"type\":\"all\"}",
      "module": "POP",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043087",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_POP_REQUEST"
    },
    {
      "value_string": "cancelled",
      "module": "POP",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043087",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_POP_REQUEST_FAIL"
    },
    {
      "value_string": "1",
      "module": "OTA",
      "product_code": "A3949",
      "mac": "F4:B6:2D:E5:BD:E7",
      "time": "1788043090",
      "device_id": "",
      "sn": "3949E7BDE52DB6F4",
      "type": "0",
      "name": "APP_OTA_ENTER"
    },
    {
      "value_string": "{\"firmware_version\":\"14.43\"}",
      "module": "OTA",
      "product_code": "A3949",
      "device_id": "",
      "time": "1788043090",
      "mac": "F4:B6:2D:E5:BD:E7",
      "sn": "3949E7BDE52DB6F4",
      "type": "1",
      "name": "APP_ENTER_OTA_WITH_NEED_UPDATE"
    }
  ],
  "country": "US",
  "sys_type": "iOS",
  "http_user_agent": "soundcore-iOS-5.0.21",
  "phone_model": "iPhone18,5",
  "uuid": "DFC3E714-0121-4B87-9187-22CBA056D1F7",
  "user_id": "",
  "phone_name": "Jonathan’s iPhone",
  "sys_version": "26.5.1",
  "phone_brand": "Apple"
}
```

## Commentary

The exact meaning of these logs is unclear, but they seem to contain commands to different "modules", each with a JSON-like payload (`value_string`) and information about the P20i that the command refers to.

Other URIs that were accessed by the Soundcore app (but failed due to the proxy detection) include:

- speaker.eufylife.com (seems to be the main API for checking firmware status, as a request was sent each time the "reload" button was pressed in the app to try fetching new firmware info)
- log.eufylife.com
- firebaselogging-pa.googleapis.com
- dts-log.anker.com

Visiting speaker.eufylife.com with a regular web browser results in a timeout, but log.eufylife.com results in this default OpenResty page:

```text
Welcome to OpenResty!

If you see this page, the OpenResty web platform is successfully installed and working. Further configuration is required.

For online documentation and support please refer to openresty.org.

Thank you for flying OpenResty.
```

And visiting dts-log.anker.com results in this default nginx page:

```text
Welcome to nginx!

If you see this page, the nginx web server is successfully installed and working. Further configuration is required.

For online documentation and support please refer to nginx.org.
Commercial support is available at nginx.com.

Thank you for using nginx.
```

That seems to imply that those two websites are not properly set up or secured, potentially making it possible to download firmware without the app.

# Analysis And Recommendations

The sections below were added after reviewing the flows file and cross referencing the blutter
reconstruction of `libapp.so`.

One correction to the note above. The default nginx and OpenResty pages at the roots of
`log.eufylife.com` and `dts-log.anker.com` are not a weakness or a firmware source. They are just
the unconfigured root of an API host that only answers specific paths such as `/push_log_hdfs`. The
firmware binary will live on a separate object storage or CDN host, not on a logging host.

## Consolidated Findings

- P20i product code is `A3949`. Both earbuds report firmware `14.43`. The device info blob carries
  the version twice, once per earbud.
- Firmware status API host is `speaker.eufylife.com`, and it is certificate pinned, so its request
  and response are not visible through the proxy. Soundcore runs on eufylife infrastructure, not on
  a soundcore.com API host.
- Telemetry host `log.eufylife.com/push_log_hdfs` is not pinned, which is why the flows leaked.
- The serial number is derived from the Bluetooth MAC. SN `3949E7BDE52DB6F4` is `3949` followed by
  the MAC `F4:B6:2D:E5:BD:E7` in reversed byte order. The serial is not secret. It is computable
  from the address the earbuds advertise.
- Requests are signed. The telemetry request carried `token`, a 32 hex digest, plus a `timestamp`
  header, `AnkerBG: SPEAKER`, and `country`.

  Correction (2026-08-30). An earlier version of this bullet claimed the Dart layer holds the signing
  pieces `gToken`, `signKey`, `app_key`, `nonce`, and `sign`, so the scheme was reconstructable from
  the blutter output. That is wrong. Those were false positive string matches (`signKey` is Fernet's
  `_signKey`, `nonce` is an AEAD cipher field, `gToken` matched html `TagToken`, `app_key` matched
  `app_keyboard`). None of the real header or signing constants (`AnkerBG`, `gtoken`, `app_key`,
  `x-auth-token`, `openudid`) appear anywhere in the Dart layer, `libapp.so`, or any shipped or on
  demand native `.so`. All HTTP goes native through `Bridge.request` (a Flutter `MethodChannel`), so
  the signing lives in the ijiami packed dex. See
  `research/notes/2026-08-29_OTA-API-Reconstruction/Signing-Analysis.md`.
- Every event had an empty `user_id`. The firmware check runs without a logged in user, so it is app
  signed, not user authenticated. That makes replaying it feasible.

## DEV_DATA_COMMAND_ALL_INFO Decode

The `value_string` hex decodes to a Soundcore device info frame.

```
0001 0503 0000                             header
31342e3433                                 "14.43"  firmware, earbud 1
31342e3433                                 "14.43"  firmware, earbud 2
3339343945374244453532444236463400        "3949E7BDE52DB6F4" serial, null terminated
7878787878787878 00 ...                    "xxxxxxxx" placeholder field
0e 01 66 01 66 01 32 01 33 01 21 01 20     TLV status block
ffffff 61 0001 ff ... ff                   status and padding
bd                                         trailing checksum
```

This is the on wire format the later Bluetooth OTA work needs.

## Where The OTA Endpoint Lives

The exact `speaker.eufylife.com` path is not recoverable from static artifacts. It is not in
`libapp.so`, the other native libraries, or the Flutter assets. The Dart layer only holds wrapper
names such as `getFirmwareUpgradeInfo` and `FirmwareUpgradeManager` that delegate to the packed
native code. So the path lives in the ijiami packed dex, the same wall that blocked the earlier
dynamic work. Static extraction of the path is not currently possible.

## Impact Of The Device Being On The Latest Firmware

The test P20i is already on `14.43`, the latest. The firmware check takes the current version as an
input, so the server reports no update and the app never downloads. Because `speaker.eufylife.com`
is pinned, the server response cannot be forged either. This blocks the plan to observe a real
download and read the URL from the telemetry channel. The telemetry does not log the check URL.

The way around this does not need a different device. Once the endpoint is known, query it directly
with a spoofed low `firmware_version` such as `1.00`. The server then treats the device as out of
date and returns the latest firmware metadata and download URL. The device state is irrelevant when
the request is driven by hand.

## Recommended Next Steps

The download observation path is blocked by the pinned API and the up to date device. The realistic
path is to reconstruct and drive the request directly.

1. Reverse the signing. Correction (2026-08-30). This step originally said to reverse it from the
   blutter output, but the signing is not in the Dart layer (see the correction above and
   `research/notes/2026-08-29_OTA-API-Reconstruction/Signing-Analysis.md`). It is in the ijiami
   packed dex, so recovering it needs a dex dump from a running app, not static blutter analysis.
2. Obtain the OTA endpoint path. It is not in any static artifact, so the options are to enumerate a
   small set of plausible paths on `speaker.eufylife.com` with a valid signature, or to probe the
   `speaker-oss.anker-in.com` object storage for a firmware path keyed on `a3949`, since the media
   assets already follow a `media/prod/<model>/...` scheme.
3. Once the endpoint responds, query with product code `A3949` and a low `firmware_version` to get
   the latest firmware URL, then download the binary. The binary is likely on an unpinned object
   storage host, so a plain request should work.

## Endpoint Probing Results

Direct probing of `speaker.eufylife.com` was tried, to find the OTA route by response differences.
It does not work, because the gateway hides route existence from unauthenticated clients.

- The host resolves to an AWS us-west-2 load balancer and runs the APISIX gateway. The root path
  returns 403. Unknown paths return a generic HTML 404.
- Calibration failed. `/speaker/unbind_device`, a real route constant taken from the blutter
  reconstruction, also returns 404, even with a full set of app style headers such as `app_key`,
  `x-auth-token`, `gtoken`, `AnkerBG`, model, and openudid. So APISIX only routes a request when it
  is properly signed. Every other request gets the same 404 whether the path is real or not.
- Result. The 404 versus JSON error oracle only works with a valid signature. Unauthenticated
  probing cannot fingerprint the OTA endpoint. Signing must be reconstructed first.

Path conventions seen in the Dart reconstruction, useful for a later authenticated enumeration.

- `/speaker/<verb_noun>`, for example `/speaker/unbind_device`.
- `/app/v1/<feature>/<action>`, for example `/app/v1/insight_card/list`.
- `/v2/anka/...` for the AI assistant feature.

The d3200 firmware manager was reconfirmed as native. Its Dart class logs in Chinese and registers
an event listener over the `anker.soundcore/flutter_boost` bridge. It makes no HTTP call, so the OTA
path is in the packed native code for every model.

## Security Relevant Observations

- The unpinned telemetry channel carries the device MAC, the serial, the firmware version, the
  Firebase push token, the phone name, and a device UUID. It is still TLS, so it is only readable
  with an installed proxy CA, but the breadth of identifiers is worth noting for disclosure.
- The serial being derivable from the advertised MAC means any nearby party can compute a device
  serial. If the OTA flow or any account flow trusts the serial as an identifier, that is worth
  testing.
