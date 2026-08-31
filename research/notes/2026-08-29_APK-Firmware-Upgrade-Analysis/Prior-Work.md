# Prior Work On The Anker And Eufy API

This note summarizes existing public reverse engineering of the Anker, eufy, and Soundcore cloud API
and Bluetooth protocol, and how it applies to the P20i firmware work. These projects cover adjacent
product lines, not the P20i, so treat the specifics as hypotheses to confirm.

## Request Signing And Authentication

- The Anker common auth uses `gtoken`, an MD5 of the encrypted `user_id`, sent with a `token_id`.
  This matches the `gToken` string found in the blutter reconstruction. Our capture had an empty
  `user_id`, so the firmware check is app level, not user bound. See thomluther/anker-solix-api.
- A 2026 write up of a newer Anker product documents HMAC-SHA256 request signing, where the HMAC key
  is the hex string encoded as UTF-8 rather than the raw bytes, with four hardcoded keys per
  environment. That product also wraps request bodies in an ECDH P-256 session with AES-128-CBC. See
  the charliex2 eufy post.
- Our `speaker.eufylife.com` and `log.eufylife.com` capture used a simpler scheme, a 32 hex `token`
  header plus a `timestamp` header and a plaintext JSON body, with `AnkerBG: SPEAKER`. So the
  speaker business group likely uses the older MD5 style token, not the ECDH and AES body encryption.
  That makes replaying requests with a normal client feasible.

## Firmware OTA Endpoints

- The Anker common OTA check is `POST /v1/app/ota/get_app_version`. The response carries a
  `download_url` and a `forceUpgrade` flag. See the charliex2 eufy post.
- The eufy device firmware pattern is `device/firmware/{deviceId}/{BLE|MCU|RES}/update/{version}`,
  plus `device/update/firmware_history/{device_id}`. See robbalmbra/eufy-api. The version in the
  path is the lever for the low version trick, since the server compares the update against it.
- These two shapes are the first candidates for the `speaker.eufylife.com` firmware path.

## Firmware Protections

- In an adjacent Anker product line, researchers found no firmware signature verification in the
  download or flash path, and a fully encrypted firmware binary marked with an `_ENCRYPT` suffix,
  with the download URL supplied by the server and a silent `forceUpgrade`. See the charliex2 post.
- Hypothesis for the P20i, expect an encrypted blob, and check whether the app verifies any
  signature before flashing. This is the second Goal 2 question.

## Bluetooth Protocol

- CoreSound is a reverse engineered Soundcore BR/EDR RFCOMM implementation, with a frame parser and
  command builders in `soundcore-protocol.js`. It corroborates the `DEV_DATA_COMMAND_ALL_INFO` frame
  and is the reference for the later Bluetooth OTA work. See CriticalRange/CoreSound.

## Sources

- [thomluther/anker-solix-api](https://github.com/thomluther/anker-solix-api)
- [charliex2 eufy post, 2026](https://charliex2.wordpress.com/2026/03/06/eufy/)
- [moag1000/anker-solix-api-exploration](https://github.com/moag1000/anker-solix-api-exploration)
- [robbalmbra/eufy-api](https://github.com/robbalmbra/eufy-api)
- [FuzzyMistborn/python-eufy-security](https://github.com/FuzzyMistborn/python-eufy-security/blob/dev/API.md)
- [USENIX WOOT 24, Reverse Engineering the Eufy Ecosystem](https://www.usenix.org/system/files/woot24_slides-goeman.pdf)
- [CriticalRange/CoreSound](https://github.com/CriticalRange/CoreSound)
- [mitchellrj/eufy_robovac issue 1](https://github.com/mitchellrj/eufy_robovac/issues/1)
