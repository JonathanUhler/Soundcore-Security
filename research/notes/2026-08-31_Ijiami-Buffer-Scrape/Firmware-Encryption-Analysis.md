# Firmware Package Encryption, Can It Be Decrypted

Question raised 2026-08-31. If a P20i firmware file were obtained, is it encrypted, and could it be
decrypted. Short answer, the P20i is a Jieli device, and the Jieli firmware protection is a weak,
already reverse-engineered scrambling, so yes, an obtained file is very likely decryptable with
existing open tools. This is a different and much easier situation than the eufy camera line.

## Do Not Confuse With The Eufy Camera Firmware

The earlier web finding that Anker firmware is "fully encrypted, `_ENCRYPT.bin`, entropy near 8, no
signature verification" is the eufy security camera line, a Linux-class SoC. That does not apply to
the P20i. The P20i is a Jieli BT audio SoC, a different firmware pipeline entirely.

## The App Adds No Encryption Layer

Checked the download and flashing path in `apk/ram-scrape/`.

- The server firmware model `com/oceanwing/ota/model/FirmwareExt` carries only `addr_begin`,
  `addr_offset`, `instruction_set`, `base_version`, `require_box_version`, `file_name`, and upgrade
  times. There is no cipher, key, iv, or encryption-scheme field. `LastPackageModel` adds `url`,
  `md5`, `size`, `version`. So the only app-layer protection on the download is the `md5` checksum,
  which is integrity, not confidentiality.
- `com/oceanwing/ota/utils/CryptoUtils` is a single `a(byte[]) -> byte[]` transform. Its body is
  extracted and it has no `<clinit>`, so it carries no hardcoded key. Given the server model exposes
  no encryption metadata, there is no evidence of an app-added firmware cipher. The transform is
  most likely a checksum or format helper.
- The Jieli config `com/jieli/jl_bt_ota/model/BluetoothOTAConfigure` exposes no firmware-encryption
  key field, and no OTA encryption-key setter is referenced anywhere in the app's Jieli or OTA code.

So the downloaded file is the Jieli update image itself, wrapped only by the transport format and
the chip's own protection.

## The Jieli Protection Is Weak And Already Broken

The firmware format is the Jieli UFW container, magic `JLUFW` or `@JMUA`, packed by the Jieli
`isd_download` and `fw_pack` tools. The confidentiality comes from the chip's on-flash scrambler,
not from strong crypto.

- The scrambler is a hardware peripheral named ENC, sitting between cache and the SPI flash
  controller. Its algorithm is reverse-engineered.
- It is an LFSR-based stream cipher similar to CRC16-CCITT. It processes 32-byte blocks, and the
  per-block 16-bit key is derived from the block index and a fixed model-specific root key. Quarkslab
  reports an example root key `0x170f` for an AC6958.
- The key space is tiny. The root key is 16-bit, so 65536 possibilities, brute-forceable directly,
  and there is abundant known plaintext in a firmware image, headers and vector tables, to confirm a
  guess. Quarkslab recovered the root key and decrypted with documented stream-cipher Python. The
  chipkey can also be read from `isd_config.ini` if the bootloader config is available.

Public tooling that already does this, kagaimiq's `jl-uboot-tool` (flash and dump over UART or USB),
`jielie` and `jl-misctools` (format and descrambler), plus the Quarkslab write-up with code. The
Jieli SDK itself is open source, `Jieli-Tech/fw-AC63_BT_SDK` and `fw-Bootloader`, and the Android OTA
library `Jieli-Tech/Android-JL_OTA`, so the container format is documented.

## Integrity Versus Confidentiality

Jieli offers `chip_verify`, an RSA signature check, as a build option. That is integrity, it stops a
tampered image being flashed to a device, it does not stop reading or decrypting an obtained image.
The app-layer `md5` is likewise only a checksum. Neither is an obstacle to decryption.

## Verdict And The Shortcut

If a P20i firmware file is obtained, decryption is very likely, using the recovered or brute-forced
16-bit root key and the public descrambler. The realistic unknowns are minor, whether Anker ships the
raw UFW or a lightly transformed variant, and which exact Jieli series the P20i uses, both settled by
inspecting one obtained file.

There is also a shortcut that sidesteps the cloud and the request signing entirely. Jieli SoCs expose
a UART and USB uboot that `jl-uboot-tool` can drive to dump the flash directly from the hardware,
which the project owns. That yields the scrambled image without any signed API call, and the same
descrambler applies.

## Links

- Quarkslab, JieLi firmware teardown and decryption.
  https://blog.quarkslab.com/nerd-life-weeks-firmware-teardown-we-were-right.html
- kagaimiq/jl-uboot-tool. https://github.com/kagaimiq/jl-uboot-tool
- kagaimiq/jielie. https://github.com/kagaimiq/jielie
- Jieli-Tech/fw-AC63_BT_SDK. https://github.com/Jieli-Tech/fw-AC63_BT_SDK
- Jieli-Tech/Android-JL_OTA. https://github.com/Jieli-Tech/Android-JL_OTA
