# Notes: A30 Firmware Decryption

These notes correspond to the plan in `research/plans/2026-09-05_A30-Firmware-Decryption/`. The plan
asked to decrypt the Sleep A30 firmware image at
`a30_firmware/1775099301461220_D1301S_ota_01.07_release_20260304162801.bin`, to first identify the
SoC, and to look for known firmware encryption weaknesses (the plan guessed the chip might be Jieli).

The headline result overturns the plan's premise. The A30 firmware is not encrypted. It is LZMA
compressed. The high entropy that earlier sessions read as a cipher is just compressed output. The
image unpacks cleanly with no key, and the decompressed firmware is plain ARM Thumb-2 code for a
Bestechnic (BES) SoC, not Jieli.

## Status

- The container format is fully decoded and the image is fully decompressed.
- SoC identified from firmware strings as Bestechnic, platform `best1503`.
- Decompressed image written to `a30_firmware/A30_decompressed.bin`, 2266052 bytes.
- Reusable unpacker committed at `scripts/a30_ota_unpack.py`.
- One minor open thread. The `CRC32_OF_IMAGE=0x55101F71` trailer is not reproduced by a standard
  CRC-32 over any obvious byte range. It is a BES specific or on-flash-layout checksum. This does not
  affect the decompression, which is validated by other means.

## The Container Format

The `.bin` is an Anker OTA container wrapping LZMA compressed flash sections. Layout:

```
ff ff ff ff                         4-byte magic
repeated record (18 of them):
    <u32 big-endian compressed length L>
    <L bytes, one complete LZMA-alone stream>
[CRC32_OF_IMAGE=0x55101F71]          ascii trailer
```

The big-endian length was confirmed against the file. For every record the length field equals the
distance to the next length field minus four, so the field measures the record payload exactly.

## The `5d 00 00 00 04 FF..` Marker Is An LZMA Header, Not A Cipher

Every record payload starts with the identical 14 bytes `5d 00 00 00 04 ff ff ff ff ff ff ff ff 00`.
Earlier this looked like an encryption block marker. It is a textbook LZMA-alone (`.lzma`) header.

- `0x5d` is the LZMA properties byte for `lc=3, lp=0, pb=2`, the classic default.
- `00 00 00 04` is the dictionary size as a little-endian u32, `0x04000000`.
- `ff ff ff ff ff ff ff ff` is the uncompressed size field set to the unknown-size sentinel.
- The trailing `0x00` is the mandatory first byte of the LZMA range coder.

Feeding each record straight into Python `lzma.LZMADecompressor(format=FORMAT_ALONE)` decompresses it.

## Section Table

Seventeen records decompress to exactly `0x20000` (128 KiB) each. The last decompresses to 37828
bytes. Total decompressed image is 2266052 bytes. The 128 KiB unit is the SoC flash page size, so
each record is one compressed flash page.

| records | compressed size | decompressed size |
|---------|-----------------|-------------------|
| 0..16   | 47507..110844   | 131072 each       |
| 17      | 4611            | 37828             |

## SoC Identification, Bestechnic best1503

The decompressed image is ARM Thumb-2 firmware. Strings identify the vendor beyond doubt. It is
Bestechnic (BES), not Jieli.

- `CHIP=best1503`, and source paths `../../platform/drivers/bt/best1503/bt_drv_reg_op.cpp`,
  `bt_1503_reg_map.h`, `bt_drv_modem_reg_map_best1503.h`.
- `BTC 1503: metal id=%d`, `BTC:1503 t0 work mode patch version:%08x`.
- IBRT, Bestechnic's proprietary TWS relay technology, is everywhere: `IBRT-STATE`,
  `W4-IBRT READY`, `IBRT_CORE`, `APP_IBRT`, `app_ibrt_ota_*`.
- BES house style HAL and RTOS: `HAL_I2C_ERRCODE_*`, `CONTROLLER_DEAD`, `RELOAD_COMPLETE`,
  `UX-THREAD` with `osMail*` CMSIS-RTX calls.
- Built with a Bestechnic GCC-10 Jenkins pipeline, newlib libc.

This agrees with the Android app, whose dominant OTA SDK is `com/oceanwing/ota/sdk/bes` and which
ships `CommonBes2OtaActivity`. Note this is a different SoC vendor from the P20i (`A3949`), which is
Jieli. Anker uses different chips per product, so the plan's Jieli guess did not carry over.

## What Is In The Image

The firmware is a full BES TWS application with a large Anker application layer under `../../anker/`.

- Product strings: `soundcore Sleep A30 Special`, `soundcore Sleep A30 Special LE`, and
  `REV_INFO=daa1116-fixed-5f45d1b-fixed:D1301`.
- Anker app modules: `anker_main.c`, `anker_protocol_soundcore.c`, `anker_protocol_box.c`,
  `anker_protocol_tws_sync.c`, `anker_app_sleep.c`, `anker_gomore.c`, `anker_tracking.c`,
  `anker_env_noise_eq.c`, `anker_battery_manage.c`, `anker_nv.c`.
- Sensors: an ST LIS2DW12 accelerometer at `../../anker/driver/gsensor/lis2dw12/lis2dw12.c`, with a
  coprocessor accel path (`cp_accel_open`, `accel_main`) feeding sleep and position detection.
- Sleep and health: `anker_gomore.c` points at GoMore, a licensed sleep and fitness algorithm.
- OTA stack: the BES `ota_control_*` and `TOTA_CONTROL` transport over BLE, with
  `ota_control_check_image_crc`, `OTA_IMAGE_CRC`, and `ota_boot_info_configure_for_secure_boot`.
  The presence of a secure-boot boot-info path is worth a closer look later.

## Corrected Understanding Of Prior Findings

The `2026-09-04_Resolving-Batch-API-Discrepancies` session concluded the image was "encrypted,
entropy near 0.97". That reading was a false positive. LZMA output is high entropy, so a whole-file
entropy scan cannot tell compression from encryption. The tell was structural. There is a plaintext
container framing around each high-entropy block, and that framing is a standard LZMA header. No
decryption is required and no key exists to recover.

## How To Reproduce

```
python3 scripts/a30_ota_unpack.py \
    a30_firmware/1775099301461220_D1301S_ota_01.07_release_20260304162801.bin \
    -o a30_firmware/A30_decompressed.bin
```

## Open Threads And Future Directions

- Resolve the `CRC32_OF_IMAGE` algorithm. Standard CRC-32 over the decompressed concatenation, over
  the same padded to a whole number of 128 KiB pages, and over the compressed record ranges all
  fail to reproduce `0x55101F71`. It is likely a BES specific CRC, or it covers the on-flash layout
  including boot-info headers rather than the raw section concatenation.
- Load `A30_decompressed.bin` in Ghidra as BES ARM Thumb-2. The load base and per-section flash
  offsets should follow from the vector table at the image start and the `best1503` memory map.
  Section 0 begins `ff ff ff ff 00 00 05 00 00 00 00 00 ...` then Thumb code, so there is a small
  image header before the entry path.
- Analyze `anker_protocol_soundcore.c` and the BES `ota_control` handlers for the OTA command set,
  and check whether `ota_boot_info_configure_for_secure_boot` implies real signature enforcement or
  is just a CRC gate. This feeds the original project goal of understanding firmware upgrade trust.
- The same container almost certainly wraps other Anker BES products. The P20i, being Jieli, uses a
  different path, so it needs its own image and its own unpacker.
