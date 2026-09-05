# Problem Statement: A30 Firmware Decryption

The conclusion of the `2026-09-04_Resolving-Batch-API-Discrepancies` research session was a
successful download of the Soundcore Sleep A30 earbud firmware. The firmware file is available at
`a30_firmware/1775099301461220_D1301S_ota_01.07_release_20260304162801.bin`.

The binary is almost certainly encrypted:

- No strings except `CRC32_OF_IMAGE=0x55101F71` are visible
- Entropy is around 0.97 throughout the entire file

The goal of this research session is to decrypt the binary. You should start by doing research to
try to identify the SoC used in the A30 earbuds. The photos in the FCC filings do not show any
markings on the chip packaging. It looks to be about 3mm by 5mm and has no visible pins on the side
of the packaging (they are probably all on the bottom).

If the chip can be identified, you should then pivot to researching known weaknesses in its firmware
encryption. If the chip is Jieli, existing community projects may be able to undo the scrambling
applied to firmware images.
