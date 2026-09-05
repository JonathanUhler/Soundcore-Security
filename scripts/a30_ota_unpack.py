#!/usr/bin/env python3
"""Unpack a Soundcore A30 (D1301S) OTA firmware image.

The A30 OTA .bin is not encrypted. It is an Anker container of LZMA compressed
flash sections. The container layout is:

    ff ff ff ff                      4-byte magic
    repeated record:
        <u32 big-endian compressed length L>
        <L bytes: a complete LZMA-alone (.lzma) stream>
    [CRC32_OF_IMAGE=0x........]       ascii trailer (BES specific crc, see notes)

Each LZMA stream decompresses to a 0x20000 (128 KiB) flash section. The final
section is shorter. Concatenating the decompressed sections yields the on-flash
firmware image for the Bestechnic (BES, best1503) SoC.
"""

import argparse
import lzma
import struct
import sys
import zlib

MAGIC = b"\xff\xff\xff\xff"
# LZMA-alone header that every record begins with: props 0x5d, dict 0x04000000,
# uncompressed size unknown (0xff * 8), then the mandatory 0x00 range-coder byte.
LZMA_HDR = bytes.fromhex("5d00000004ffffffffffffffff00")


def unpack(path):
    data = open(path, "rb").read()
    if data[:4] != MAGIC:
        print("warning: file does not start with ff ff ff ff magic", file=sys.stderr)

    sections = []
    off = 4
    idx = 0
    while off + 4 <= len(data):
        length = struct.unpack(">I", data[off : off + 4])[0]
        start = off + 4
        end = start + length
        if length == 0 or end > len(data):
            break
        stream = data[start:end]
        if stream[:14] != LZMA_HDR:
            print(f"record {idx}: unexpected header {stream[:14].hex()}", file=sys.stderr)
        out = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(stream)
        sections.append(out)
        print(f"record {idx:02d}: comp={length:6d} -> decomp={len(out):6d} (0x{len(out):x})")
        off = end
        idx += 1

    trailer = data[off:]
    image = b"".join(sections)
    print(f"\nsections: {len(sections)}  image: {len(image)} bytes (0x{len(image):x})")
    print(f"trailer: {trailer.decode('latin1', 'replace').strip()}")
    print(f"crc32(image) standard = 0x{zlib.crc32(image) & 0xffffffff:08x}")
    return image


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", help="packed A30 OTA .bin")
    ap.add_argument("-o", "--output", help="write decompressed image here")
    args = ap.parse_args()
    image = unpack(args.input)
    if args.output:
        open(args.output, "wb").write(image)
        print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
