#!/usr/bin/env python3
"""Make an in-memory (ART/ijiami) dex loadable by jadx.

An in-memory dex has an ART-patched Adler-32 checksum and SHA-1 signature, and
its tail map_list page is often truncated or zero-filled by the reassembly. jadx
rejects the checksum, then crashes on the bad map_list. This rebuilds a valid
map_list in place from the header section table, then recomputes the signature
and checksum so jadx accepts the file.

This fixes the container only. It does NOT repair a body whose pages were
reclaimed or mismapped at capture time. Run dex_health.py afterward. If the
resolvable percentage is not ~100, the capture is bad and must be redone.

Usage:
    python3 fix_inmemory_dex.py in.dex out.dex
"""
import struct, zlib, hashlib, sys

# dex map_list type codes for the seven index sections plus the map itself
SECTIONS = [
    (0x0000, None, 0x00),        # header_item, one entry at offset 0
    (0x0001, 0x38, 0x3c),        # string_id_item
    (0x0002, 0x40, 0x44),        # type_id_item
    (0x0003, 0x48, 0x4c),        # proto_id_item
    (0x0004, 0x50, 0x54),        # field_id_item
    (0x0005, 0x58, 0x5c),        # method_id_item
    (0x0006, 0x60, 0x64),        # class_def_item
]


def fix(src, dst):
    d = bytearray(open(src, 'rb').read())
    n = len(d)
    u32 = lambda o: struct.unpack_from('<I', d, o)[0]
    map_off = u32(0x34)

    entries = []
    for type_code, size_off, off_off in SECTIONS:
        if size_off is None:
            entries.append((type_code, 1, 0))
        else:
            entries.append((type_code, u32(size_off), u32(off_off)))
    entries.append((0x1000, 1, map_off))               # map_list points at itself

    blob = struct.pack('<I', len(entries))
    for type_code, size, off in entries:
        blob += struct.pack('<HHII', type_code, 0, size, off)

    if map_off == 0 or map_off + len(blob) > n:
        raise SystemExit(f"map_off 0x{map_off:x} has no room for a {len(blob)} byte map in {n} bytes")
    d[map_off:map_off + len(blob)] = blob

    d[12:32] = hashlib.sha1(bytes(d[32:])).digest()    # signature over bytes 0x20..end
    struct.pack_into('<I', d, 8, zlib.adler32(bytes(d[12:])) & 0xffffffff)  # checksum over 0x0c..end
    open(dst, 'wb').write(d)
    print(f"{src}: rebuilt {len(entries)} entry map at 0x{map_off:x}, fixed checksum and signature")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    fix(sys.argv[1], sys.argv[2])
