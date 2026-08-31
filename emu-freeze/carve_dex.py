#!/usr/bin/env python3
"""Carve and validate DEX files out of raw memory dumps.

Feed this the region dumps produced by dump-proc-mem.sh (Strategy 1) or a full
guest RAM image produced by the QEMU monitor (Strategy 2). It scans for the DEX
magic, parses each candidate header, and confirms it with the two integrity
fields every valid DEX carries: the Adler-32 checksum and the SHA-1 signature.
Anything that passes both is a real, complete DEX and is written out.

A physically contiguous dump (a per-region /proc/<pid>/mem read) validates
cleanly because the bytes are in virtual-address order. A full physical RAM
image may have a DEX split across scattered physical pages, in which case the
header is found but validation fails. Those are reported as truncated so you
know to fall back to the per-region dump path.

Usage:
    python3 carve_dex.py DUMP [DUMP ...] --out ./carved
    python3 carve_dex.py ram.bin --out ./carved --min-size 4096
"""

import argparse
import hashlib
import os
import struct
import sys
import zlib

MAGIC_PREFIX = b"dex\n"
VALID_VERSIONS = {b"035", b"036", b"037", b"038", b"039"}
HEADER_SIZE = 0x70
ENDIAN_TAG = 0x12345678
# The app classes we actually want live under this package path.
TARGET_MARKER = b"com/oceanwing/soundcore"


def parse_header(buf, off):
    """Return a dict describing the DEX at buf[off:] or None if the header is
    not self-consistent. Does not run the expensive hash checks."""
    if off + HEADER_SIZE > len(buf):
        return None
    if buf[off:off + 4] != MAGIC_PREFIX:
        return None
    version = buf[off + 4:off + 7]
    if version not in VALID_VERSIONS or buf[off + 7] != 0:
        return None
    checksum = struct.unpack_from("<I", buf, off + 0x08)[0]
    file_size = struct.unpack_from("<I", buf, off + 0x20)[0]
    header_size = struct.unpack_from("<I", buf, off + 0x24)[0]
    endian_tag = struct.unpack_from("<I", buf, off + 0x28)[0]
    if header_size != HEADER_SIZE or endian_tag != ENDIAN_TAG:
        return None
    if file_size < HEADER_SIZE or file_size > 256 * 1024 * 1024:
        return None
    return {
        "version": version.decode(),
        "checksum": checksum,
        "file_size": file_size,
        "stored_sig": bytes(buf[off + 0x0C:off + 0x20]),
    }


def validate(buf, off, hdr):
    """Confirm the Adler-32 checksum and SHA-1 signature. Returns
    (checksum_ok, sig_ok, complete). complete is False if the candidate runs
    past the end of the buffer (scattered or truncated dump)."""
    fs = hdr["file_size"]
    if off + fs > len(buf):
        return (False, False, False)
    body = buf[off:off + fs]
    sig_ok = hashlib.sha1(body[0x20:]).digest() == hdr["stored_sig"]
    checksum_ok = (zlib.adler32(body[0x0C:]) & 0xFFFFFFFF) == hdr["checksum"]
    return (checksum_ok, sig_ok, True)


def scan(path, out_dir, min_size):
    with open(path, "rb") as fh:
        buf = fh.read()
    print(f"[*] {path}: {len(buf):,} bytes")
    results = []
    pos = 0
    while True:
        i = buf.find(MAGIC_PREFIX, pos)
        if i < 0:
            break
        pos = i + 1
        hdr = parse_header(buf, i)
        if hdr is None:
            continue
        if hdr["file_size"] < min_size:
            continue
        checksum_ok, sig_ok, complete = validate(buf, i, hdr)
        results.append((i, hdr, checksum_ok, sig_ok, complete))
    return buf, results


def main():
    ap = argparse.ArgumentParser(description="Carve DEX files from memory dumps.")
    ap.add_argument("dumps", nargs="+", help="region dumps or a full RAM image")
    ap.add_argument("--out", default="./carved", help="output directory")
    ap.add_argument("--min-size", type=int, default=0x70,
                    help="ignore DEX headers claiming a smaller file_size")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    valid = 0
    partial = 0
    hits = 0
    for path in args.dumps:
        buf, results = scan(path, args.out, args.min_size)
        base = os.path.basename(path)
        for off, hdr, checksum_ok, sig_ok, complete in results:
            tag = f"{base}@0x{off:x}"
            if checksum_ok and sig_ok:
                body = buf[off:off + hdr["file_size"]]
                name = f"dex_{base}_{off:08x}.dex"
                with open(os.path.join(args.out, name), "wb") as w:
                    w.write(body)
                marked = TARGET_MARKER in body
                if marked:
                    hits += 1
                valid += 1
                flag = "  <-- contains com/oceanwing/soundcore" if marked else ""
                print(f"[+] VALID  {tag} v{hdr['version']} "
                      f"{hdr['file_size']:,}B -> {name}{flag}")
            elif not complete:
                partial += 1
                print(f"[~] header only {tag} v{hdr['version']} claims "
                      f"{hdr['file_size']:,}B but dump ends first "
                      f"(scattered/truncated)")
            else:
                print(f"[-] bad hashes {tag} checksum_ok={checksum_ok} "
                      f"sig_ok={sig_ok} (false magic or corrupt)")

    print(f"\n[=] {valid} valid DEX, {hits} containing the target package, "
          f"{partial} header-only candidates")
    if valid == 0:
        print("[!] no complete DEX recovered. If you dumped full RAM, retry "
              "with the Strategy 1 per-region dump for contiguous bytes.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
