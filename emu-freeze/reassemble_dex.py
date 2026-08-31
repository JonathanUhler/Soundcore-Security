#!/usr/bin/env python3
"""Reconstruct contiguous DEX files from a physical RAM dump using the guest's
page tables.

The in-memory (ijiami-decrypted) dex is virtually contiguous but its 4 KB pages
are scattered across physical RAM, so a linear carve of the physical dump can
find the header but never validate the body. This walks the x86-64 4-level page
tables from a PGD (CR3), rebuilds a process's virtual address space (where the
dex is contiguous again), scans it for the dex magic, and writes out every dex
whose Adler-32 checksum and SHA-1 signature verify.

Getting CR3 (same capture as the dump): at the freeze, in the QEMU monitor
(telnet 127.0.0.1 55555) run `info registers` (or `info registers -a`) and read
a CR3=... value.

The process that hit the breakpoint may be a watchdog, not the app that holds
the dex, and the app process may not be scheduled on any CPU. So prefer
--scan-all: it uses the given CR3 only as a kernel-half fingerprint, finds EVERY
process PGD in the dump, and reconstructs them all. The dex is pulled from
whichever process is the app (flagged by the com/oceanwing/soundcore marker).

Usage:
    python3 reassemble_dex.py --cr3 0x47e8a000 --scan-all ram.bin --out carved_virt
    python3 reassemble_dex.py --cr3 0x47e8a000 ram.bin --out carved_virt   # single PGD

    # AVD with >3 GB RAM (physical split across the 4 GB hole):
    python3 reassemble_dex.py --cr3 0x.. --scan-all low.bin --highmem high.bin \
        --lowsize 0xC0000000 --out carved_virt
"""

import argparse
import hashlib
import mmap
import os
import struct
import sys
import zlib

PRESENT = 1
PS = 1 << 7
M4K = 0x000FFFFFFFFFF000
M2M = 0x000FFFFFFFE00000
M1G = 0x000FFFFFC0000000

MAGIC = b"dex\n"
VERS = {b"035", b"036", b"037", b"038", b"039"}
HDR = 0x70
ENDIAN = 0x12345678
MARK = b"com/oceanwing/soundcore"


class Phys:
    def __init__(self, low_path, high_path=None, lowsize=None):
        self.lowf = open(low_path, "rb")
        self.low = mmap.mmap(self.lowf.fileno(), 0, access=mmap.ACCESS_READ)
        self.low_len = len(self.low)
        self.lowsize = lowsize if lowsize is not None else self.low_len
        self.high = None
        if high_path:
            self.highf = open(high_path, "rb")
            self.high = mmap.mmap(self.highf.fileno(), 0, access=mmap.ACCESS_READ)

    def read(self, pa, n):
        if pa < self.lowsize:
            if pa + n > self.low_len:
                return None
            return self.low[pa:pa + n]
        if self.high is not None and pa >= 0x100000000:
            off = pa - 0x100000000
            if off + n > len(self.high):
                return None
            return self.high[off:off + n]
        return None


def table(phys, base):
    d = phys.read(base, 4096)
    if not d:
        return
    for i in range(512):
        e = struct.unpack_from("<Q", d, i * 8)[0]
        if e & PRESENT:
            yield i, e


def walk_user(phys, pgd):
    for i, e4 in table(phys, pgd & M4K):
        if i >= 256:               # user space = low canonical half
            continue
        va4 = i << 39
        for j, e3 in table(phys, e4 & M4K):
            va3 = va4 | (j << 30)
            if e3 & PS:
                yield va3, e3 & M1G, 1 << 30
                continue
            for k, e2 in table(phys, e3 & M4K):
                va2 = va3 | (k << 21)
                if e2 & PS:
                    yield va2, e2 & M2M, 1 << 21
                    continue
                for l, e1 in table(phys, e2 & M4K):
                    yield va2 | (l << 12), e1 & M4K, 1 << 12


def build_map(phys, pgd):
    m = {}
    for va, pa, size in walk_user(phys, pgd):
        for off in range(0, size, 0x1000):
            m[va + off] = pa + off
    return m


def runs(vpages):
    vpages.sort()
    start = prev = None
    for v in vpages:
        if start is None:
            start = prev = v
        elif v == prev + 0x1000:
            prev = v
        else:
            yield start, prev + 0x1000
            start = prev = v
    if start is not None:
        yield start, prev + 0x1000


def vread(phys, vmap, va, length, fill=False):
    """Read `length` bytes of virtual memory from `va`. Returns None on an
    unmapped hole, unless fill=True (then missing pages become zeros and the
    number of hole pages is returned alongside)."""
    out = bytearray()
    end = va + length
    p = va & ~0xFFF
    holes = 0
    while p < end:
        pa = vmap.get(p)
        d = phys.read(pa, 0x1000) if pa is not None else None
        if d is None:
            if not fill:
                return None
            d = b"\x00" * 0x1000
            holes += 1
        out += d
        p += 0x1000
    lead = va & 0xFFF
    body = bytes(out[lead:lead + length])
    return (body, holes) if fill else body


def valid_header(buf, off):
    if buf[off:off + 4] != MAGIC or buf[off + 4:off + 7] not in VERS or buf[off + 7] != 0:
        return None
    if off + HDR > len(buf):
        return None
    checksum = struct.unpack_from("<I", buf, off + 8)[0]
    file_size = struct.unpack_from("<I", buf, off + 0x20)[0]
    hsz = struct.unpack_from("<I", buf, off + 0x24)[0]
    et = struct.unpack_from("<I", buf, off + 0x28)[0]
    if hsz != HDR or et != ENDIAN or not (HDR <= file_size <= 64 * 1024 * 1024):
        return None
    return checksum, file_size, bytes(buf[off + 12:off + 0x20])


def structural_ok(h, fsz):
    """Validate a DEX header by its section table alone (no hashes), so a dex
    whose checksum/signature were patched in memory still passes. h is >= 0x70
    bytes starting at the header."""
    def u32(o):
        return struct.unpack_from("<I", h, o)[0]
    # every present section offset must land inside the file, past the header
    for o in (0x34, 0x3C, 0x44, 0x4C, 0x54, 0x5C, 0x64, 0x6C):
        v = u32(o)
        if v and not (0x70 <= v < fsz):
            return False
    # section counts must be sane
    for o in (0x38, 0x40, 0x48, 0x50, 0x58, 0x60):
        if u32(o) > 4_000_000:
            return False
    # a real app dex has strings and class definitions
    return u32(0x38) > 0 and u32(0x60) > 0


def resolvable_fraction(body):
    """Fraction of class_defs whose type descriptor resolves to a valid 'L...;'
    string. A healthy dex scores ~1.0. A dex whose pages were reclaimed or
    mismapped at capture scores near 0, which no checksum or map_list patch can
    repair. This is the signal that a `patched-hash` dex is actually corrupt and
    not just ART-rewritten. Returns None if the header is unreadable."""
    n = len(body)
    if n < 0x70:
        return None
    u32 = lambda o: struct.unpack_from("<I", body, o)[0]
    ss, so = u32(0x38), u32(0x3C)
    ts, to = u32(0x40), u32(0x44)
    cs, co = u32(0x60), u32(0x64)
    if not cs or co + cs * 32 > n:
        return None

    def uleb(o):
        s = 0
        while body[o] & 0x80:
            o += 1
            s += 1
            if s > 4:
                break
        return o + 1

    def type_name(ci):
        if ci >= ts:
            return None
        si = u32(to + ci * 4)
        if si >= ss:
            return None
        p = u32(so + si * 4)
        if not (0x70 <= p < n):
            return None
        o = uleb(p)
        e = body.find(b"\x00", o, o + 400)
        return body[o:e] if e > o else None

    good = 0
    for i in range(cs):
        nm = type_name(u32(co + i * 32))
        if nm and nm[:1] == b"L" and nm[-1:] == b";":
            good += 1
    return good / cs


def process_pgd(phys, pgd, out_dir, tag, loose=False, fill=False):
    """Reconstruct one process's user space; extract dexes. In loose mode a dex
    passes on header structure alone (checksum/signature may be patched in
    memory); in strict mode the hashes must verify. Returns (extracted,
    app_dex, marker_hits, pages)."""
    vmap = build_map(phys, pgd)
    if not vmap:
        return 0, 0, 0, 0
    extracted = app = marks = 0
    WIN = 16 << 20
    for rstart, rend in runs(list(vmap.keys())):
        va = rstart
        while va < rend:
            span = min(WIN, rend - va)
            buf = vread(phys, vmap, va, span, fill=True)[0]
            marks += buf.count(MARK)
            pos = 0
            while True:
                i = buf.find(MAGIC, pos)
                if i < 0:
                    break
                pos = i + 1
                hv = va + i
                hdr = vread(phys, vmap, hv, HDR)
                if not hdr:
                    continue
                vh = valid_header(hdr, 0)
                if not vh:
                    continue
                _, file_size, sig = vh
                if not structural_ok(hdr, file_size):
                    continue
                got = vread(phys, vmap, hv, file_size, fill=fill)
                if got is None:      # hole and not filling
                    print("  [~] dex va=0x%x %d bytes has an unmapped hole "
                          "(re-run with --fill-holes)" % (hv, file_size))
                    continue
                body, holes = got if fill else (got, 0)
                checksum = struct.unpack_from("<I", body, 8)[0]
                clean = (hashlib.sha1(body[0x20:]).digest() == sig and
                         (zlib.adler32(body[12:]) & 0xFFFFFFFF) == checksum)
                if not loose and not clean:
                    continue
                marked = MARK in body
                name = "dex_%s_%012x.dex" % (tag, hv)
                with open(os.path.join(out_dir, name), "wb") as w:
                    w.write(body)
                extracted += 1
                app += marked
                tags = []
                if not clean:
                    tags.append("patched-hash")
                if holes:
                    tags.append("%d hole-pages" % holes)
                health = None
                if marked:
                    tags.append("com/oceanwing/soundcore")
                    health = resolvable_fraction(body)
                    if health is not None:
                        tags.append("%.0f%% resolvable" % (health * 100))
                print("  [+] va=0x%x %d bytes -> %s%s"
                      % (hv, file_size, name, ("  [" + ", ".join(tags) + "]") if tags else ""))
                if health is not None and health < 0.9:
                    print("  [!] %s is DEGRADED: only %.0f%% of classes resolvable. Its body was "
                          "partly reclaimed or mismapped at capture and cannot be decompiled. "
                          "Re-capture with the app fully resident; see dex_health.py." %
                          (name, health * 100))
            va += span if span < WIN else (WIN - 0x1000)
    return extracted, app, marks, len(vmap)


def find_pgds_by_half(phys, khalf):
    """Every process kernel-PGD shares an identical upper (kernel) half. Scan the
    low dump for pages whose entries 256..511 match `khalf`, i.e. every process
    PGD."""
    out = []
    mm = phys.low
    n = phys.lowsize
    pa = 0
    while pa + 0x1000 <= n:
        if mm[pa + 0x800:pa + 0x1000] == khalf:
            out.append(pa)
        pa += 0x1000
    return out


def find_pgds(phys, seed_pgd):
    """Locate all process PGDs using a seed CR3's kernel half as the fingerprint.
    Returns [] if the seed page is not in the dump (e.g. a CR3 that points above
    the dumped range)."""
    d = phys.read(seed_pgd & M4K, 4096)
    if not d:
        return []
    return find_pgds_by_half(phys, bytes(d[0x800:0x1000]))


def _all_entries_plausible(block, phys_max):
    """Parse a 2 KB block as 256 8-byte page-table entries. Return (present,
    plausible) counts. A page-table page has every present entry pointing to a
    real physical frame with sane reserved bits; a random data page does not."""
    present = plausible = 0
    for i in range(0, len(block), 8):
        e = int.from_bytes(block[i:i + 8], "little")
        if e & 1:                            # present
            present += 1
            pa = e & 0x000FFFFFFFFFF000
            if 0 < pa < phys_max and (e & 0x07F0000000000000) == 0:
                plausible += 1
    return present, plausible


def auto_kernel_half(phys):
    """Recover the shared kernel half with no CR3 at all. It is identical in every
    process PGD, so among pages that STRUCTURALLY look like a PGD (a sparse user
    half and a kernel half whose every present entry is a valid PTE) it is by far
    the most common upper half. This makes reassembly independent of which CPU's
    CR3 was captured, and of whether that CR3 was even in the dump. Returns None if
    no confident kernel half is found."""
    from collections import Counter
    mm = phys.low
    n = phys.lowsize
    phys_max = 1 << 40
    counts = Counter()
    sample = {}
    pa = 0
    while pa + 0x1000 <= n:
        low = mm[pa:pa + 0x800]
        z = low.count(0)
        # user half must be sparse (few entries) but not empty
        if 0x800 - 512 <= z < 0x800:
            up = mm[pa + 0x800:pa + 0x1000]
            if any(up):
                upres, uok = _all_entries_plausible(up, phys_max)
                if upres and upres == uok and upres <= 64:
                    lpres, lok = _all_entries_plausible(low, phys_max)
                    if lpres and lpres == lok and lpres <= 64:
                        h = hash(bytes(up))
                        counts[h] += 1
                        if h not in sample:
                            sample[h] = bytes(up)
        pa += 0x1000
    if not counts:
        return None
    h, c = counts.most_common(1)[0]
    if c < 4:                                # a real kernel half is shared by many PGDs
        return None
    return sample[h]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ram")
    ap.add_argument("--cr3", nargs="+",
                    help="one or more CR3 seeds (kernel-half fingerprint). Pass every CPU's CR3 "
                         "from 'info registers -a'; the first that resolves PGDs is used. If none "
                         "resolve (or none given), the kernel half is auto-detected from the dump.")
    ap.add_argument("--scan-all", action="store_true", help="find & reconstruct every process PGD")
    ap.add_argument("--pgd", help="reconstruct just this one process PGD (e.g. 0x9c000)")
    ap.add_argument("--loose", action="store_true",
                    help="accept dexes on header structure alone (in-memory dexes often have "
                         "patched checksum/signature)")
    ap.add_argument("--fill-holes", action="store_true",
                    help="zero-fill unmapped pages so a dex spanning a hole is still written")
    ap.add_argument("--highmem")
    ap.add_argument("--lowsize")
    ap.add_argument("--out", default="carved_virt")
    args = ap.parse_args()

    cr3s = [int(x, 16) for x in (args.cr3 or [])]
    lowsize = int(args.lowsize, 0) if args.lowsize else None
    phys = Phys(args.ram, args.highmem, lowsize)
    os.makedirs(args.out, exist_ok=True)

    if args.pgd:
        pgd = int(args.pgd, 16)
        print("[*] reconstructing PGD 0x%x (loose=%s fill=%s) ..."
              % (pgd & M4K, args.loose, args.fill_holes))
        e, a, m, pg = process_pgd(phys, pgd, args.out, "%012x" % (pgd & M4K),
                                  loose=args.loose, fill=args.fill_holes)
        print("[=] %d dex extracted, %d with app package, %d marker hits, %.0f MB"
              % (e, a, m, pg * 4096 / 1e6))
        return 0

    if not args.scan_all:
        if not cr3s:
            print("[!] single-PGD mode needs a --cr3 (the app PGD). Use --scan-all to auto-find it.")
            return 1
        cr3 = cr3s[0]
        print("[*] reconstructing single PGD 0x%x ..." % (cr3 & M4K))
        e, a, m, pg = process_pgd(phys, cr3, args.out, "%012x" % (cr3 & M4K),
                                  loose=args.loose, fill=args.fill_holes)
        print("[=] %d dex, %d app dex, %d marker hits, %d pages" % (e, a, m, pg))
        if a == 0 and m == 0:
            print("[!] this process has no app data. Re-run with --scan-all.")
        return 0

    # Try each provided CR3 seed and keep the one that yields the MOST PGDs. A seed
    # above the dumped range yields nothing; a stale/garbage CR3 may yield a few by
    # chance, but the real kernel half is shared by every process so it resolves the
    # full set. Stop early once a seed clearly hits that set.
    pgds = []
    for seed in cr3s:
        pg = find_pgds(phys, seed)
        print("[~] CR3 seed 0x%x -> %d PGD(s)" % (seed & M4K, len(pg)))
        if len(pg) > len(pgds):
            pgds = pg
        if len(pgds) >= 8:                    # the shared kernel half, not a fluke
            break
    if len(pgds) < 4:
        print("[*] CR3 seeds gave few PGDs; auto-detecting the kernel half from the dump ...")
        khalf = auto_kernel_half(phys)
        if khalf:
            cand = find_pgds_by_half(phys, khalf)
            if len(pgds) < len(cand) <= 4096:   # better, and a sane AVD process count
                pgds = cand
                print("[*] auto-detected kernel half -> %d candidate PGD(s)" % len(pgds))
            else:
                print("[!] auto-detect gave %d PGDs, keeping %d" % (len(cand), len(pgds)))
    print("[*] using %d candidate PGD(s)" % len(pgds))
    if not pgds:
        print("[!] could not locate any process PGD. If the app dex sits above the dumped "
              "range, re-dump every RAM bank (capture.sh does this via 'info mtree -f').")
    total_app = 0
    for pgd in pgds:
        e, a, m, pg = process_pgd(phys, pgd, args.out, "%012x" % pgd,
                                  loose=args.loose, fill=args.fill_holes)
        if a or m:
            print("[proc pgd=0x%x] %d dex, %d APP dex, %d marker hits, %.0f MB"
                  % (pgd, e, a, m, pg * 4096 / 1e6))
        total_app += a
    print("\n[=] recovered %d app dex into %s" % (total_app, args.out))
    if total_app == 0:
        print("[!] no app dex validated. Re-run targeting the app process with loose "
              "structural matching:  --pgd 0x9c000 --loose --fill-holes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
