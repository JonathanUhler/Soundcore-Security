#!/usr/bin/env python3
"""Freeze the VM and snapshot every guest RAM bank, robustly for any AVD size.

A single `pmemsave 0 0x80000000` only works if all guest RAM sits in the low 2 GB.
It does not in general. The guest-physical map can place RAM above 2 GB, and a
larger guest splits RAM across the 4 GB hole. When the app's page tables or dex
pages fall outside the dump, the reassembler reads zero PGDs. This asks QEMU for
the real layout via `info mtree -f`, dumps each RAM bank, and reports every CPU's
CR3 (from `info registers -a`) so the reassembler can pick a seed that resolves.

Two emulator quirks are handled here:
  - The monitor parses the pmemsave filename as an expression, so an absolute path
    fails ("invalid char 'h'" on /home, "'t'" on /tmp). Bare filenames are used,
    and QEMU's cwd (where it writes them) is discovered from /proc.
  - `info mtree -f` lists firmware flash and device regions as 'ram' too. Only the
    segment starting at 0 (low bank) and the one at 0x100000000 (high bank) are
    taken; everything else is ignored.

Prints machine-readable lines for capture.sh:
    LOWFILE=<abs path>
    LOWSIZE=0x...             (size of the low bank, == the reassembler --lowsize)
    HIGHFILE=<abs path>       (only if a high bank exists, at phys 0x100000000)
    CR3S=0x.. 0x.. ...        (every distinct CPU CR3)
plus '# ...' diagnostic lines.

Usage: python3 snapshot.py HOST:PORT OUTDIR [FALLBACK_LOWSIZE]
"""
import os
import re
import sys

from mon import Monitor

RAM_LINE = re.compile(r"\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+\(prio[^,]*,\s*ram\):")
HIGH_BASE = 0x100000000


def parse_ram_ranges(mtree):
    """Every RAM leaf in the flat memory tree, deduped and sorted. `info mtree -f`
    prints one FlatView per CPU address space, so the same leaves appear many times
    and must be deduplicated."""
    out = set()
    for line in mtree.splitlines():
        m = RAM_LINE.match(line)
        if m:
            a, b = int(m.group(1), 16), int(m.group(2), 16)
            if b > a:
                out.add((a, b + 1))          # mtree ends are inclusive
    return sorted(out)


def segments(ranges, merge_gap=2 << 20):
    """Coalesce RAM leaves that overlap or are separated by a small gap (the main
    RAM is split into several leaves by the sub-1 MB VGA window), but never merge
    across the 4 GB line, so firmware flash just below 4 GB does not fuse onto the
    high bank."""
    segs = []
    for a, e in sorted(ranges):
        # merge on overlap (a < prev_end) or a small gap, unless it crosses 4 GB
        if segs and a - segs[-1][1] <= merge_gap and not (segs[-1][1] <= HIGH_BASE <= a):
            segs[-1][1] = max(segs[-1][1], e)
        else:
            segs.append([a, e])
    return [(a, e) for a, e in segs]


def banks(ranges, fallback_low):
    """The low bank is the RAM segment that starts at physical 0. The high bank is
    the segment that starts at 0x100000000. Firmware and device regions (which
    start elsewhere) are ignored."""
    segs = segments(ranges)
    low = next(((a, e) for a, e in segs if a == 0), None)
    high = next(((a, e) for a, e in segs if a == HIGH_BASE), None)
    low_end = low[1] if low else fallback_low
    return low_end, high, segs


def _listen_inode(port):
    for proc in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = open(proc).read().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            f = ln.split()
            if len(f) < 10 or f[3] != "0A":          # 0A = LISTEN
                continue
            try:
                if int(f[1].split(":")[1], 16) == port:
                    return f[9]
            except (ValueError, IndexError):
                continue
    return None


def find_qemu_cwd(port):
    """QEMU writes pmemsave files relative to its own cwd. Find that process by the
    monitor's listening socket and read its cwd, so we can locate the dumps."""
    inode = _listen_inode(port)
    if not inode:
        return None
    target = "socket:[%s]" % inode
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            for fd in os.listdir("/proc/%s/fd" % pid):
                try:
                    if os.readlink("/proc/%s/fd/%s" % (pid, fd)) == target:
                        return os.readlink("/proc/%s/cwd" % pid)
                except OSError:
                    continue
        except OSError:
            continue
    return None


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    host, port = sys.argv[1].rsplit(":", 1)
    port = int(port)
    outdir = sys.argv[2]
    fallback_low = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x80000000

    # Where QEMU will write the bare-named dumps. Fall back to our own cwd, then
    # the requested outdir, if the process cannot be found.
    qcwd = find_qemu_cwd(port) or os.getcwd()
    print("# qemu cwd: %s" % qcwd)

    m = Monitor(host, port)
    m.cmd("stop")
    ranges = parse_ram_ranges(m.cmd("info mtree -f"))
    low_end, high, segs = banks(ranges, fallback_low)
    print("# RAM segments: %s" % (", ".join("[0x%x,0x%x)" % s for s in segs) or "(none parsed)"))
    print("# low bank [0,0x%x)%s" % (low_end, ", high bank [0x%x,0x%x)" % high if high else ""))

    def dump(addr, size, name):
        """pmemsave to a bare filename (absolute paths break the monitor parser),
        then verify QEMU wrote it in its cwd. Returns the path on success, else ''."""
        resp = m.cmd("pmemsave 0x%x 0x%x %s" % (addr, size, name))
        path = os.path.join(qcwd, name)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            if resp.strip():
                print("# pmemsave note: %s" % resp.strip())
            return path
        print("# pmemsave 0x%x 0x%x -> %s FAILED: %s" %
              (addr, size, name, resp.strip() or "no file written"))
        return ""

    lowpath = dump(0, low_end, "ram-low.bin")
    if not lowpath and low_end != fallback_low:
        print("# retrying low bank at fallback size 0x%x ..." % fallback_low)
        low_end = fallback_low
        lowpath = dump(0, low_end, "ram-low.bin")
    if lowpath:
        print("LOWFILE=%s" % lowpath)
        print("LOWSIZE=0x%x" % low_end)
    else:
        print("# LOW BANK DUMP FAILED. If it is a write error, cd the emulator to a writable "
              "dir before launch; if a parse error, this monitor may need a different command.")

    if high:
        highpath = dump(HIGH_BASE, high[1] - HIGH_BASE, "ram-high.bin")
        if highpath:
            print("HIGHFILE=%s" % highpath)

    print("CR3S=%s" % " ".join(parse_cr3s(m.cmd("info registers -a"))))
    m.close()


def parse_cr3s(regs):
    seen, out = set(), []
    for v in re.findall(r"CR3\s*=\s*([0-9a-fA-F]+)", regs):
        iv = int(v, 16)
        if iv and iv not in seen:
            seen.add(iv)
            out.append("0x%x" % iv)
    return out


if __name__ == "__main__":
    main()
