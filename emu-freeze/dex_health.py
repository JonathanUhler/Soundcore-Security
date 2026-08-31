#!/usr/bin/env python3
"""Report the structural health of a (possibly in-memory) dex. A healthy dex
resolves ~100% of its class_def type descriptors to 'L...;' strings and has a
strictly increasing string_ids table. A capture whose pages were reclaimed or
mismapped scores near 0%, which no checksum or map_list patch can fix."""
import struct, sys, os

def health(path):
    d = open(path, 'rb').read(); n = len(d)
    if n < 0x70 or d[:4] != b'dex\n': return None
    u32 = lambda o: struct.unpack_from('<I', d, o)[0]
    ss, so_ = u32(0x38), u32(0x3c)
    ts, to_ = u32(0x40), u32(0x44)
    cs, co_ = u32(0x60), u32(0x64)
    def uleb(o):
        r = s = 0
        while True:
            b = d[o]; o += 1; r |= (b & 0x7f) << s
            if not (b & 0x80): break
            s += 7
        return r, o
    def gs(i):
        if i >= ss: return None
        p = u32(so_ + i * 4)
        if not (0x70 <= p < n): return None
        try:
            _, o = uleb(p); e = d.find(b'\x00', o, o + 400)
            return d[o:e].decode('utf-8', 'replace') if e > o else None
        except Exception: return None
    good = 0
    for i in range(cs):
        ci = u32(co_ + i * 32)
        if ci < ts:
            sname = gs(u32(to_ + ci * 4))
            if sname and sname[:1] == 'L' and sname[-1:] == ';': good += 1
    mono = sum(1 for i in range(1, ss) if u32(so_ + i * 4) >= u32(so_ + (i - 1) * 4))
    PAGE = 0x1000
    zp = sum(1 for pg in range(0, n, PAGE) if d[pg:pg+PAGE].count(0) == min(PAGE, n-pg))
    return dict(name=os.path.basename(path), size=n, classes=cs,
                resolvable=good, resolvable_pct=100*good/max(1,cs),
                mono_pct=100*mono/max(1,ss), zero_page_pct=100*zp/((n+PAGE-1)//PAGE))

if __name__ == '__main__':
    print(f"{'dex':40s} {'size':>9} {'classes':>8} {'resolv%':>8} {'mono%':>6} {'zeropg%':>7}  verdict")
    for p in sys.argv[1:]:
        h = health(p)
        if not h: print(f"{os.path.basename(p):40s}  not a dex"); continue
        v = 'USABLE' if h['resolvable_pct'] > 90 else ('DEGRADED' if h['resolvable_pct'] > 40 else 'UNUSABLE')
        print(f"{h['name'][:40]:40s} {h['size']:>9} {h['classes']:>8} "
              f"{h['resolvable_pct']:>7.1f}% {h['mono_pct']:>5.0f}% {h['zero_page_pct']:>6.1f}%  {v}")
