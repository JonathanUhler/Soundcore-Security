#!/usr/bin/env python3
"""Report the structural health of a (possibly in-memory) dex. Two independent
signals are printed, and both matter.

  resolv%  fraction of class_def type descriptors that resolve to an 'L...;'
           string. This measures whether the index tables (string_ids, type_ids,
           class_defs) survived the capture. Class names are not code_items, so a
           dex can score ~100% here and still have empty method bodies.

  code%    fraction of large code_items whose insns are substantially present.
           ijiami's method-extraction packer keeps the code_item header
           (registers, insns_size) but nulls the instruction body, restoring it
           on demand only when a method runs. An extracted body reads back as a
           fixed 1-2 word stub ("return null") padded with zeros for the original
           insns_size. That fixed stub is a large fraction of a short method but a
           tiny fraction of a long one, so only code_items of at least 16 code
           units are discriminating. Among those, a real body is >25% non-zero and
           a stub is well under. code% is the fraction of discriminating code_items
           that are present, so it reads ~0% for a fully extracted dex (only the
           <clinit>s that ran at class verification survive) and ~100% for a dex
           whose bodies were never extracted or were all restored.

A capture whose pages were reclaimed or mismapped scores near 0% on resolv%,
which no checksum or map_list patch can fix. A structurally intact but method-
extracted copy scores ~100% resolv% but low code%. Only a copy that is high on
both is fully decompilable."""
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
    # Code integrity: walk each class_data_item, then each encoded_method, and
    # measure how much of its code_item's insns survived. Count a body as present
    # when more than 25% of its instruction bytes are non-zero. A real body sits
    # well above that (dense bytecode); an extracted body sits near 0% (a short
    # stub padded with zeros for the original insns_size).
    total_code = nz_code = 0
    budget = 1_000_000                             # cap total encoded members, so a corrupt
    for i in range(cs):                            # dex with garbage counts cannot hang the scan
        if budget <= 0: break
        cdo = u32(co_ + i * 32 + 24)               # class_data_off
        if not (0x70 <= cdo < n): continue
        try:
            o = cdo
            sf, o = uleb(o); inf, o = uleb(o); dm, o = uleb(o); vm, o = uleb(o)
            if sf > 65536 or inf > 65536 or dm > 65536 or vm > 65536:
                continue                           # garbage class_data (corrupt/encrypted copy)
            budget -= sf + inf + dm + vm
            for _ in range(sf + inf):              # encoded_field: idx_diff, access_flags
                _, o = uleb(o); _, o = uleb(o)
            for _ in range(dm + vm):               # encoded_method: idx_diff, access, code_off
                _, o = uleb(o); _, o = uleb(o); coff, o = uleb(o)
                if coff == 0: continue             # abstract or native, no body by design
                if coff + 16 > n: continue
                isz = u32(coff + 12)               # insns_size, in 16-bit code units
                if not (16 <= isz <= 300000): continue  # too short to judge, or garbage-huge
                a, b = coff + 16, coff + 16 + isz * 2
                if b > n: continue                 # claims more bytes than the file holds, invalid
                total_code += 1
                seg = d[a:b]
                if (len(seg) - seg.count(0)) > 0.25 * len(seg): nz_code += 1
        except Exception:
            continue
    mono = sum(1 for i in range(1, ss) if u32(so_ + i * 4) >= u32(so_ + (i - 1) * 4))
    PAGE = 0x1000
    zp = sum(1 for pg in range(0, n, PAGE) if d[pg:pg+PAGE].count(0) == min(PAGE, n-pg))
    return dict(name=os.path.basename(path), size=n, classes=cs,
                resolvable=good, resolvable_pct=100*good/max(1,cs),
                code_items=total_code, code_nonzero=nz_code,
                code_pct=100*nz_code/max(1,total_code),
                mono_pct=100*mono/max(1,ss), zero_page_pct=100*zp/((n+PAGE-1)//PAGE))

if __name__ == '__main__':
    print(f"{'dex':40s} {'size':>9} {'classes':>8} {'resolv%':>8} {'code%':>7} "
          f"{'mono%':>6} {'zeropg%':>7}  verdict")
    for p in sys.argv[1:]:
        h = health(p)
        if not h: print(f"{os.path.basename(p):40s}  not a dex"); continue
        # USABLE needs both the index tables and most method bodies. A dex that
        # resolves names but is missing code is STRUCT-ONLY: good for the API
        # surface, useless for the signing bytecode.
        if h['resolvable_pct'] > 90 and h['code_pct'] > 90: v = 'USABLE'
        elif h['resolvable_pct'] > 90:                      v = 'STRUCT-ONLY'
        elif h['resolvable_pct'] > 40:                      v = 'DEGRADED'
        else:                                               v = 'UNUSABLE'
        print(f"{h['name'][:40]:40s} {h['size']:>9} {h['classes']:>8} "
              f"{h['resolvable_pct']:>7.1f}% {h['code_pct']:>6.1f}% {h['mono_pct']:>5.0f}% "
              f"{h['zero_page_pct']:>6.1f}%  {v}")
