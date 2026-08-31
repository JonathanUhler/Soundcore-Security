# Sourced by gdb (see freeze.sh). Keeps the ijiami-packed app from completing its
# emulator-check suicide, so its decrypted dex can be captured.
#
# MODE=neuter (default): the signal syscalls (kill/tkill/tgkill/rt_sigqueueinfo/
#   rt_tgsigqueueinfo) have their signal argument rewritten to 0 for the app, so
#   no fatal signal lands. A voluntary exit_group/exit cannot be no-oped, so once
#   the app starts trying to die those are armed and the next one HALTS the VM.
# MODE=freeze: halt the whole VM at the app's first fatal kill. The app is still
#   alive (we stop at the syscall entry, before the signal is delivered) with its
#   memory intact, so you can snapshot guest RAM from the QEMU monitor. This is
#   the most reliable capture because it sidesteps the exit_group fallback.
#
# The breakpoints are on kernel code the app cannot checksum, so this stays
# invisible to every in-guest anti-tamper layer.
#
# Env: GDB_REMOTE, APP_PID, MODE, ARCH(x86_64|aarch64), DEBUG_TRAP, and the
#      *_ADDR kernel addresses (freeze.sh fills these from kallsyms.txt).
import os
import struct

import gdb

REMOTE = os.environ.get("GDB_REMOTE", "127.0.0.1:1234")
APP_PID = os.environ.get("APP_PID")
MODE = os.environ.get("MODE", "neuter")
ARCH = os.environ.get("ARCH", "x86_64")
DEBUG = os.environ.get("DEBUG_TRAP")
app_pid = int(APP_PID) if APP_PID else None

U64 = (1 << 64) - 1
GDB_ARCH = "aarch64" if ARCH == "aarch64" else "i386:x86-64"
if ARCH == "aarch64":
    ARGREG, A0, A1, A2 = "x0", 0, 8, 16
else:
    ARGREG, A0, A1, A2 = "rdi", 112, 104, 96
FATAL = {3, 4, 6, 8, 9, 11, 15, 24}


def rd_u64(a):
    return struct.unpack("<Q", bytes(gdb.selected_inferior().read_memory(a & U64, 8)))[0]


def wr_u64(a, v):
    gdb.selected_inferior().write_memory(a & U64, struct.pack("<Q", v))


def gread(addr, n):
    """Read n bytes of guest memory in chunks (the current context maps the app's
    user pages, since a syscall breakpoint runs in kernel mode with the process
    page tables active)."""
    inf = gdb.selected_inferior()
    out = bytearray()
    off = 0
    while off < n:
        c = min(1 << 20, n - off)
        out += bytes(inf.read_memory((addr + off) & U64, c))
        off += c
    return bytes(out)


def dump_dex_regions_from_maps(maps_path, out_dir):
    """Using a /proc/<pid>/maps snapshot captured while the app was alive, dump
    each dalvik dex region (by name, or whose bytes start with the dex magic)
    from the app's VIRTUAL memory, so the bytes are contiguous and carve cleanly."""
    import os
    os.makedirs(out_dir, exist_ok=True)
    got = 0
    for line in open(maps_path, errors="replace"):
        p = line.split()
        if len(p) < 2 or p[1][:1] != "r":
            continue
        try:
            s, e = (int(x, 16) for x in p[0].split("-"))
        except ValueError:
            continue
        length = e - s
        if length <= 0:
            continue
        name = p[5] if len(p) >= 6 else ""
        nm = name.lower()
        want = ("dalvik" in nm and "dex" in nm) or "inmemorydex" in nm or nm.endswith(".dex")
        if not want:
            if length > 64 * 1024 * 1024:
                continue  # don't magic-probe/dump the huge heap regions
            try:
                want = gread(s, 4) == b"dex\n"
            except Exception:
                want = False
        if not want:
            continue
        try:
            data = gread(s, length)
        except Exception as ex:
            print("  skip 0x%x (%s)" % (s, ex))
            continue
        fn = os.path.join(out_dir, "region_%x.bin" % s)
        with open(fn, "wb") as w:
            w.write(data)
        got += 1
        print("  dumped 0x%x %d bytes -> %s" % (s, length, fn))
    print("[*] dumped %d dex region(s) to %s" % (got, out_dir))


_exit_armed = [False]


def arm_exit_traps():
    if _exit_armed[0]:
        return
    got = 0
    for env, nm in (("EXITGROUP_ADDR", "exit_group"), ("EXIT_ADDR", "exit")):
        a = os.environ.get(env)
        if a:
            ExitTrap("*" + a, nm)
            got += 1
    if got:
        _exit_armed[0] = True
        print("[*] app is trying to die -- armed %d exit trap(s); the next exit "
              "halts the VM." % got)


class SigTrap(gdb.Breakpoint):
    def __init__(self, spec, name, tgt_off, sig_off):
        super(SigTrap, self).__init__(spec, gdb.BP_BREAKPOINT)
        self.name = name
        self.tgt_off = tgt_off
        self.sig_off = sig_off

    def stop(self):
        try:
            regs = int(gdb.parse_and_eval("$" + ARGREG)) & U64
            tgt = rd_u64(regs + self.tgt_off) & 0xFFFFFFFF
            sig = rd_u64(regs + self.sig_off) & 0xFFFFFFFF
        except Exception as e:
            if DEBUG:
                print("[hit] %s (arg read failed: %s)" % (self.name, e))
            return False
        if DEBUG:
            print("[hit] %s target=%d sig=%d" % (self.name, tgt, sig))
            return False
        if sig not in FATAL:
            return False
        if app_pid is not None and tgt != app_pid:
            return False
        if MODE == "freeze":
            print("[freeze] %s(pid=%d, sig=%d) -- VM halted." % (self.name, tgt, sig))
            maps = os.environ.get("DUMP_MAPS")
            if maps and os.path.exists(maps):
                print("[*] dumping the app's dex regions virtually from %s ..." % maps)
                try:
                    dump_dex_regions_from_maps(maps, os.environ.get("DUMP_DIR", "dumps_virt"))
                    print("[*] carve with: python3 carve_dex.py %s/*.bin --out carved"
                          % os.environ.get("DUMP_DIR", "dumps_virt"))
                except Exception as ex:
                    print("[!] region dump failed (%s). Fall back to the monitor RAM dump." % ex)
            else:
                print("    Dump guest RAM from the QEMU monitor, or set DUMP_MAPS to a "
                      "maps snapshot (see grab-maps.sh) for a clean virtual dump.")
            return True
        wr_u64(regs + self.sig_off, 0)
        print("[neuter] blocked %s to pid %d (sig %d -> 0)" % (self.name, tgt, sig))
        arm_exit_traps()
        return False


class ExitTrap(gdb.Breakpoint):
    def __init__(self, spec, name):
        super(ExitTrap, self).__init__(spec, gdb.BP_BREAKPOINT)
        self.name = name

    def stop(self):
        if DEBUG:
            print("[hit] %s" % self.name)
            return False
        print("[freeze] %s -- VM halted at a process exit. This is very likely the "
              "app finishing its suicide: dump guest RAM from the QEMU monitor "
              "(dump-guest-memory /tmp/ram.core), then 'continue'. If it turns out "
              "not to be the app, just 'continue'." % self.name)
        return True


def addr(env):
    v = os.environ.get(env)
    return v if v else None


gdb.execute("set pagination off")
# Pin the arch before connecting or the 64-bit register block parses as 32-bit.
gdb.execute("set architecture " + GDB_ARCH)
gdb.execute("target remote " + REMOTE)
gdb.execute("set architecture " + GDB_ARCH)

SIGSPECS = [
    ("KILL_ADDR", "kill", A0, A1),
    ("TKILL_ADDR", "tkill", A0, A1),
    ("TGKILL_ADDR", "tgkill", A0, A2),
    ("RTSIG_ADDR", "rt_sigqueueinfo", A0, A1),
    ("RTTGSIG_ADDR", "rt_tgsigqueueinfo", A0, A2),
]
n = 0
for env, nm, to, so in SIGSPECS:
    a = addr(env)
    if a:
        SigTrap("*" + a, nm, to, so)
        n += 1

# In neuter mode the exit traps are armed lazily, the moment the app first tries
# to signal-kill itself (so unrelated process exits don't halt us). In freeze
# mode we halt at the kill itself, so exits are not watched. DEBUG/TRAP_EXITGROUP
# arm them up front for observation.
if DEBUG or os.environ.get("TRAP_EXITGROUP"):
    arm_exit_traps()

if n == 0 and not _exit_armed[0]:
    raise gdb.GdbError("no syscall addresses provided (run find-kill-symbol.sh)")

print("[*] armed %d signal trap(s), mode=%s, app_pid=%s. Continuing (Ctrl-C to detach)..."
      % (n, MODE, app_pid))
gdb.execute("continue")
