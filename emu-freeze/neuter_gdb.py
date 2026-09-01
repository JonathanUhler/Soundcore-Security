# Sourced by gdb (see neuter.sh). Keeps the ijiami-packed app alive past its
# emulator-detection suicide by intercepting its process-death syscalls from the
# QEMU gdbstub -- a layer below the guest, so the anti-tamper (libexec.so
# anti-Frida, drisk anti-debug, libijm-emulator) cannot observe it. The
# breakpoints sit on guest *kernel* code the app cannot checksum.
#
# Two things this driver gets right that a naive version does not:
#
#   Scope. Neutering fatal signals for every process but init starves
#   system_server/zygote and the AVD reboots itself. So it scopes tightly to the
#   Soundcore process tree, tracked live via a pid file neuter.sh refreshes (so
#   it follows the ijiami watchdog re-exec without pinning a stale pid, and
#   touches nothing else in the guest).
#
#   Cost. exit_group/exit/do_group_exit fire across the WHOLE guest, constantly.
#   A breakpoint on them stops the VM on every hit for a slow gdbstub round-trip,
#   which starves the guest so hard the app never launches. So only the
#   low-frequency kill-family syscalls are armed up front; the death traps are
#   armed LAZILY, the moment the app first tries to signal-kill itself, and
#   self-disable once the suicide window closes -- restoring full guest speed.
#
# Death vectors covered, for the app only:
#   kill / tkill / tgkill / rt_sigqueueinfo / rt_tgsigqueueinfo / pidfd_send_signal
#       -> fatal signal argument rewritten to 0  (armed up front, cheap).
#   exit_group  (voluntary whole-process exit, e.g. System.exit / _exit)
#       -> the syscall is skipped (a synthesized return 0 to userspace), but only
#          from the app's own code region, learned from a blocked app kill.
#   do_group_exit  (the funnel every death reaches)
#       -> never blocked; a tripwire that reports how a death that slips through
#          happened (signal N vs clean exit).
#
# Modes:
#   MODE=neuter   (default) block the app's suicide; report app deaths that slip.
#   MODE=diagnose block nothing; log every vector and its userspace caller PC.
# EAGER=1 arms the death traps up front instead of lazily -- use only if the app
# dies without first making a kill syscall (its first vector is a raw fault), and
# expect the guest to run slowly.
#
# Env: GDB_REMOTE, ARCH (x86_64|aarch64), MODE, WINDOW (death-trap lifetime,
#      seconds), APP_PIDS_FILE and/or APP_PIDS, ALL (reboot-prone, opt-in),
#      NEUTER_EXIT, EXITGROUP_ALWAYS, EAGER, DEBUG, and the *_ADDR guest-kernel
#      addresses neuter.sh resolves from kallsyms.
import os
import struct
import sys
import time

import gdb

U64 = (1 << 64) - 1

REMOTE = os.environ.get("GDB_REMOTE", "127.0.0.1:1234")
ARCH = os.environ.get("ARCH", "x86_64")
MODE = os.environ.get("MODE", "neuter")
DEBUG = bool(os.environ.get("DEBUG"))
WINDOW = float(os.environ.get("WINDOW", "30"))
NEUTER_EXIT = bool(os.environ.get("NEUTER_EXIT"))
EXITGROUP_ALWAYS = bool(os.environ.get("EXITGROUP_ALWAYS"))
EAGER = bool(os.environ.get("EAGER"))
ALL = bool(os.environ.get("ALL"))
APP_PIDS_FILE = os.environ.get("APP_PIDS_FILE") or None

# Signals whose default action terminates the process, i.e. the ones a suicide
# would use. Utility/job-control signals are left alone.
FATAL = {3, 4, 5, 6, 7, 8, 9, 11, 15, 16, 24, 25, 31}

DENY = {1}  # never touch init


def _static_pids():
    out = set()
    for src in (os.environ.get("APP_PIDS", ""), os.environ.get("APP_PID", "")):
        for tok in src.replace(" ", ",").split(","):
            if tok.strip().isdigit():
                out.add(int(tok.strip()))
    return out


# Per-arch calling convention. The __x64_sys_*/__arm64_sys_* wrappers take a
# single `struct pt_regs *` (rdi / x0); the userspace syscall args and the
# return-to-userspace PC live inside that pt_regs at these byte offsets. Plain
# kernel functions such as do_group_exit take their int arg directly in the
# first arg register.
if ARCH == "aarch64":
    GDB_ARCH = "aarch64"
    PTR = "x0"            # holds pt_regs* at a syscall wrapper entry
    ARG0_REG = "x0"       # first arg of a plain kernel function
    A0, A1, A2 = 0, 8, 16
    IP_OFF, SP_OFF = 256, 248
    RET_REG, RETVAL_REG, PC_REG = "lr", "x0", "pc"
else:
    GDB_ARCH = "i386:x86-64"
    PTR = "rdi"
    ARG0_REG = "rdi"
    A0, A1, A2 = 112, 104, 96   # pt_regs.di / .si / .dx
    IP_OFF, SP_OFF = 128, 152   # pt_regs.ip / .sp
    RET_REG, RETVAL_REG, PC_REG = None, "rax", "rip"

# Code-region granularity for attributing an exit_group to the app: 16 MB. A
# blocked app kill records its caller's region; an exit_group is only skipped if
# it comes from a recorded region. Distinct ASLR'd processes land in different
# regions, so this never catches a system process's exit.
REGION_SHIFT = 24


def log(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def rd_u64(a):
    return struct.unpack("<Q", bytes(gdb.selected_inferior().read_memory(a & U64, 8)))[0]


def wr_u64(a, v):
    gdb.selected_inferior().write_memory(a & U64, struct.pack("<Q", v & U64))


def reg(name):
    return int(gdb.parse_and_eval("$" + name)) & U64


def setreg(name, val):
    gdb.execute("set $%s = %d" % (name, val & U64))


def kaddr(env):
    v = os.environ.get(env, "").strip()
    return v if v else None


class State:
    pids = set()             # live app pid set (static seed + file + blocked targets)
    regions = set()          # code regions confirmed to be the app's
    armed_until = 0.0        # death traps live / deaths reported while now < this
    exit_skips = {}          # caller ip -> times skipped, to catch a spin loop
    blocked = 0
    last_read = 0.0
    last_death = (None, 0.0)  # (sig, ts) for a light throttle
    sticky = set()           # pids seen via a blocked kill, to bridge a poll gap
    death_bps = {}           # env name -> gdb.Breakpoint, armed lazily
    death_announced = False


def refresh_pids():
    """Re-read the live app pid file, throttled. Keep the last non-empty set so a
    momentary empty read during the watchdog re-exec does not open a gap."""
    if not APP_PIDS_FILE:
        return
    now = time.time()
    if now - State.last_read < 0.2:
        return
    State.last_read = now
    try:
        with open(APP_PIDS_FILE) as f:
            s = {int(x) for x in f.read().split() if x.isdigit()}
    except (OSError, ValueError):
        return
    if s:
        State.pids = s | State.sticky


def scoped(tgt):
    """Whether pid `tgt` is in scope for neutering."""
    if tgt in DENY:
        return False
    if ALL:
        return True
    refresh_pids()
    return tgt in State.pids


def arm_window():
    State.armed_until = time.time() + WINDOW


def armed():
    return EXITGROUP_ALWAYS or time.time() < State.armed_until


def synth_return(retval=0):
    """Make the current kernel function return `retval` to its caller without
    running its body. At a function's first instruction the return address is on
    the stack (x86) or in LR (arm64), so we simulate a `ret`."""
    if ARCH == "aarch64":
        setreg(PC_REG, reg(RET_REG))
        setreg(RETVAL_REG, retval)
    else:
        rsp = reg("rsp")
        setreg("rip", rd_u64(rsp))
        setreg("rsp", rsp + 8)
        setreg(RETVAL_REG, retval)


def arm_death_traps():
    """Lazily insert the broad exit_group/do_group_exit (and optional exit)
    breakpoints. Called the moment the app first tries to signal-kill itself, so
    these hot, guest-wide paths are only breakpointed for the brief suicide
    window -- never at startup, where they would starve the guest and stop the
    app launching. Idempotent: re-enables traps a prior window disabled."""
    specs = [("EXITGROUP_ADDR", ExitGroupBP), ("DOGROUPEXIT_ADDR", DeathTrip)]
    if NEUTER_EXIT:
        specs.append(("EXIT_ADDR", ExitBP))
    for env, cls in specs:
        a = kaddr(env)
        if not a:
            continue
        bp = State.death_bps.get(env)
        if bp is None:
            State.death_bps[env] = cls("*" + a)
        elif not bp.enabled:
            bp.enabled = True
    if not State.death_announced:
        State.death_announced = True
        log("[*] app entered its death sequence -- armed exit_group%s + do_group_exit "
            "watchers (%ss window)." % ("/exit" if NEUTER_EXIT else "", int(WINDOW)))


def escalate():
    """Enter the armed window and bring up the death traps."""
    arm_window()
    arm_death_traps()


def death_trap_live(bp):
    """Shared gate for the lazily-armed traps: once the window closes, disable so
    the guest returns to full speed. Returns False when the trap should not act."""
    if not armed():
        bp.enabled = False
        return False
    return True


class SignalBP(gdb.Breakpoint):
    """A kill-family syscall. Rewrite a fatal signal to 0 when it targets the
    app. `target_pidfd` marks pidfd_send_signal, whose target is an fd we cannot
    map to a pid, so it is scoped by the armed window (app is mid-suicide)."""

    def __init__(self, spec, name, tgt_off, sig_off, target_pidfd=False):
        super(SignalBP, self).__init__(spec, gdb.BP_BREAKPOINT, internal=True)
        self.name = name
        self.tgt_off = tgt_off
        self.sig_off = sig_off
        self.target_pidfd = target_pidfd

    def stop(self):
        try:
            regs = reg(PTR)
            sig = rd_u64(regs + self.sig_off) & 0xFFFFFFFF
            tgt = None if self.target_pidfd else (rd_u64(regs + self.tgt_off) & 0xFFFFFFFF)
            ip = rd_u64(regs + IP_OFF)
        except gdb.error as e:
            if DEBUG:
                log("[dbg] %s: arg read failed: %s" % (self.name, e))
            return False

        if sig not in FATAL:
            return False

        # Is this the app? pidfd has no pid we can check, so only treat it as the
        # app while already mid-suicide.
        mine = armed() if self.target_pidfd else scoped(tgt)

        if MODE == "diagnose":
            if mine:
                log("[diag] %s target=%s sig=%d caller_ip=0x%x"
                    % (self.name, tgt if tgt is not None else "pidfd", sig, ip))
                if tgt is not None:
                    State.regions.add(ip >> REGION_SHIFT)
                escalate()   # bring up the death watchers to catch what follows
            return False

        if not mine:
            return False

        wr_u64(regs + self.sig_off, 0)
        State.blocked += 1
        if tgt is not None:
            State.sticky.add(tgt)
            State.pids.add(tgt)
        State.regions.add(ip >> REGION_SHIFT)   # learn the app's code region
        log("[block] %s(target=%s, sig=%d) -> sig 0   caller_ip=0x%x"
            % (self.name, tgt if tgt is not None else "pidfd", sig, ip))
        escalate()
        return False


class ExitGroupBP(gdb.Breakpoint):
    """Voluntary whole-process exit. Skip it (return 0 to userspace) only when it
    comes from the app's own code region, learned from a blocked app kill. Bail
    out if one caller spins on it, since endless skipping is a hang."""

    def __init__(self, spec, name="exit_group"):
        super(ExitGroupBP, self).__init__(spec, gdb.BP_BREAKPOINT, internal=True)
        self.name = name

    def stop(self):
        if not death_trap_live(self):
            return False
        try:
            regs = reg(PTR)
            code = rd_u64(regs + A0) & 0xFFFFFFFF
            ip = rd_u64(regs + IP_OFF)
        except gdb.error:
            return False

        if MODE == "diagnose":
            log("[diag] %s code=%d caller_ip=0x%x region=0x%x"
                % (self.name, code, ip, ip >> REGION_SHIFT))
            return False

        if not (EXITGROUP_ALWAYS or (ip >> REGION_SHIFT) in State.regions):
            if DEBUG:
                log("[dbg] %s ip=0x%x not app region, letting it exit" % (self.name, ip))
            return False

        n = State.exit_skips.get(ip, 0) + 1
        State.exit_skips[ip] = n
        if n > 20:
            log("[warn] %s from ip=0x%x skipped %d times -- the app is spinning on "
                "exit, not recovering. Letting it through; this vector needs the "
                "caller neutralised, not the syscall." % (self.name, ip, n))
            return False

        synth_return(0)
        log("[block] %s(code=%d) skipped, returned 0   caller_ip=0x%x  (skip %d)"
            % (self.name, code, ip, n))
        return False


class ExitBP(gdb.Breakpoint):
    """Single-thread exit. Only armed under NEUTER_EXIT, for a main-thread-exit
    suicide. App-region-scoped like exit_group."""

    def __init__(self, spec, name="exit"):
        super(ExitBP, self).__init__(spec, gdb.BP_BREAKPOINT, internal=True)
        self.name = name

    def stop(self):
        if not death_trap_live(self):
            return False
        try:
            regs = reg(PTR)
            code = rd_u64(regs + A0) & 0xFFFFFFFF
            ip = rd_u64(regs + IP_OFF)
        except gdb.error:
            return False
        if MODE == "diagnose":
            log("[diag] %s code=%d caller_ip=0x%x" % (self.name, code, ip))
            return False
        if (ip >> REGION_SHIFT) not in State.regions:
            return False
        synth_return(0)
        log("[block] %s(code=%d) skipped   caller_ip=0x%x" % (self.name, code, ip))
        return False


class DeathTrip(gdb.Breakpoint):
    """do_group_exit: the funnel every death reaches, whatever the vector. Never
    blocks (too late to resume cleanly); reports the cause. The low 7 bits of the
    exit code carry the killing signal, distinguishing a signal death we failed
    to catch from a clean exit we failed to skip. Only live during the app's
    suicide window, so routine lmkd SIGKILLs of cached processes stay quiet."""

    def __init__(self, spec, name="do_group_exit"):
        super(DeathTrip, self).__init__(spec, gdb.BP_BREAKPOINT, internal=True)
        self.name = name

    def stop(self):
        if not death_trap_live(self):
            return False
        try:
            code = reg(ARG0_REG) & 0xFFFFFFFF
        except gdb.error:
            return False
        sig = code & 0x7F
        last_sig, last_ts = State.last_death
        now = time.time()
        if sig == last_sig and now - last_ts < 1.0:   # coalesce a burst
            return False
        State.last_death = (sig, now)
        if sig:
            log("[DEATH] do_group_exit: killed by SIGNAL %d (code=0x%x). A fatal "
                "signal reached the process WITHOUT a kill syscall we hook -- a "
                "deliberate fault (SIGSEGV/SIGILL/SIGABRT), a seccomp kill, or a "
                "kernel-internal kill. Run MODE=diagnose to see the app PC." % (sig, code))
        else:
            log("[DEATH] do_group_exit: clean exit, code %d, from an exit path not "
                "attributed to the app region." % (code >> 8))
        return False


State.pids = _static_pids()

gdb.execute("set pagination off")
# Pin the architecture before AND after connecting, or the 64-bit register block
# parses as 32-bit (same gotcha freeze_gdb.py documents).
gdb.execute("set architecture " + GDB_ARCH)
gdb.execute("target remote " + REMOTE)
gdb.execute("set architecture " + GDB_ARCH)

# Arm ONLY the low-frequency kill-family syscalls up front. These are cheap
# enough to leave always-on (the old flow did) and let the app launch normally.
# The broad exit_group/do_group_exit/exit traps are armed lazily by escalate(),
# the instant the app first tries to kill itself -- see arm_death_traps().
armed_count = 0
for env, name, to, so in (
    ("KILL_ADDR", "kill", A0, A1),
    ("TKILL_ADDR", "tkill", A0, A1),
    ("TGKILL_ADDR", "tgkill", A0, A2),
    ("RTSIG_ADDR", "rt_sigqueueinfo", A0, A1),
    ("RTTGSIG_ADDR", "rt_tgsigqueueinfo", A0, A2),
):
    a = kaddr(env)
    if a:
        SignalBP("*" + a, name, to, so)
        armed_count += 1

a = kaddr("PIDFD_ADDR")
if a:
    SignalBP("*" + a, "pidfd_send_signal", A0, A1, target_pidfd=True)
    armed_count += 1

if armed_count == 0:
    raise gdb.GdbError("no kill syscall addresses provided (neuter.sh resolves them from kallsyms)")

if EAGER:
    escalate()   # for the rare case the first death vector is a raw fault, not a kill

if ALL:
    scope = "ALL processes but init (reboot-prone)"
elif APP_PIDS_FILE:
    scope = "app pid file %s (live, follows re-exec)" % APP_PIDS_FILE
elif State.pids:
    scope = "static pids " + ",".join(map(str, sorted(State.pids)))
else:
    scope = "NONE -- no pid source; nothing will be blocked (set APP_PIDS_FILE/APP_PIDS/ALL)"

log("[*] neuter armed: %d kill-family trap(s) up front, mode=%s, arch=%s, window=%ss."
    % (armed_count, MODE, ARCH, int(WINDOW)))
log("[*] death traps (exit_group/do_group_exit) arm lazily on first suicide, to keep the guest fast.")
log("[*] scope: %s" % scope)
log("[*] Continuing. Watch for [block] (suicide stopped) and [DEATH] (slipped through). Ctrl-C to detach.")
gdb.execute("continue")
