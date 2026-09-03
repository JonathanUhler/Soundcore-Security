'use strict';
/*
 * anti-tamper.js  --  Defeat the JM/ijiami reinforcement SDK so the app survives
 * Frida jailed spawn on iOS 26 and runs to the firmware upgrade screen.
 *
 * Load this FIRST, during the spawn pause, before %resume:
 *   frida -U -f com.oceanwing.SoundCore.G8AW4BQ7RV -l scripts/ios-frida/anti-tamper.js
 *   (then, after "[anti-tamper] armed", type %resume)
 *
 * To also capture in the same session, append the other scripts:
 *   frida -U -f com.oceanwing.SoundCore.G8AW4BQ7RV \
 *     -l scripts/ios-frida/anti-tamper.js \
 *     -l scripts/ios-frida/network-hooks.js \
 *     -l scripts/ios-frida/crypto-hooks.js
 *
 * Design (see research/notes/2026-09-02_iOS-Anti-Tamper-Bypass/):
 *   The SDK is a detector -> result-flag -> dispatcher -> terminate pipeline. The
 *   one thing every path must do is terminate the process, so the core defense
 *   blocks the ways to terminate. The first on-device run proved the kill does NOT
 *   go through exit/_exit/_Exit/abort/kill/__pthread_kill or showAJMSafeExit, so
 *   this revision widens the net:
 *     - Layer 0  a CPU-trap catcher (brk/udf). Anti-tamper often "crashes itself"
 *                with an illegal instruction, which no function hook can see.
 *     - Layer 1  a termination-primitive net that also covers the low-level syscall
 *                stubs (__exit, __kill) and the modern terminate syscalls
 *                (abort_with_payload, terminate_with_reason), plus a log-only pass
 *                over the rest so the next run names the exact primitive.
 *     - Layer 2  neutralize the named UI kill funnel showAJMSafeExit(type:handler:).
 *     - Layer 3  observability tripwires on the JM/AC detection surface.
 *     - Layer 4  (optional) hide Frida's image from the dyld enumeration scanner.
 *   If a run still dies silently with no Layer 0/1 line, the kill is an inline
 *   `svc SYS_exit` that never calls a libc stub, and the next step is Stalker or a
 *   static patch of the detection routine. Also pull a crash report either way: a
 *   report with EXC_BREAKPOINT/BAD_INSTRUCTION means a trap (Layer 0 territory), no
 *   report means a clean exit syscall (Layer 1 territory).
 *
 * Ghidra anchors (preferred base 0x100000000, so runtime = mainModule.base + offset):
 *   0x188e94  SC_DKAlertCountDownView_showAJMSafeExit  (Swift impl)
 *   0x188fe8  -[DKAlertCountDownView showAJMSafeExitWithType:handler:]  (@objc thunk)
 *   0x1f288d4 JM_jailbreakPathScan  (native JB path scanner, sets result flag)
 */

var OFF = {
  showAJMSafeExit_swift: 0x188e94,
  showAJMSafeExit_thunk: 0x188fe8,
  jailbreakPathScan:     0x1f288d4
};

/* Keep NativeCallback and allocated objects alive for the process lifetime. */
var KEEP = [];

var mainModule = Process.mainModule || Process.enumerateModules()[0];
function rt(off) { return mainModule.base.add(off); }

/* Is a code address inside the main SoundCore image? Attributes a kill/trap. */
function inMainImage(addr) {
  try {
    return addr.compare(mainModule.base) >= 0 &&
           addr.compare(mainModule.base.add(mainModule.size)) < 0;
  } catch (e) { return false; }
}

function symbolize(addr) {
  try {
    var s = DebugSymbol.fromAddress(addr);
    if (s && s.name) return s.toString();
  } catch (e) {}
  var m = Process.findModuleByAddress(addr);
  if (m) return m.name + '!' + addr.sub(m.base) + '  (' + addr + ')';
  return '' + addr;
}

/* Resolve a global export across Frida 16 and 17 API differences. */
function findExport(name) {
  try {
    if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(name);
    if (typeof Module.getGlobalExportByName === 'function') {
      try { return Module.getGlobalExportByName(name); } catch (e) { return null; }
    }
    return Module.findExportByName(null, name);
  } catch (e) { return null; }
}

/* Print a labelled backtrace from a hook context, flag app-attributed frames. */
function reportKill(tag, ctx, returnAddr) {
  console.log('\n############ [anti-tamper] TERMINATION ' + tag + ' ############');
  var frames = [];
  try { frames = Thread.backtrace(ctx, Backtracer.ACCURATE); } catch (e) {}
  if (frames.length === 0 && returnAddr) frames = [returnAddr];
  var attributed = false;
  for (var i = 0; i < frames.length && i < 24; i++) {
    var inApp = inMainImage(frames[i]);
    if (inApp) attributed = true;
    console.log('   ' + (inApp ? '>>' : '  ') + ' ' + symbolize(frames[i]));
  }
  console.log('   caller in SoundCore image: ' + attributed +
              '   (true = the kill is the app, not the agent)');
}

/* --------------------------------------------------------------------------
 * Layer 0: executable-memory rescuer.
 * The device runs showed the real kill. The SDK strips execute permission from
 * its own hook-trampoline region when it detects the gum agent. recon.js installs
 * no hooks and still died the same way, so this is the SDK, not our Interceptor.
 * Every function routed through those trampolines then faults as an instruction
 * fetch (pc == fault-addr) on a now non-executable page. Two pages were seen,
 * 0x11323xxxx hit by the main thread's signal() in didFinishLaunching, and
 * 0x11531xxxx hit by a dispatch worker in +[NSFileHandle initialize], both holding
 * a valid `ldr x16,..; br x16` trampoline that reads fine but will not execute.
 *
 * The counter is to re-arm the page as executable and re-run the same instruction,
 * not to advance pc, which just walks the page as data. mprotect does not lower a
 * region's max protection, so Memory.protect can restore exec. Layer 0d covers the
 * one case it cannot, a mach_vm_protect that lowers max protection.
 * ------------------------------------------------------------------------ */
var PAGE = Process.pageSize;
var PAGE_MASK = ptr(PAGE - 1).not();
var reprot = {};         // page base -> times re-armed
var poisoned = {};       // page base string -> true, pages the SDK stripped of exec
var faultLog = 0;        // detailed log budget
var FAULT_CAP = 3000;    // stop handling after this many, so the session ends

// Restore exec on a poisoned code page. Try r-x first: these are code pages whose
// max protection is r-x, and the strip removed the current exec bit, so r-x is
// within max and succeeds, while rwx fails on W^X (cannot add write). Memory.protect
// reports failure by returning false, not by throwing, so check the return value.
function reArm(page) {
  var ok = false;
  try { ok = Memory.protect(page, PAGE, 'r-x'); } catch (e) {}
  if (!ok) { try { ok = Memory.protect(page, PAGE, 'rwx'); } catch (e) {} }
  return ok;
}

// NOTE: relocation into a Frida-allocated copy was tried and does not work on this
// process. iOS AMFI refuses to execute unsigned pages (no JIT entitlement), so the
// copy faults on its own first instruction, cascading forever. Reactive recovery of
// executable memory is not possible here. The only path is to PREVENT the strip.
Process.setExceptionHandler(function (details) {
  // Bulletproof and verbose. Everything is wrapped so the handler can never abort
  // silently (which, returning nothing, reads as false and lets debugserver suspend
  // the thread, the frozen home screen). It logs the result of Memory.protect,
  // including its boolean return, which the previous version ignored.
  var handled = false, note = 'unknown';
  try {
    var pc = details.context.pc;
    var fault = details.address;
    var isFetch = fault.equals(pc);
    if (isFetch) {
      var page = pc.and(PAGE_MASK);
      var k = page.toString();
      poisoned[k] = true;
      reprot[k] = (reprot[k] || 0) + 1;
      // Best effort in-place re-arm. This cannot truly win (the page is re-stripped,
      // and re-armed exec does not stick under AMFI), but it keeps the process from
      // dying instantly so the [Lprot] and detection diagnostics can be read. A cap
      // stops the infinite heartbeat so the session ends on its own.
      reArm(page);
      handled = faultLog < FAULT_CAP;
      if (reprot[k] === 20) {
        console.log('!! [L0] LIVELOCK on ' + page + ' (re-faulted 20x). Reactive recovery cannot ' +
                    'win on a non-JIT process. The fix must PREVENT the detection, not patch faults.');
      }
      note = 'fetch ' + page + ' n=' + reprot[k];
    } else {
      note = 'data pc=' + symbolize(pc) + ' fault-addr=' + fault + ' [not re-arming]';
    }
  } catch (outer) {
    note = 'HANDLER-ERROR ' + outer;
    handled = false;
  }
  if (faultLog < 10 || faultLog % 2000 === 0) console.log('@@ [L0] #' + faultLog + ' ' + note + (handled ? '' : '  -> give up'));
  faultLog++;
  return handled;
});
console.log('[L0] executable-memory rescuer armed (verbose; reports Memory.protect result)');

/* --------------------------------------------------------------------------
 * Layer 0b: anti-anti-debug. The fault only happens under a debugger, so the SDK
 * is checking for one and then taking a deliberate-fault branch. Jailed spawn runs
 * the app under debugserver, which sets P_TRACED and makes getppid the debugger's
 * pid. Lie about both, plus no-op ptrace, so the SDK does not see a debugger and
 * never takes the fault branch. This may prevent the crash at its source, which is
 * cleaner than riding it in Layer 0.
 * ------------------------------------------------------------------------ */
(function () {
  // sysctl KERN_PROC,KERN_PROC_PID -> clear the P_TRACED (0x800) bit in p_flag.
  var pS = findExport('sysctl');
  if (pS && !pS.isNull()) {
    Interceptor.attach(pS, {
      onEnter: function (a) {
        this.name = a[0]; this.oldp = a[2];
        try {
          this.isProc = this.name.readU32() === 1 &&        // CTL_KERN
                        this.name.add(4).readU32() === 14 && // KERN_PROC
                        this.name.add(8).readU32() === 1;    // KERN_PROC_PID
        } catch (e) { this.isProc = false; }
      },
      onLeave: function () {
        if (!this.isProc || !this.oldp || this.oldp.isNull()) return;
        try {
          var pflag = this.oldp.add(32);                     // offsetof(kinfo_proc, kp_proc.p_flag)
          var v = pflag.readU32();
          if (v & 0x800) { pflag.writeU32(v & ~0x800); console.log('[L0b] sysctl P_TRACED scrubbed'); }
        } catch (e) {}
      }
    });
    console.log('[L0b] sysctl anti-debug scrub armed');
  }
  // getppid -> 1 (launchd), the value expected for a normally launched app.
  var pG = findExport('getppid');
  if (pG && !pG.isNull()) {
    var cbG = new NativeCallback(function () { return 1; }, 'int', []);
    KEEP.push(cbG);
    Interceptor.replace(pG, cbG);
    console.log('[L0b] getppid -> 1');
  }
  // ptrace -> 0. Harmless here since Frida is already attached, but stops any
  // PT_DENY_ATTACH re-assertion the SDK might issue.
  var pP = findExport('ptrace');
  if (pP && !pP.isNull()) {
    var cbP = new NativeCallback(function () { return 0; }, 'int', ['int', 'int', 'pointer', 'int']);
    KEEP.push(cbP);
    Interceptor.replace(pP, cbP);
    console.log('[L0b] ptrace -> 0 (no-op)');
  }
  // Mach exception ports. debugserver claims the task/thread exception ports on
  // jailed spawn, and Frida's agent is NOT a dyld image (only libffi-trampolines is
  // foreign), so the injection check is most likely reading the exception ports
  // rather than the image list. Report zero installed ports.
  //   *_get_exception_ports(target, mask, masks[], *count, ports[], behaviors[], flavors[])
  // The masks-count is arg index 3; zero it on return so it looks unhooked.
  ['task_get_exception_ports', 'thread_get_exception_ports',
   'task_get_exception_ports_info'].forEach(function (name) {
    var p = findExport(name);
    if (p === null || p.isNull()) return;
    Interceptor.attach(p, {
      onEnter: function (a) { this.cnt = a[3]; },
      onLeave: function () {
        try { if (this.cnt && !this.cnt.isNull()) this.cnt.writeU32(0); } catch (e) {}
      }
    });
    console.log('[L0b] masking ' + name);
  });
})();

/* --------------------------------------------------------------------------
 * Layer P: PREVENT the LIBRARY_INJECTION detection instead of reacting to its
 * sabotage. The kill is not a single call, it is the SDK branching onto a sabotage
 * path once it detects the gum agent, then re-stripping its own trampolines in a
 * loop. Blocking the symptoms cannot get us back to a normal boot. The detection
 * fires merely from the agent being loaded (recon.js, zero hooks, triggers it), and
 * APP_FIRM_LIBRARY_INJECTION walks the dyld image list. Hide Frida's images from
 * that enumeration so the check reports clean and the app takes its normal path.
 *
 * Index-remap technique. Compute the visible (non-Frida) image indices once during
 * the spawn pause, shrink _dyld_image_count, and remap the index argument of
 * _dyld_get_image_{name,header,vmaddr_slide} so the hidden entries are skipped. The
 * SDK resolves these by dlsym, which returns the same exports we hook here.
 * ------------------------------------------------------------------------ */
(function () {
  var cCount = findExport('_dyld_image_count');
  var cName  = findExport('_dyld_get_image_name');
  var cHdr   = findExport('_dyld_get_image_header');
  var cSlide = findExport('_dyld_get_image_vmaddr_slide');
  if (!cCount || !cName || !cHdr) { console.log('[P] dyld enumeration exports missing'); return; }

  var BAD = /frida|gum|gadget|cynject|substrate|libhooker/i;
  var badBase = {};
  // Diagnostic: list every module that is not obviously an Apple system library or
  // the app bundle. The Frida agent hides among these, so this names it for us.
  console.log('[P] foreign (non-system, non-app) modules:');
  try {
    Process.enumerateModules().forEach(function (m) {
      var p = m.path || '';
      var system = p.indexOf('/System/') === 0 || p.indexOf('/usr/lib/') === 0 ||
                   p.indexOf('/usr/') === 0 || p.indexOf('/Developer/') === 0;
      var app = p.indexOf('.app/') !== -1;
      if (BAD.test(m.name) || BAD.test(p)) badBase[m.base.toString()] = m.name || p;
      if (!system && !app) console.log('   ' + m.base + '  ' + (m.name || '?') + '  <-  ' + p);
    });
  } catch (e) { console.log('[P] enumerate failed: ' + e); }

  var realCount = new NativeFunction(cCount, 'int', []);
  var realName  = new NativeFunction(cName, 'pointer', ['int']);
  var realHdr   = new NativeFunction(cHdr, 'pointer', ['int']);

  var visible = [], hiddenNames = [];
  var n = realCount();
  for (var i = 0; i < n; i++) {
    var nm = ''; try { nm = realName(i).readUtf8String() || ''; } catch (e) {}
    var h = realHdr(i);
    var bad = BAD.test(nm) || (h && badBase[h.toString()]);
    if (bad) hiddenNames.push(nm || ('' + h)); else visible.push(i);
  }
  Interceptor.attach(cCount, { onLeave: function (r) { r.replace(ptr(visible.length)); } });
  function remap(fn) {
    Interceptor.attach(fn, {
      onEnter: function (a) {
        var i = a[0].toInt32();
        if (i >= 0 && i < visible.length) a[0] = ptr(visible[i]);
      }
    });
  }
  remap(cName); remap(cHdr); if (cSlide) remap(cSlide);
  if (hiddenNames.length) console.log('[P] dyld hiding armed, ' + n + ' -> ' + visible.length +
                                      ', hidden: ' + hiddenNames.join(', '));
  else console.log('[P] dyld hiding armed but NO Frida image matched (detection vector may differ)');
})();

/* --------------------------------------------------------------------------
 * Layer 0d and 0e: keep the SDK from stripping exec off its trampoline pages.
 * Layer 0 restores exec reactively after each fault, which is enough if the strip
 * is one-time. If the SDK re-strips on a timer, that races. These hooks stop the
 * strip at the source.
 *   0d  mach_vm_protect / vm_protect. Force the execute bit back whenever a call
 *       removes it, either from the current protection or from the max protection
 *       (set_maximum), which Layer 0 cannot undo.
 *   0e  mprotect. Force the execute bit back only when the call's range covers a
 *       page we have already seen fault (a known poisoned trampoline page), so
 *       normal read-only transitions elsewhere are left alone.
 * ------------------------------------------------------------------------ */
var protLog = 0;         // budget for verbose protection logging
function currentlyExec(addr) {
  try { var r = Process.findRangeByAddress(addr); return !!r && r.protection.indexOf('x') !== -1; }
  catch (e) { return false; }
}
// Prevent the exec strip at its source, and log every protection change so the strip
// call is visible. Force the execute bit back only when the call removes it from a
// page that is currently executable, or lowers max protection (set_maximum). That is
// targeted: ordinary read-only transitions on data pages are left untouched, because
// their range is not currently executable.
function guardProtect(name, addrIdx, lenIdx, protIdx, maxIdx) {
  var p = findExport(name);
  if (p === null || p.isNull()) { console.log('[Lprot] absent ' + name); return; }
  Interceptor.attach(p, {
    onEnter: function (a) {
      try {
        var prot = a[protIdx].toInt32();
        var removingExec = (prot & 4) === 0;
        var setMax = maxIdx >= 0 && a[maxIdx].toInt32() !== 0;
        var addr = a[addrIdx];
        var curX = currentlyExec(addr);
        if (protLog < 60) {
          protLog++;
          console.log('[Lprot] ' + name + ' addr=' + addr + ' len=' + a[lenIdx] + ' prot=' + prot +
                      (maxIdx >= 0 ? ' setmax=' + (setMax ? 1 : 0) : '') + ' curExec=' + curX +
                      (removingExec && (curX || setMax) ? '  -> KEEP EXEC' : ''));
        }
        if (removingExec && (curX || setMax)) a[protIdx] = ptr(prot | 4);
      } catch (e) {}
    }
  });
  console.log('[Lprot] guarding ' + name);
}
//            name              addrIdx lenIdx protIdx maxIdx
guardProtect('mprotect',        0,      1,     2,      -1);
guardProtect('mach_vm_protect', 1,      2,     4,       3);
guardProtect('vm_protect',      1,      2,     4,       3);

/* --------------------------------------------------------------------------
 * Layer 1: termination-primitive net.
 *   blockFatal  swallow a noreturn terminator. The []-signature callback is ABI
 *               safe on arm64 (caller-cleanup), even for a function that takes
 *               args, because we ignore them and just return.
 *   guardKill   for kill/pthread_kill families, zero the signal (turns a fatal
 *               signal into a harmless existence check) for self-directed calls.
 *   logOnly     attach and log without changing behavior, so the next run names
 *               whatever terminator actually fired.
 * ------------------------------------------------------------------------ */
var _getpid = findExport('getpid');
var myPid = _getpid ? new NativeFunction(_getpid, 'int', [])() : -1;

function blockFatal(name) {
  var p = findExport(name);
  if (p === null || p.isNull()) { return false; }
  var cb = new NativeCallback(function () {
    reportKill('blocked ' + name + '()', this.context, this.returnAddress);
    return 0;
  }, 'int', []);
  KEEP.push(cb);
  try { Interceptor.replace(p, cb); console.log('[L1] blocked ' + name); return true; }
  catch (e) { console.log('[L1] could not replace ' + name + ': ' + e); return false; }
}

function guardKill(name) {
  var p = findExport(name);
  if (p === null || p.isNull()) { return false; }
  var perThread = name.indexOf('pthread') !== -1;
  Interceptor.attach(p, {
    onEnter: function (args) {
      var sig = args[1].toInt32();
      if (sig === 0) return;
      var self = perThread || args[0].toInt32() === myPid || args[0].toInt32() === 0;
      if (self) {
        reportKill('neutralized ' + name + '(sig=' + sig + ')', this.context, this.returnAddress);
        args[1] = ptr(0);
      }
    }
  });
  console.log('[L1] guarded ' + name);
  return true;
}

function logOnly(name) {
  var p = findExport(name);
  if (p === null || p.isNull()) { return false; }
  Interceptor.attach(p, {
    onEnter: function () { reportKill('called ' + name, this.context, this.returnAddress); }
  });
  console.log('[L1] logging ' + name);
  return true;
}

// Noreturn terminators, including the low-level syscall stubs and modern reasons.
['exit', '_exit', '_Exit', '__exit', 'abort',
 'abort_with_payload', '__abort_with_payload',
 'terminate_with_reason', '__terminate_with_reason'].forEach(blockFatal);

// Signal-based self-kills.
['kill', '__kill', 'pthread_kill', '__pthread_kill'].forEach(guardKill);

// Log-only: name any other terminator that fires. pthread_exit ends the calling
// thread (fatal on the main thread); std::terminate and cxa handlers are C++ aborts;
// task/thread_terminate are the Mach path (task_terminate(mach_task_self) evades all
// of the above). If one of these prints, the next revision neutralizes it precisely.
['pthread_exit', '_pthread_exit', '_ZSt9terminatev', '__cxa_pure_virtual',
 'objc_terminate', '_objc_terminate', 'task_terminate', 'thread_terminate',
 'task_terminate_internal'].forEach(logOnly);

/* --------------------------------------------------------------------------
 * Layer 2: neutralize the named UI kill funnel showAJMSafeExit(type:handler:).
 * Driven by address, not ObjC name, because the Swift class registers under a
 * mangled runtime name. Confirmed working on device (thunk resolved and replaced).
 * ------------------------------------------------------------------------ */
(function () {
  var TYPE = { 0: 'network_proxy', 1: 'app_resign', 2: 'system_env' };
  function toInt(v) {
    try { return typeof v.toInt32 === 'function' ? v.toInt32() : parseInt('' + v); }
    catch (e) { return -1; }
  }
  var thunk = rt(OFF.showAJMSafeExit_thunk);
  var cb = new NativeCallback(function (self, cmd, type, handler) {
    console.log('\n[L2] showAJMSafeExit BLOCKED  type=' + toInt(type) +
                ' (' + (TYPE[toInt(type)] || '?') + ') -- no dialog, no exit');
  }, 'void', ['pointer', 'pointer', 'int64', 'pointer']);
  KEEP.push(cb);
  try {
    Interceptor.replace(thunk, cb);
    console.log('[L2] neutralized showAJMSafeExit @objc thunk @ ' + thunk);
  } catch (e) {
    var swift = rt(OFF.showAJMSafeExit_swift);
    var cb2 = new NativeCallback(function (type) {
      console.log('\n[L2] showAJMSafeExit (swift) BLOCKED  type=' + toInt(type));
    }, 'void', ['int64', 'pointer', 'pointer']);
    KEEP.push(cb2);
    Interceptor.replace(swift, cb2);
    console.log('[L2] thunk replace failed (' + e + '); neutralized swift impl @ ' + swift);
  }
})();

/* --------------------------------------------------------------------------
 * Layer 3: observability tripwires. Log only. Names which detector ran.
 * ------------------------------------------------------------------------ */
(function () {
  try {
    Interceptor.attach(rt(OFF.jailbreakPathScan), {
      onEnter: function () { console.log('[L3] JM_jailbreakPathScan entered'); },
      onLeave: function (retval) {
        console.log('[L3] JM_jailbreakPathScan -> ' + retval + ' (0 = clean on stock device)');
      }
    });
    console.log('[L3] tripwire on JM_jailbreakPathScan');
  } catch (e) { console.log('[L3] jailbreak scanner tripwire failed: ' + e); }

  if (ObjC.available) {
    var probes = [
      ['ACJailBreak', ['isJailBreak', 'isAppJailBreak', 'ac_isJailBreak', 'ac_isAppJailBreak']],
      ['ACSafety', ['isJailBreak', 'isAppJailBreak']]
    ];
    probes.forEach(function (pr) {
      var clsName = pr[0];
      if (!(clsName in ObjC.classes)) return;
      var cls = ObjC.classes[clsName];
      var found = 0;
      pr[1].forEach(function (raw) {
        ['+ ' + raw, '- ' + raw].forEach(function (sel) {
          var m = cls[sel];
          if (!m) return;
          try {
            Interceptor.attach(m.implementation, {
              onLeave: function (retval) {
                console.log('[L3] ' + sel.charAt(0) + '[' + clsName + ' ' + raw + '] -> ' + retval);
              }
            });
            found++;
          } catch (e) {}
        });
      });
      if (found) console.log('[L3] tripwire on ObjC class ' + clsName + ' (' + found + ' selectors)');
    });
  }
})();

/* --------------------------------------------------------------------------
 * Layer 4 (optional): hide the Frida image from the LIBRARY_INJECTION scanner.
 * Off by default. Turn on if a later detection re-fires. Layer 1 keeps the app
 * alive on its own, so this is only for making the process look clean.
 * ------------------------------------------------------------------------ */
var HIDE_IMAGE = false;
if (HIDE_IMAGE) {
  var BAD = /frida|gum|gadget|cynject|substrate|libhooker|pep\.dylib/i;
  var benign = Memory.allocUtf8String('/usr/lib/libSystem.B.dylib');
  KEEP.push(benign);
  var pName = findExport('_dyld_get_image_name');
  if (pName && !pName.isNull()) {
    Interceptor.attach(pName, {
      onLeave: function (retval) {
        try {
          if (!retval.isNull() && BAD.test(retval.readUtf8String())) retval.replace(benign);
        } catch (e) {}
      }
    });
    console.log('[L4] masking _dyld_get_image_name for Frida images');
  }
}

console.log('\n[anti-tamper] armed. Now type  %resume  to let the app start.');
console.log('[anti-tamper] if it still dies: note whether ANY [L0]/[L1] line printed, and pull a');
console.log('              crash report. Silent death + no crash report = inline svc exit syscall.');
