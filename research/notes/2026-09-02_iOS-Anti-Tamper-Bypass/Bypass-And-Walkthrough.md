# The Bypass And The On Device Walkthrough

This documents `scripts/ios-frida/anti-tamper.js`, the reasoning behind its layering, and the on
device procedure for Goals 1, 3, and 4. The script is written and code reviewed but not yet run on
device. Everything below the design section is a procedure for a device operator to execute and
record.

## First On Device Result

The first device run (2026-09-02) refined the picture. All hooks armed cleanly, the thunk resolved at
`0x1006a4fe8` so the main image base was `0x10051c000` with a `0x51c000` slide, and Layer 2 replaced
the `showAJMSafeExit` thunk. On `%resume` the process terminated instantly with no output. No
`[L1] BLOCKED`, no `[L2]`, and the Layer 3 jailbreak tripwire never printed.

That rules out a lot. The instant kill does not go through `exit`, `_exit`, `_Exit`, `abort`, `kill`,
or `__pthread_kill`, and it does not go through `showAJMSafeExit`. It also happens before
`JM_jailbreakPathScan` runs, so it is a very early startup check. Two mechanisms remain. Either the
SDK calls a low-level terminator that is not a public C function, a syscall stub like `__exit` or a
modern reason syscall like `terminate_with_reason`, or it kills with a CPU trap, a `brk` or `udf`
illegal instruction, which no function hook can observe.

The script was revised to cover both. Layer 0 installed a `Process.setExceptionHandler`, and Layer 1
was widened to the `__` syscall stubs and the `abort_with_payload` and `terminate_with_reason`
family, with log only over the rest including the Mach `task_terminate` path.

The second run (2026-09-02) caught it. No terminator fired. Instead the exception handler reported an
`access-violation` fault at data address `0x114d15000`, with the backtrace inside
`-[SoundCore.AppDelegate application:didFinishLaunchingWithOptions:]`, in its Swift body
`FUN_100d57350`, right at the top. So the kill is not a call at all. It is a deliberate bad memory
access early in `didFinishLaunching`. The unmodified app runs fine, so this fault only occurs under a
debugger. That is the signature of an exception-based anti-debug. The SDK triggers a fault it expects
to catch in its own signal handler and recover from. Under debugserver the debugger catches the fault
first and the app dies.

Two counters were added and both go out in the next run.

- Layer 0b, anti-anti-debug. Jailed spawn runs the app under debugserver, which sets `P_TRACED` and
  makes `getppid` the debugger's pid. The added hooks scrub the `P_TRACED` bit from the `sysctl`
  `KERN_PROC` result, force `getppid` to 1, and no-op `ptrace`. If the SDK checks for a debugger this
  way and only faults when it finds one, this prevents the fault at its source, which is the clean
  fix.
- Layer 0 upgraded to a fault rider. It now reports the true faulting pc, the fault address, the
  registers, and the bytes at pc, and it advances past the faulting instruction for faults in the app
  image or an anonymous page, capped at 256, mimicking the recovery the SDK's own handler would do.

The next run tells us which worked. If Layer 0b prevents the fault, there is no exception line and the
app proceeds. If not, the rider prints the exact faulting instruction and register set, which pins the
trigger in Ghidra for a static neutralization if riding does not stabilize.

## Third On Device Result, The Real Mechanism

The third run (2026-09-02, captured in `frida.log`) revealed the actual kill. It is not a data fault
and not a call to a terminator. It is an instruction fetch fault, `pc` equal to the fault address, on
a non-executable page. Two pages appeared, `0x11323xxxx` reached by the main thread's `signal()` call
in `didFinishLaunching`, and `0x11531xxxx` reached by a dispatch worker inside
`+[NSFileHandle initialize]` by way of FontServices and libGSFont. Both pages hold a valid
`ldr x16, ..; str x16, [sp,#-0x10]; ldr x16, ..; br x16` trampoline. The bytes read fine, so the page
is readable, but executing them faults, so the page is not executable.

The reading is that the SDK strips execute permission from its own hook-trampoline region when it
detects the gum agent. Every function routed through those trampolines then faults on the next call,
on any thread, which is why the crash appears on unrelated system threads as well as the app's main
thread. This is confirmed to be the SDK rather than our hooks, because the earlier recon.js session
installed no Interceptor hooks and still died the same way on resume.

The pc advancing rider was the wrong tool. It walked each dead page four bytes at a time across two
threads and never progressed. The right counter is to re-arm the page as executable and re-run the
same instruction. `mprotect` does not lower a region's max protection, so `Memory.protect` can restore
exec. Layer 0 was rewritten to do exactly this, keyed by page with a cap. Layer 0d was added to cover
the one path `Memory.protect` cannot undo, a `mach_vm_protect` or `vm_protect` that lowers max
protection with `set_maximum`, by keeping the execute bit in the requested max protection.

If the re-arm works, the run shows one `[L0] re-armed executable page` line per poisoned page and then
the app proceeds. If the SDK re-strips the same page in a tight loop, the per-page cap is reached and
the app dies, and the next step is to neutralize the strip at its source, either by hooking the SDK's
`mprotect` or `mach_vm_protect` call for that region, or by finding and disabling the detection that
triggers it, using the `didFinishLaunching` entry at Ghidra `FUN_100d57350` as the anchor.

## Fourth On Device Result, The Rescue Half Worked

The fourth run stopped the death but froze the app on the boot screen. The log showed the cause. Only
three faults appeared, all at the same page, and no `re-armed` line printed. The re-arm branch had a
gate, `mod === null`, meant to touch only non-image pages, but Frida attributes the SDK's trampoline
pages to a module, so the gate skipped them. The handler then returned false, and under debugserver a
returned-false fault suspends the faulting thread rather than killing it, which is the frozen home
screen. The caller was SDK code at `SoundCore` offset `0x3149c08`, doing `br x16` into the trampoline.

The fix removes the gate. An instruction fetch fault, `pc` equal to the fault address, always means
execution hit a non-executable page, so the module attribution is irrelevant and the page is always
re-armed. Two source-side pins were also added so a timer-based re-strip cannot race the reactive
re-arm. Layer 0d now forces the execute bit back on any `mach_vm_protect` or `vm_protect` that removes
it from a page already seen faulting or that lowers max protection. Layer 0e does the same for
`mprotect`, but only when the call's range covers a known poisoned page, so unrelated read-only
transitions are left alone. Strip-block logging is rate limited.

## Fifth On Device Result, A Handler That Would Not Talk

The fifth run stayed alive but stuck on the opening logo. The log showed three faults, all at the same
page, and, impossibly, neither the re-arm success line nor the re-arm failure line. The tag confirmed
the fault was an instruction fetch, so the re-arm branch should have run and logged one or the other.
The static side explained the caller. The faulting page is the resolved target of an import stub, so
the SDK rebinds monitored libc imports to redirect pages in a `0x11xxxxxxx` region, and those pages
are the ones stripped of exec. The caller `FUN_103149ad0` reaches the stub at a `bl` whose return
address is the `0x3149c08` frame in the backtrace.

Two problems were addressed. First, the reactive handler ignored the boolean that `Memory.protect`
returns, and could abort before logging, which reads as an unhandled fault and lets debugserver
suspend the thread. It was rewritten to wrap everything, to try `rwx` then `r-x`, and to log the
boolean result and any error for every fault. Second, the protection guard was made both verbose and
preventive. It now logs the first sixty `mprotect`, `mach_vm_protect`, and `vm_protect` calls with
their address, length, protection, and whether the target is currently executable, which will make
the strip call itself visible, and it forces the execute bit back whenever a call removes it from a
currently executable page or lowers max protection.

The next run is diagnostic. The `[Lprot]` lines will show whether the strip goes through a hooked
protection call, and if so the `KEEP EXEC` marker will show it being prevented. The `@@ [L0]` lines
will show whether `Memory.protect` can restore exec after the fact. One of those two paths should keep
the pages executable. If neither fires and the pages still go non-executable, the strip uses a path
that is not a protection syscall, for example an `mmap` with `MAP_FIXED` over the region, and the next
step is to hook that.

## Sixth On Device Result, The Protect Call Was Wrong

The sixth run gave the clean answer. One fault, `@@ [L0] fetch ... protect=false`, and no `[Lprot]`
line for the region, then termination. The verbose handler exposed a bug in the handler itself. It
called `Memory.protect` with `rwx` first, but the trampoline pages are code pages whose max protection
is `r-x`, so `rwx` fails on W^X because it cannot add write, and `Memory.protect` reports that by
returning false rather than throwing. The fallback to `r-x` sat in a catch block, so a false return
skipped it and the handler gave up.

The absence of an `[Lprot]` line for the region also means the strip does not go through the libc
`mprotect`, `mach_vm_protect`, or `vm_protect` wrappers. It is a raw Mach trap or a fresh mapping. That
makes prevention hard, so the handler must recover after the fact.

The handler was fixed to try `r-x` first and to trust the boolean return. In place restore should now
succeed for the normal case, where the strip only cleared the current exec bit and left max protection
at `r-x`. A relocation fallback was added for the harder case, where max protection itself lost exec.
It copies the page into Frida owned executable memory and redirects pc into the copy. The trampolines
are position independent, a pc-relative load plus an absolute branch, so the copy runs identically and
returns to the original caller through the link register. In place restore is a one time fix per page.
Relocation faults once per call, so if the run survives only through relocation it may be slow, and the
better long term fix is to stop the detection that triggers the strip, anchored at `FUN_100d57350`.

## Seventh On Device Result, And Why Reacting Cannot Win

The seventh run made the strategy clear. In place `r-x` restore now succeeded, but the same page
faulted forty times in a row, each restore reported success, and the app never advanced. It is a
livelock. We restore exec, the retry runs, and a watchdog thread re-strips the page before or during
the next access, so the same instruction faults again. The re-strip goes through a raw Mach trap, no
`[Lprot]` line, so it cannot be pinned at the wrapper.

This is the key lesson. The kill is not one event to block. Once the SDK detects the agent it branches
onto a sabotage path and actively works to keep the app from running, re-stripping its own trampolines
in a loop and likely more. Re-arming pages, blocking exit, and neutralizing the alert all patch
symptoms the sabotage path produces. The sabotage path is designed never to reach a working app, so
each patched symptom exposes the next. Reacting cannot get back to a normal boot.

The path to a normal boot is prevention. Keep the app on its normal path by making the detection
report clean, so it never enters sabotage mode. The detection fires from the agent being loaded, since
recon.js with zero hooks triggers it, and `APP_FIRM_LIBRARY_INJECTION` walks the dyld image list. The
debugger checks were already neutralized and did not help, which points at the image list vector.

Layer P was added to hide Frida's images from the dyld enumeration. It computes the visible non-Frida
indices once during the spawn pause, shrinks `_dyld_image_count`, and remaps the index argument of
`_dyld_get_image_name`, `_dyld_get_image_header`, and `_dyld_get_image_vmaddr_slide`, so a scan never
sees the agent. The reactive handler was switched to relocation so it no longer livelocks, and given a
heartbeat log, but that is only a safety net. Success is Layer P eliminating the faults entirely.

If faults still occur after Layer P, the detection reads the image list a different way, most likely
the raw `dyld_all_image_infos` structure through `task_info(TASK_DYLD_INFO)` rather than the API, and
the next step is to hook that or to move to a static neutralization of the detector.

## Eighth On Device Result, Two Walls

The eighth run hit two walls that bound the whole approach.

The relocation safety net revealed a hard limit. Each fault copied a page and redirected into the
copy, then the copy faulted on its own first instruction, and the handler copied that, walking up the
address space for tens of thousands of faults. The cause is iOS code signing. AMFI refuses to execute
unsigned pages, and this sideloaded app has no JIT entitlement, so a Frida allocated page cannot be
made executable no matter what `Memory.protect` returns. This also explains the earlier in place
livelock. Re-armed exec does not stick. The conclusion is firm. Reactive recovery of executable memory
is impossible on this process, so patching the faults can never reach a boot.

Layer P did not get a fair test. Its heuristic for finding the unnamed agent, the module backing a
fresh NativeCallback, resolved to `ArgumentParserInternal` and hid that instead of the agent. So the
dyld image list vector is still untested. Layer P was changed to instead print every module that is
not an Apple system library or the app bundle, which will name the agent so it can be hidden correctly.
The relocation path was removed, and the reactive handler now only best effort re-arms, detects the
livelock, and caps the fault count so the session ends rather than looping forever.

This is a decision point. The reactive side is a dead end. The remaining paths are, one, confirm and
defeat the detection vector so the app never enters sabotage mode, starting by naming the agent and
testing dyld image hiding, then the raw `dyld_all_image_infos` read, then a static neutralization of
the detector. Two, reconsider the capture vehicle, since the signing scheme is already recovered
statically in `anker-signing-scheme-recovered`, so the remaining need is the firmware URL and md5 from
a check for update, which might be reachable by replaying the API directly rather than driving the
instrumented app.

## Why Block The Exit Primitives

The static analysis in `Kill-Switch-Analysis.md` showed there is no single clean choke point to
patch. The detectors are obfuscated native ObjC, there are many of them, and the dispatcher reaches
termination by more than one route, a direct exit early and the `showAJMSafeExit` alert later. The
one action every path shares is terminating the process. So the core defense blocks the exit
primitives. Whatever detector fires, and whichever route the dispatcher takes, it must call an exit
primitive to kill the app, and that call is intercepted.

This also gives the Goal 1 proof for free. Each blocked call prints a backtrace and flags whether the
calling frame is inside the SoundCore image. That confirms the kill originates in the app rather than
in the Frida agent, and it names the exact primitive and call site.

## The Layers

- Layer 1, the exit primitive backstop. Replaces `exit`, `_exit`, `_Exit`, and `abort` with a logging
  no op, and neutralizes self directed `kill` and `__pthread_kill` by rewriting the signal argument
  to zero, which turns a fatal signal into a harmless existence check and lets the real function
  return normally for any legitimate caller. This layer is what keeps the app alive.
- Layer 2, neutralize `showAJMSafeExit`. Replaces the @objc thunk at offset `0x188fe8` by address so
  the compromised dialog never shows and its terminating handler never runs. It logs the alert type
  so the operator learns which category fired. It is driven by address, not by ObjC class name,
  because the Swift class registers under a mangled runtime name that `ObjC.classes` may not expose.
- Layer 3, observability tripwires. Log only hooks on `JM_jailbreakPathScan` at offset `0x1f288d4`
  and on the `ACJailBreak` and `ACSafety` jailbreak selectors, if present. These do not change
  behavior. They show which detector ran and in what order.
- Layer 4, optional image hiding. Masks the Frida image name from `_dyld_get_image_name`, which is how
  `APP_FIRM_LIBRARY_INJECTION` enumerates loaded images. It is off by default because Layer 1 already
  keeps the app alive, and this is only worth enabling if a later detection re-fires. Turn it on by
  setting `HIDE_IMAGE` to true.

## Address Model

All hooks resolve at runtime as `main image base + offset`, where the main image base already
includes the ASLR slide. The offsets are fixed values from the Ghidra project, listed in the header
of the script and in the table in `Kill-Switch-Analysis.md`. There is nothing to recompute per boot.
The exit primitives are resolved by export name, so they need no offset.

## Known Risks In The Bypass

- Replacing a noreturn function and returning to its caller is the one fragile part. The compiler may
  emit no code after a call it believes cannot return, so control returns into whatever follows. In
  practice the dispatcher usually has a clean tail, but if the app crashes right after a `[L1]
  BLOCKED` line, this is why. The fix is to prefer the earlier layers so the exit is never reached,
  which is what Layers 2 and 4 are for.
- A raw exit syscall bypasses the libc export hooks. If the SDK issues `svc` for `SYS_exit` directly,
  or traps with `brk`, Layer 1 does not see it. The symptom is a kill with no `[L1] BLOCKED` line.
  Confirm from a crash report and extend to that path.
- Re-checks on a timer. If a detector re-runs, the block simply fires again, which is fine for the
  exit primitives. If it escalates to a raw syscall, see the point above.

## Goal 1, Prove The Kill Path

1. Complete the environment setup in `scripts/ios-frida/COMMANDS.md`, sections 1 through 5, the
   tunnel and the mounted developer image.
2. Spawn with only the bypass loaded, so the output is clean.

   ```bash
   frida -U -f com.oceanwing.SoundCore.G8AW4BQ7RV -l scripts/ios-frida/anti-tamper.js
   ```

3. Wait for `[anti-tamper] armed`, then type `%resume`.
4. Read the first `############ [anti-tamper] BLOCKED ... ############` block. Record the primitive
   that fired, `exit`, `_exit`, `abort`, or a neutralized `kill`, and the backtrace. The
   `caller in SoundCore image: true` line is the proof the kill is the app's own code. This resolves
   Goal 1.
5. If nothing is blocked and the app dies anyway, it is a raw syscall exit. Pull a fresh crash report
   and read the faulting frame, then extend Layer 1.

## Goal 2, Confirm The App Survives

Success is the app reaching its home screen and staying alive with the bypass loaded. Note whether any
`[L2]` or `[L3]` tripwire fired and in what order. If the app survives the first kill but dies a few
seconds later, a second path fired, likely the `showAJMSafeExit` countdown. Confirm Layer 2 logged it,
and if the death still happens, enable `HIDE_IMAGE`.

## Goals 3 And 4, Reach The Upgrade Screen And Capture

1. With the app alive, drive it by hand. It can be used without an account, so try navigating to the
   paired P20i and its firmware or OTA screen without logging in first. Log in only if the OTA screen
   requires it.
2. Re-spawn with the capture hooks appended, so the signing and firmware traffic is instrumented from
   launch.

   ```bash
   frida -U -f com.oceanwing.SoundCore.G8AW4BQ7RV \
     -l scripts/ios-frida/anti-tamper.js \
     -l scripts/ios-frida/network-hooks.js \
     -l scripts/ios-frida/crypto-hooks.js
   ```

3. Resume, navigate to the OTA screen, and trigger a check for update. Capture the signed request and
   its headers from `network-hooks.js`, the ECDH shared secret and the HMAC key, message, and mac from
   `crypto-hooks.js`, and the firmware URL and md5 from the check for update response.
4. If the network hooks see no traffic, the requests may route through Dart or Alamofire's delegate
   path rather than the `NSURLSession` completion handler. Fall back to the crypto primitives, or run
   mitmproxy in parallel, per the troubleshooting notes in `COMMANDS.md`.

This reconnects to Goals 1 and 2 of the prior plan, and the capture can be written up as its own
session.
</content>
