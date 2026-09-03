/*
 * screader.c -- Goal 2 credential reader for the iOS Custom Dylib Monitor plan.
 *
 * A passive, file backed, app signed dylib added to the Soundcore bundle at
 * re-sign time, the same vehicle proven in Goal 1. It reads the network config
 * singleton that the app's own request signer reads, and dumps the credential
 * material to the unified log so the host can reproduce a signed firmware
 * check-for-update call.
 *
 * Everything here is a read. Memory is touched only through
 * mach_vm_read_overwrite, which returns an error instead of faulting on an
 * unmapped or bad address, so walking a struct whose exact layout is not known
 * cannot crash the app. No function is hooked and no code is patched, so this
 * stays inside the footprint that Goal 1 showed the reinforcement SDK tolerates.
 *
 * The read chain is taken from the bootstrap signer FUN_102d78e9c in Ghidra.
 *   holder = *(main_base + 0x5446558)   the config holder pointer (global slot)
 *   sub    = *(holder + 0x10)           the config data object
 *   secret = *(sub + 0x48)              the HMAC secret string
 * The signer builds its message as clientId + tsMsg + onceMsg + secret. clientId
 * and the other credentials (clientSecret, presetKey) live as string fields in
 * the same config data object, so this reader dumps every string looking field
 * of both the holder and the sub object rather than assuming their offsets.
 *
 * Kotlin/Native string layout, confirmed from the string constants in the
 * binary, is [TypeInfo* 8][count 4][hash 4][chars]. ASCII text is stored either
 * UTF-16LE (constants) or Latin-1 (runtime), so the dumper drops null bytes and
 * prints whatever prints, which reads correctly for both.
 */

#include <os/log.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * The iOS SDK gates <mach/mach_vm.h> behind #error "mach_vm.h unsupported.",
 * treating it as macOS only, even though the function is in libSystem and works
 * on iOS for our own task. Declare the prototype directly instead of including
 * the gated header. The types come from <mach/mach.h> above.
 */
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t *outsize);

#define TAG "SCREAD"
#define CONFIG_SLOT_OFFSET 0x5446558   /* Ghidra 0x105446558 - image base */

static os_log_t g_log;

/* Runtime base of the main executable image, which is its mach header address. */
static uintptr_t main_image_base(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h != NULL && h->filetype == MH_EXECUTE) {
            return (uintptr_t)h;
        }
    }
    return 0;
}

/* Fault proof read of our own task memory. Returns true only on a full read. */
static bool safe_read(uintptr_t addr, void *out, size_t len) {
    if (addr == 0) {
        return false;
    }
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),
                                              (mach_vm_address_t)addr,
                                              (mach_vm_size_t)len,
                                              (mach_vm_address_t)out,
                                              &got);
    return kr == KERN_SUCCESS && got == len;
}

static bool safe_read64(uintptr_t addr, uintptr_t *out) {
    return safe_read(addr, out, sizeof(*out));
}

/*
 * Treat p as a candidate Kotlin/Native string object and, if it looks like one,
 * log its char data as ASCII. Anything that does not look like a string is
 * skipped silently, so this is safe to call on every field of an unknown struct.
 */
static void dump_candidate(const char *group, int off, uintptr_t p) {
    if (p < 0x100000000ULL || (p & 0x7) != 0) {
        return;                         /* not a plausible heap object pointer */
    }
    uint32_t count = 0;
    if (!safe_read(p + 8, &count, sizeof(count))) {
        return;
    }
    if (count == 0 || count > 2048) {
        return;                         /* not a plausible string length */
    }
    size_t nbytes = (size_t)count * 2;  /* enough for UTF-16, over-reads Latin-1 */
    if (nbytes > 128) {
        nbytes = 128;
    }
    unsigned char buf[128];
    if (!safe_read(p + 16, buf, nbytes)) {
        return;
    }
    char ascii[130];
    size_t a = 0;
    for (size_t i = 0; i < nbytes && a < sizeof(ascii) - 1; i++) {
        unsigned char c = buf[i];
        if (c >= 0x20 && c < 0x7f) {
            ascii[a++] = (char)c;
        }
    }
    ascii[a] = '\0';
    if (a == 0) {
        return;                         /* no printable content, not our target */
    }
    os_log(g_log, "%{public}s %{public}s[+0x%x] ptr=0x%lx count=%u ascii=\"%{public}s\"",
           TAG, group, off, (unsigned long)p, count, ascii);
}

static void *screader_thread(void *arg) {
    (void)arg;
    uintptr_t base = main_image_base();
    if (base == 0) {
        os_log(g_log, "%{public}s no MH_EXECUTE image found", TAG);
        return NULL;
    }
    uintptr_t slot = base + CONFIG_SLOT_OFFSET;
    os_log(g_log, "%{public}s main base=0x%lx config slot=0x%lx", TAG,
           (unsigned long)base, (unsigned long)slot);

    /* Poll until the config holder and its data object are populated. The
     * constructor runs during dyld init, well before the app's initConfig, so
     * this normally spins for a moment before the object appears. */
    for (int i = 0; i < 400; i++) {     /* ~100 s at 250 ms */
        uintptr_t holder = 0, sub = 0;
        if (safe_read64(slot, &holder) && holder != 0 &&
            safe_read64(holder + 0x10, &sub) && sub != 0) {
            /* Give initConfig a moment to finish setting every field. */
            usleep(2 * 1000 * 1000);
            safe_read64(slot, &holder);
            safe_read64(holder + 0x10, &sub);

            uintptr_t secret = 0;
            safe_read64(sub + 0x48, &secret);
            os_log(g_log, "%{public}s config populated: holder=0x%lx sub=0x%lx secret=0x%lx",
                   TAG, (unsigned long)holder, (unsigned long)sub, (unsigned long)secret);

            dump_candidate("secret", 0x48, secret);
            for (int off = 0; off <= 0xC0; off += 8) {
                uintptr_t fp = 0;
                if (safe_read64(sub + off, &fp)) {
                    dump_candidate("sub", off, fp);
                }
            }
            for (int off = 0; off <= 0x40; off += 8) {
                uintptr_t fp = 0;
                if (safe_read64(holder + off, &fp)) {
                    dump_candidate("holder", off, fp);
                }
            }
            os_log(g_log, "%{public}s dump complete", TAG);
            return NULL;
        }
        usleep(250 * 1000);
    }
    os_log(g_log, "%{public}s timed out waiting for config singleton", TAG);
    return NULL;
}

__attribute__((constructor))
static void screader_init(void) {
    g_log = os_log_create("com.soundcore.research", "reader");
    os_log(g_log, "%{public}s loaded, starting config poll", TAG);

    pthread_t th;
    if (pthread_create(&th, NULL, screader_thread, NULL) == 0) {
        pthread_detach(th);
    } else {
        os_log(g_log, "%{public}s pthread_create failed", TAG);
    }
}
