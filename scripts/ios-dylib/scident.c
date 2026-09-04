/*
 * scident.c -- guest identity and session sweeper for the iOS Custom Dylib
 * Monitor plan. Same passive, file backed, app signed vehicle as screader.
 *
 * Why this exists. screader dumped the netApi network config, the object the
 * request signer reads for the clientSecret. That object holds only the signing
 * material, not the identity. The user or guest identity, userId, userToken, and
 * touristId, and the derived gtoken, live in a different object updated by
 * updateUserInfoToken:userId: (FUN_102ee542c). We do not know its exact global,
 * but every config singleton the app uses clusters in the 0x5446xxx global
 * region, DAT_105446460, _558, _568, _1e8, _208, _440, _4c0. So this sweeps that
 * whole region of global pointer slots, and from each one walks the object graph
 * a few levels deep, decoding every string field and flagging the ones that look
 * like an identity or a token.
 *
 * Everything is a fault proof read through mach_vm_read_overwrite, so walking an
 * unknown graph cannot fault. No hook, no patch, same footprint Goal 1 proved.
 *
 * Kotlin/Native string layout is [TypeInfo* 8][count 4][hash 4][chars], chars in
 * UTF-16LE for constants or Latin-1 for runtime strings, so the decoder drops
 * null bytes and keeps what prints, which reads correctly for both.
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

extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t *outsize);

#define TAG "SCIDENT"
#define CONFIG_SLOT_OFFSET 0x5446558   /* Ghidra 0x105446558 - image base */
#define REGION_START       0x5446000   /* sweep the whole config global cluster */
#define REGION_END         0x5447800
#define MAX_DEPTH          4           /* levels to descend from each global */
#define VISITED_CAP        60000       /* dedup and work bound for the sweep */

static os_log_t g_log;

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

static bool safe_read(uintptr_t addr, void *out, size_t len) {
    if (addr == 0) {
        return false;
    }
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),
                                              (mach_vm_address_t)addr,
                                              (mach_vm_size_t)len,
                                              (mach_vm_address_t)out, &got);
    return kr == KERN_SUCCESS && got == len;
}

static bool safe_read64(uintptr_t addr, uintptr_t *out) {
    return safe_read(addr, out, sizeof(*out));
}

/* Open addressing set of visited pointers, both for dedup and to bound work. */
static uintptr_t g_seen[1 << 17];       /* 131072 slots, load factor < 0.5 */
static size_t g_seen_count;

static bool seen_add(uintptr_t p) {
    if (g_seen_count >= VISITED_CAP) {
        return false;                   /* full, treat as already seen */
    }
    size_t mask = (sizeof(g_seen) / sizeof(g_seen[0])) - 1;
    size_t i = (size_t)(p >> 3) & mask;
    while (g_seen[i] != 0) {
        if (g_seen[i] == p) {
            return false;               /* already visited */
        }
        i = (i + 1) & mask;
    }
    g_seen[i] = p;
    g_seen_count++;
    return true;                        /* newly inserted */
}

static bool plausible_obj(uintptr_t p) {
    return p >= 0x100000000ULL && p < 0x800000000000ULL && (p & 0x7) == 0;
}

/* Classify a decoded string as identity or token looking, for easy grep. */
static const char *classify(const char *s, size_t n) {
    if (n < 5) {
        return NULL;
    }
    if (n >= 3 && s[0] == 'e' && s[1] == 'y' && s[2] == 'J') {
        return "JWT?";
    }
    size_t hex = 0, dig = 0, tokch = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            hex++;
        }
        if (c >= '0' && c <= '9') {
            dig++;
        }
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            c == '-' || c == '_' || c == '.') {
            tokch++;
        }
    }
    if (hex == n && n == 32) return "md5/gtoken?";
    if (hex == n && n == 64) return "sha256/key?";
    if (hex == n && n == 40) return "sha1?";
    if (dig == n && n >= 5)  return "numeric-id?";
    if (tokch == n && n >= 16) return "token/id?";
    return NULL;
}

static size_t g_plain_logged;           /* cap noisy non identity string logs */
#define PLAIN_LOG_CAP 2500

/*
 * If fp is a Kotlin/Native string, decode and log it with its parent context,
 * then return true so the caller does not enqueue it. A string has a small count
 * at +8 and no object fields. Non strings return false so the caller enqueues it.
 * parent and off say which field this came from, so an identity hit can be located
 * precisely later, for a targeted reader.
 */
static bool try_string(uintptr_t fp, uintptr_t parent, int off) {
    uint32_t count = 0;
    if (!safe_read(fp + 8, &count, sizeof(count))) {
        return false;
    }
    if (count == 0 || count > 4096) {
        return false;
    }
    size_t nbytes = (size_t)count * 2;
    if (nbytes > 256) {
        nbytes = 256;
    }
    unsigned char buf[256];
    if (!safe_read(fp + 16, buf, nbytes)) {
        return false;
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
    if (a < 2) {
        return false;                   /* not text, let caller descend into it */
    }
    const char *label = classify(ascii, a);
    if (label != NULL) {
        os_log(g_log, "%{public}s IDENT parent=0x%lx+0x%x ptr=0x%lx count=%u [%{public}s] \"%{public}s\"",
               TAG, (unsigned long)parent, off, (unsigned long)fp, count, label, ascii);
    } else if (g_plain_logged < PLAIN_LOG_CAP) {
        g_plain_logged++;
        os_log(g_log, "%{public}s str parent=0x%lx+0x%x ptr=0x%lx count=%u \"%{public}s\"",
               TAG, (unsigned long)parent, off, (unsigned long)fp, count, ascii);
    }
    return true;
}

/* Breadth first walk of the object graph rooted at the config globals. Iterative
 * with an explicit queue, so a deep graph does not blow the stack. Only objects,
 * not strings, are enqueued. seen_add dedups both, so each string logs once. */
static uintptr_t g_queue[VISITED_CAP];
static size_t g_qhead, g_qtail;

static void push_obj(uintptr_t p, int depth) {
    if (g_qtail < VISITED_CAP) {
        g_queue[g_qtail++] = p | (uintptr_t)(depth & 7);
    }
}

static void sweep(uintptr_t base) {
    uintptr_t start = base + REGION_START;
    uintptr_t end = base + REGION_END;
    os_log(g_log, "%{public}s sweeping globals 0x%lx..0x%lx", TAG,
           (unsigned long)start, (unsigned long)end);

    for (uintptr_t slot = start; slot < end; slot += 8) {
        uintptr_t p = 0;
        if (safe_read64(slot, &p) && plausible_obj(p) && seen_add(p)) {
            if (!try_string(p, slot, 0)) {
                push_obj(p, MAX_DEPTH);
            }
        }
    }

    size_t strings = 0, objects = 0;
    while (g_qhead < g_qtail) {
        uintptr_t packed = g_queue[g_qhead++];
        int depth = (int)(packed & 7);
        uintptr_t p = packed & ~(uintptr_t)7;
        objects++;
        if (depth <= 0) {
            continue;
        }
        for (int off = 8; off <= 0x120; off += 8) {   /* walk this object's fields */
            uintptr_t fp = 0;
            if (!safe_read64(p + off, &fp) || !plausible_obj(fp) || !seen_add(fp)) {
                continue;
            }
            if (try_string(fp, p, off)) {
                strings++;
            } else {
                push_obj(fp, depth - 1);
            }
        }
    }
    os_log(g_log, "%{public}s sweep done, visited=%zu objects=%zu strings=%zu (plain cap %d)",
           TAG, g_seen_count, objects, strings, PLAIN_LOG_CAP);
}

/* Reset the dedup set and queue so a later sweep re-observes everything, in case
 * the guest identity is populated only after the app connects or the operator
 * navigates to a screen that triggers it. */
static void sweep_reset(void) {
    memset(g_seen, 0, sizeof(g_seen));
    g_seen_count = 0;
    g_qhead = 0;
    g_qtail = 0;
    g_plain_logged = 0;
}

static void *scident_thread(void *arg) {
    (void)arg;
    uintptr_t base = main_image_base();
    if (base == 0) {
        os_log(g_log, "%{public}s no MH_EXECUTE image found", TAG);
        return NULL;
    }
    uintptr_t slot = base + CONFIG_SLOT_OFFSET;
    os_log(g_log, "%{public}s main base=0x%lx config slot=0x%lx", TAG,
           (unsigned long)base, (unsigned long)slot);

    /* Wait for the config to populate, the same signal screader uses, so the
     * identity object has had a chance to be built and, ideally, filled by a
     * guest connect. Then give it extra time in case the tourist session is
     * established a little after initConfig. */
    for (int i = 0; i < 400; i++) {     /* ~100 s at 250 ms */
        uintptr_t holder = 0, sub = 0;
        if (safe_read64(slot, &holder) && holder != 0 &&
            safe_read64(holder + 0x10, &sub) && sub != 0) {
            os_log(g_log, "%{public}s config populated, sweeping over time", TAG);
            /* Sweep several times at increasing delays. The guest identity may be
             * filled only after the app connects or the operator opens a screen
             * that needs it, so a single early sweep can miss it. Each pass resets
             * the dedup set so it re observes the whole graph. Drive the app during
             * this window, connect the earbuds and open the firmware screen. */
            static const int delays[] = {8, 15, 25, 40};
            int passes = (int)(sizeof(delays) / sizeof(delays[0]));
            for (int k = 0; k < passes; k++) {
                usleep((useconds_t)delays[k] * 1000 * 1000);
                sweep_reset();
                os_log(g_log, "%{public}s === sweep pass %d/%d ===", TAG, k + 1, passes);
                sweep(base);
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
static void scident_init(void) {
    g_log = os_log_create("com.soundcore.research", "ident");
    os_log(g_log, "%{public}s loaded, starting identity sweep", TAG);

    pthread_t th;
    if (pthread_create(&th, NULL, scident_thread, NULL) == 0) {
        pthread_detach(th);
    } else {
        os_log(g_log, "%{public}s pthread_create failed", TAG);
    }
}
