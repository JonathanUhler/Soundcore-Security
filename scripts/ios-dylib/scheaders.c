/*
 * scheaders.c -- Goal 2 header value capture for the iOS Custom Dylib Monitor.
 *
 * The firmware endpoint gates on a gtoken the app computes at runtime. Rather
 * than reproduce that computation, read the value the app already computed. The
 * request header keys are compiled string constants at fixed addresses, and the
 * app stores each header value in a map keyed by one of those constants. So a
 * map entry that references a key constant sits next to the value. This scans the
 * writable heap for pointers to each known key constant and decodes the Kotlin
 * strings in the neighboring slots, which surfaces the live header values.
 *
 * This also captures a real X-Signature with its X-Request-Ts and X-Request-Once,
 * which lets the recovered HMAC scheme be verified offline against a known good
 * triple, and it confirms whether Client-id and X-Client-Credential are empty.
 *
 * Passive, same footprint as the other readers. Every access is a fault proof
 * mach_vm_read_overwrite, nothing is written, no code is hooked. Keep the app
 * active so a request is in flight or recent while this runs, since the header
 * map is per request.
 */

#include <os/log.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t,
                                            mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_region_recurse(vm_map_t, mach_vm_address_t *, mach_vm_size_t *,
                                            natural_t *, vm_region_recurse_info_t,
                                            mach_msg_type_number_t *);

#define TAG "SCHDR"
#define CHUNK (1u << 20)
#define MAX_REGION (256u << 20)

/* Header key constants, offset from the preferred image base 0x100000000. */
struct keydef {
    const char *name;
    uintptr_t offset;
};
static const struct keydef KEYS[] = {
    {"gtoken", 0x2c1b90},
    {"X-Signature", 0x2c1bb0},
    {"X-Request-Ts", 0x2c1860},
    {"X-Request-Once", 0x2c1830},
    {"Client-id", 0x2c1af0},
    {"X-Client-Credential", 0x2c1b20},
    {"uid", 0x2c1a70},
};
#define NKEYS (sizeof(KEYS) / sizeof(KEYS[0]))

static os_log_t g_log;

static bool safe_read(uintptr_t addr, void *out, size_t len) {
    if (addr == 0) {
        return false;
    }
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)addr,
                                              (mach_vm_size_t)len, (mach_vm_address_t)out, &got);
    return kr == KERN_SUCCESS && got == len;
}

static bool safe_read64(uintptr_t addr, uintptr_t *out) {
    return safe_read(addr, out, sizeof(*out));
}

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

/* Decode a candidate Kotlin string at p into out, dropping null bytes so both
 * UTF-16 and Latin-1 render. Returns the printable length, 0 if not a string. */
static size_t decode_kstring(uintptr_t p, char *out, size_t cap) {
    if (p < 0x100000000ULL || (p & 0x7) != 0) {
        return 0;
    }
    uint32_t count = 0;
    if (!safe_read(p + 8, &count, sizeof(count)) || count == 0 || count > 4096) {
        return 0;
    }
    size_t nbytes = (size_t)count * 2;
    if (nbytes > 1024) {
        nbytes = 1024;
    }
    unsigned char buf[1024];
    if (!safe_read(p + 16, buf, nbytes)) {
        return 0;
    }
    size_t a = 0;
    for (size_t i = 0; i < nbytes && a < cap - 1; i++) {
        if (buf[i] >= 0x20 && buf[i] < 0x7f) {
            out[a++] = (char)buf[i];
        }
    }
    out[a] = '\0';
    return a;
}

static void dump_neighbors(const char *name, uintptr_t hit) {
    /* Walk the slots around the key pointer. In a Kotlin/Native map entry the
     * value pointer sits next to the key pointer, so decode each neighbor. */
    for (int d = -0x20; d <= 0x28; d += 8) {
        if (d == 0) {
            continue;
        }
        uintptr_t vp = 0;
        if (!safe_read64(hit + d, &vp)) {
            continue;
        }
        char val[512];
        size_t n = decode_kstring(vp, val, sizeof(val));
        if (n > 0) {
            os_log(g_log, "%{public}s [%{public}s] entry@0x%lx %+d -> \"%{public}s\"",
                   TAG, name, (unsigned long)hit, d, val);
        }
    }
}

static void scan_region(uintptr_t base, size_t size, const uintptr_t *targets,
                        unsigned char *scratch) {
    size_t off = 0;
    while (off < size) {
        size_t want = size - off;
        if (want > CHUNK) {
            want = CHUNK;
        }
        if (!safe_read(base + off, scratch, want)) {
            off += 0x1000;
            continue;
        }
        size_t slots = want / 8;
        const uintptr_t *w = (const uintptr_t *)scratch;
        for (size_t i = 0; i < slots; i++) {
            uintptr_t v = w[i];
            for (size_t k = 0; k < NKEYS; k++) {
                if (v == targets[k]) {
                    dump_neighbors(KEYS[k].name, base + off + i * 8);
                }
            }
        }
        if (want < CHUNK) {
            break;
        }
        off += CHUNK - 8;
    }
}

static void *headers_thread(void *arg) {
    (void)arg;
    uintptr_t base = main_image_base();
    if (base == 0) {
        os_log(g_log, "%{public}s no main image", TAG);
        return NULL;
    }
    uintptr_t targets[NKEYS];
    for (size_t k = 0; k < NKEYS; k++) {
        targets[k] = base + KEYS[k].offset;
    }
    os_log(g_log, "%{public}s base=0x%lx, scanning for header key references", TAG,
           (unsigned long)base);

    unsigned char *scratch = (unsigned char *)malloc(CHUNK);
    if (scratch == NULL) {
        return NULL;
    }
    for (int pass = 0; pass < 120; pass++) {
        mach_vm_address_t addr = 0;
        while (1) {
            mach_vm_size_t size = 0;
            natural_t depth = 0;
            vm_region_submap_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
            kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &addr, &size, &depth,
                                                      (vm_region_recurse_info_t)&info, &cnt);
            if (kr != KERN_SUCCESS) {
                break;
            }
            if (info.is_submap) {
                depth++;
                continue;
            }
            if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE) &&
                size <= MAX_REGION) {
                scan_region((uintptr_t)addr, (size_t)size, targets, scratch);
            }
            addr += size;
        }
        sleep(2);
    }
    os_log(g_log, "%{public}s scan finished", TAG);
    free(scratch);
    return NULL;
}

__attribute__((constructor))
static void scheaders_init(void) {
    g_log = os_log_create("com.soundcore.research", "headers");
    os_log(g_log, "%{public}s loaded", TAG);
    pthread_t th;
    if (pthread_create(&th, NULL, headers_thread, NULL) == 0) {
        pthread_detach(th);
    }
}
