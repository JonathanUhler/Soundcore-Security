/*
 * scharvest.c -- Goal 2 firmware URL harvester for the iOS Custom Dylib Monitor.
 *
 * Strategy. Let the app make the firmware check itself. It holds valid tokens and
 * signs correctly, so its request passes the endpoint's token and signature gates
 * that a replayed request could not. This dylib does two memory level things and
 * hooks nothing.
 *
 *   1. Version forcing. The earbuds are already on the latest firmware, so a
 *      normal check returns no update. This scans the writable heap for the
 *      current firmware version string and overwrites it in place with a lower
 *      value of the SAME length, so the app sends a well formed, properly signed
 *      request with an old version and the server returns a download URL. This is
 *      a single data write to a heap string, no code is patched. Off by default,
 *      enabled by setting VER_FROM and VER_TO below.
 *
 *   2. URL harvest. It scans the writable heap for http(s) URLs and logs each
 *      unique one, flagging the ones that look like a firmware package. The app's
 *      check response, parsed into a heap string, is where lastPackage.url lands.
 *
 * Only writable regions are scanned, which is where runtime strings live, so the
 * read only dyld shared cache and the app image are skipped and each pass is
 * cheap. Every read is fault proof through mach_vm_read_overwrite.
 *
 * Operator flow. Build, inject, and launch as in README.md. Connect the P20i,
 * navigate to the firmware or OTA screen, and tap check for update while
 * streaming the log. Do NOT tap download or install, a forced low version could
 * push a downgrade to the earbuds. We only need the URL, then the firmware
 * downloads from the CDN outside the app.
 */

#include <os/log.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The iOS SDK gates <mach/mach_vm.h>, so declare what we use. See screader.c. */
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t,
                                            mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t,
                                   mach_msg_type_number_t);
extern kern_return_t mach_vm_region_recurse(vm_map_t, mach_vm_address_t *, mach_vm_size_t *,
                                            natural_t *, vm_region_recurse_info_t,
                                            mach_msg_type_number_t *);

#define TAG "SCHARV"

/*
 * Phase 2 version forcing. Leave both empty for Phase 1, URL harvest only. To
 * force an update, set VER_FROM to the P20i firmware version EXACTLY as the app
 * shows it, and VER_TO to a lower version of the SAME character length, so the
 * in place overwrite fits. Example, VER_FROM "01.62.00", VER_TO "00.00.01".
 */
static const char *VER_FROM = "";
static const char *VER_TO = "";

#define CHUNK (1u << 20)          /* 1 MB scan chunk */
#define OVERLAP 512               /* carry between chunks so matches are not split */
#define MAX_REGION (256u << 20)   /* skip regions larger than this */
#define MAX_URL 512
#define SEEN_MAX 512

static os_log_t g_log;
static uint32_t g_seen[SEEN_MAX];
static int g_seen_n;
static long g_writes;

static bool safe_read(uintptr_t addr, void *out, size_t len) {
    if (addr == 0) {
        return false;
    }
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)addr,
                                              (mach_vm_size_t)len, (mach_vm_address_t)out, &got);
    return kr == KERN_SUCCESS && got == len;
}

/* djb2, used to dedup logged URLs without storing the strings. */
static uint32_t hash_str(const char *s) {
    uint32_t h = 5381;
    for (; *s; s++) {
        h = h * 33u + (unsigned char)*s;
    }
    return h;
}

static bool seen_before(const char *s) {
    uint32_t h = hash_str(s);
    for (int i = 0; i < g_seen_n; i++) {
        if (g_seen[i] == h) {
            return true;
        }
    }
    if (g_seen_n < SEEN_MAX) {
        g_seen[g_seen_n++] = h;
    }
    return false;
}

static bool url_char(unsigned char c) {
    /* Characters allowed to continue a URL token. Guard c == 0 explicitly, since
     * strchr matches a set string's own terminating null. */
    if (c == 0) return false;
    if (c >= 'a' && c <= 'z') return true;
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= '0' && c <= '9') return true;
    return strchr("-._~:/?#[]@!$&'()*+,;=%", c) != NULL;
}

static bool contains_ci(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl) {
            char a = p[i], b = needle[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
            i++;
        }
        if (i == nl) return true;
        if (p[i] == '\0') break;
    }
    return false;
}

static bool looks_like_firmware(const char *url) {
    return contains_ci(url, "firmware") || contains_ci(url, "/ota") ||
           contains_ci(url, ".bin") || contains_ci(url, ".bfu") ||
           contains_ci(url, ".img") || contains_ci(url, ".zip") ||
           contains_ci(url, "a3949") || contains_ci(url, "package") ||
           contains_ci(url, "download") || contains_ci(url, "amazonaws") ||
           contains_ci(url, "upgrade");
}

static void log_url(const char *url) {
    if (strlen(url) < 12 || seen_before(url)) {
        return;
    }
    if (looks_like_firmware(url)) {
        os_log(g_log, "%{public}s FWLIKELY %{public}s", TAG, url);
    } else if (g_seen_n < 300) {
        os_log(g_log, "%{public}s url %{public}s", TAG, url);
    }
}

/* Extract an ASCII URL starting at buf[i], one byte per char. */
static void take_ascii(const unsigned char *buf, size_t len, size_t i) {
    char url[MAX_URL];
    size_t n = 0;
    while (i < len && n < MAX_URL - 1 && url_char(buf[i])) {
        url[n++] = (char)buf[i++];
    }
    url[n] = '\0';
    log_url(url);
}

/* Extract a UTF-16LE URL starting at buf[i], where high bytes are zero. */
static void take_utf16(const unsigned char *buf, size_t len, size_t i) {
    char url[MAX_URL];
    size_t n = 0;
    while (i + 1 < len && n < MAX_URL - 1 && buf[i + 1] == 0 && url_char(buf[i])) {
        url[n++] = (char)buf[i];
        i += 2;
    }
    url[n] = '\0';
    log_url(url);
}

/* JWT / token body characters, base64url plus the dot separator. */
static bool tok_char(unsigned char c) {
    if (c == 0) return false;
    if (c >= 'a' && c <= 'z') return true;
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= '0' && c <= '9') return true;
    return c == '.' || c == '_' || c == '-';
}

/* A JWT access token starts "eyJ" and carries two dots. Capture it from either
 * encoding so a captured token can be replayed via sign_firmware_request.py. */
static void take_token(const unsigned char *buf, size_t len, size_t i, bool wide) {
    char t[MAX_URL];
    size_t n = 0;
    size_t step = wide ? 2 : 1;
    while (i + step <= len && n < MAX_URL - 1 && (!wide || buf[i + 1] == 0) && tok_char(buf[i])) {
        t[n++] = (char)buf[i];
        i += step;
    }
    t[n] = '\0';
    int dots = 0;
    for (size_t k = 0; t[k]; k++) {
        if (t[k] == '.') dots++;
    }
    if (n >= 30 && dots >= 2 && !seen_before(t)) {
        os_log(g_log, "%{public}s TOKEN %{public}s", TAG, t);
    }
}

/* Overwrite every occurrence of needle in [buf,len) at absolute base, in place. */
static void overwrite(uintptr_t base, const unsigned char *buf, size_t len,
                      const unsigned char *needle, size_t nl,
                      const unsigned char *repl) {
    if (nl == 0 || len < nl) {
        return;
    }
    for (size_t i = 0; i + nl <= len; i++) {
        if (memcmp(buf + i, needle, nl) == 0) {
            kern_return_t kr = mach_vm_write(mach_task_self(), (mach_vm_address_t)(base + i),
                                             (vm_offset_t)repl, (mach_msg_type_number_t)nl);
            g_writes++;
            os_log(g_log, "%{public}s patched version @ 0x%lx (write kr=%d)",
                   TAG, (unsigned long)(base + i), kr);
        }
    }
}

static void scan_chunk(uintptr_t base, const unsigned char *buf, size_t len, bool writable,
                       const unsigned char *fa, const unsigned char *ta, size_t la,
                       const unsigned char *fu, const unsigned char *tu, size_t lu) {
    if (len >= 8) {
        for (size_t i = 0; i + 8 <= len; i++) {
            if (buf[i] == 'h' && buf[i + 1] == 't' && buf[i + 2] == 't' && buf[i + 3] == 'p') {
                take_ascii(buf, len, i);
            } else if (buf[i] == 'h' && buf[i + 1] == 0 && buf[i + 2] == 't' && buf[i + 3] == 0 &&
                       buf[i + 4] == 't' && buf[i + 5] == 0 && buf[i + 6] == 'p' && buf[i + 7] == 0) {
                take_utf16(buf, len, i);
            } else if (buf[i] == 'e' && buf[i + 1] == 'y' && buf[i + 2] == 'J') {
                take_token(buf, len, i, false);
            } else if (buf[i] == 'e' && buf[i + 1] == 0 && buf[i + 2] == 'y' && buf[i + 3] == 0 &&
                       buf[i + 4] == 'J' && buf[i + 5] == 0) {
                take_token(buf, len, i, true);
            }
        }
    }
    if (writable && la > 0) {
        overwrite(base, buf, len, fa, la, ta);   /* ASCII / Latin-1 version */
        overwrite(base, buf, len, fu, lu, tu);   /* UTF-16LE version */
    }
}

static void process_region(uintptr_t base, size_t size, bool writable, unsigned char *scratch,
                           const unsigned char *fa, const unsigned char *ta, size_t la,
                           const unsigned char *fu, const unsigned char *tu, size_t lu) {
    size_t off = 0;
    while (off < size) {
        size_t want = size - off;
        if (want > CHUNK) {
            want = CHUNK;
        }
        if (!safe_read(base + off, scratch, want)) {
            /* Skip a page and keep going, part of the region may be resident. */
            off += 0x1000;
            continue;
        }
        scan_chunk(base + off, scratch, want, writable, fa, ta, la, fu, tu, lu);
        if (want < CHUNK) {
            break;
        }
        off += CHUNK - OVERLAP;
    }
}

/* Build the UTF-16LE form of an ASCII string into out, returns byte length. */
static size_t to_utf16(const char *s, unsigned char *out, size_t cap) {
    size_t n = 0;
    for (; *s && n + 2 <= cap; s++) {
        out[n++] = (unsigned char)*s;
        out[n++] = 0;
    }
    return n;
}

static void *harvest_thread(void *arg) {
    (void)arg;
    unsigned char *scratch = (unsigned char *)malloc(CHUNK);
    if (scratch == NULL) {
        os_log(g_log, "%{public}s scratch alloc failed", TAG);
        return NULL;
    }

    size_t la = strlen(VER_FROM);
    unsigned char fu[128], tu[128];
    size_t lu = to_utf16(VER_FROM, fu, sizeof(fu));
    to_utf16(VER_TO, tu, sizeof(tu));
    if (la > 0) {
        if (strlen(VER_TO) != la) {
            os_log(g_log, "%{public}s VER_FROM/VER_TO length mismatch, disabling patch", TAG);
            la = 0;
        } else {
            os_log(g_log, "%{public}s version forcing on: '%{public}s' -> '%{public}s'",
                   TAG, VER_FROM, VER_TO);
        }
    } else {
        os_log(g_log, "%{public}s URL harvest only (no version forcing)", TAG);
    }

    /* Repeat so the patch stays applied as the app refreshes the version, and so
     * the URL is caught after the check completes. About 4 minutes. */
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
            bool readable = (info.protection & VM_PROT_READ) != 0;
            bool writable = (info.protection & VM_PROT_WRITE) != 0;
            if (readable && writable && size <= MAX_REGION) {
                process_region((uintptr_t)addr, (size_t)size, writable, scratch,
                               (const unsigned char *)VER_FROM, (const unsigned char *)VER_TO, la,
                               fu, tu, lu);
            }
            addr += size;
        }
        sleep(2);
    }
    os_log(g_log, "%{public}s harvest finished, %ld version writes", TAG, g_writes);
    free(scratch);
    return NULL;
}

__attribute__((constructor))
static void scharvest_init(void) {
    g_log = os_log_create("com.soundcore.research", "harvest");
    os_log(g_log, "%{public}s loaded", TAG);
    pthread_t th;
    if (pthread_create(&th, NULL, harvest_thread, NULL) == 0) {
        pthread_detach(th);
    } else {
        os_log(g_log, "%{public}s pthread_create failed", TAG);
    }
}
