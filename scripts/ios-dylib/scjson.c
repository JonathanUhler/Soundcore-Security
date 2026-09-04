/*
 * scjson.c -- serialized batch-request-body capturer for the OTA Batch Request
 * Capture plan. Same passive, file backed, app signed vehicle as scharvest and
 * scident, reads only, no hook, no code patch, no memory writes at all.
 *
 * Why this exists. Auth to the firmware API is solved, but the real firmware
 * check is the batch endpoint api/v2/speaker/firmware/upgrade_check/batch, model
 * SCOTAMultipleRequestModel, and every body shape guessed by hand returns
 * 400 Err_InvalidRequest. Static analysis stalled on the exact schema, the OTA
 * models serialize through HandyJSON/ObjectMapper and the reflection metadata
 * carries two different key sets, snake_case product_code/sn/version next to
 * camelCase firmwareList/wifiVersion, so the required item shape is ambiguous.
 * The reliable answer is the exact JSON the app itself serializes just before it
 * hands the body to the pinned TLS connection. That string sits in the writable
 * heap for a moment. This dylib catches it.
 *
 * How. It sweeps every readable, writable region on a tight loop, looking for the
 * two byte prefix that starts a JSON object, {" in ASCII/UTF-8 or {"00 in
 * UTF-16LE. HandyJSON emits a Swift String, UTF-8 backed, so the body is single
 * byte ASCII, but the wide form is detected too as a cheap safety net. On a hit it
 * re-reads a bounded window straight from the target address, so a body that
 * straddles a scan chunk boundary is never truncated, then walks it with quote and
 * brace awareness to capture one complete object. If the object carries at least
 * two OTA field markers, or the definitive firmwareList wrapper key, it is logged
 * uncapped, chunked across several os_log lines with a capture id and a segment
 * index so the operator can reassemble it exactly. Content is deduped by hash so a
 * body is logged once even though it is re-observed on many passes.
 *
 * Every read is fault proof through mach_vm_read_overwrite, so sweeping the heap
 * cannot fault the app, and nothing is ever written back. That is the whole reason
 * this vehicle survives the reinforcement SDK, so it is kept strictly read only.
 */

#include <os/log.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* The iOS SDK gates <mach/mach_vm.h>, so declare what we use. See screader.c. */
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t,
                                            mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_region_recurse(vm_map_t, mach_vm_address_t *, mach_vm_size_t *,
                                            natural_t *, vm_region_recurse_info_t,
                                            mach_msg_type_number_t *);

#define TAG "SCJSON"

#define CHUNK (1u << 20)          /* 1 MB scan chunk */
#define OVERLAP 8                 /* carry between chunks so a prefix is not split */
#define MAX_REGION (256u << 20)   /* skip regions larger than this */
#define CAP 32768                 /* max JSON bytes captured from one object */
#define SEG 160                   /* chars per os_log segment line */
#define SEEN_MAX 256              /* distinct bodies remembered for dedup */
#define RUN_SECONDS 600           /* total sweep window, ~10 minutes */
#define PASS_PAUSE_US (150 * 1000)/* short yield between full passes */

static os_log_t g_log;
static uint32_t g_seen[SEEN_MAX];
static int g_seen_n;
static unsigned g_capture_id;

/* OTA field markers. A batch body carries several of these. firmwareList and its
 * snake sibling are definitive wrapper keys, the rest are item fields seen in the
 * SCOTAMultipleItemStruct reflection metadata, both key styles. The quoted "sn",
 * "version", and "matched" are matched with their quotes so they do not fire on
 * substrings of longer keys like wifiVersion. */
static const char *const MARKERS[] = {
    "firmwareList", "firmware_list",
    "upgrade_check",
    "product_code", "productCode",
    "product_component", "productComponent",
    "product_language", "productLanguage",
    "base_version", "wifiVersion", "wifi_Version", "relationSn",
    "\"sn\"", "\"version\"", "\"matched\"",
};
#define MARKER_COUNT ((int)(sizeof(MARKERS) / sizeof(MARKERS[0])))

static bool safe_read(uintptr_t addr, void *out, size_t len) {
    if (addr == 0) {
        return false;
    }
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)addr,
                                              (mach_vm_size_t)len, (mach_vm_address_t)out, &got);
    return kr == KERN_SUCCESS && got == len;
}

/* djb2 over the decoded body, used to dedup captures without storing the strings. */
static uint32_t hash_str(const char *s, size_t n) {
    uint32_t h = 5381;
    for (size_t i = 0; i < n; i++) {
        h = h * 33u + (unsigned char)s[i];
    }
    return h;
}

static bool seen_before(uint32_t h) {
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

/* Count how many distinct OTA markers appear, and whether a definitive wrapper key
 * is present. definitive alone is enough to log, otherwise two markers are wanted
 * so a lone "version" in some unrelated model does not trigger a capture. */
static int marker_score(const char *s, bool *definitive) {
    *definitive = false;
    int score = 0;
    for (int i = 0; i < MARKER_COUNT; i++) {
        if (strstr(s, MARKERS[i]) != NULL) {
            score++;
            if (i < 2) {                 /* firmwareList / firmware_list */
                *definitive = true;
            }
        }
    }
    return score;
}

/*
 * Capture one complete JSON object beginning at an absolute address. The window is
 * re-read straight from the target, independent of the scan chunk, so a body that
 * spans a chunk boundary is captured whole. For ASCII each char is one byte, for
 * UTF-16LE each char is a low byte with a zero high byte. The walk is quote and
 * escape aware so a brace inside a string does not close the object early, and it
 * stops at the matching close brace, a NUL, or a non JSON byte. Returns the decoded
 * length in bytes and sets closed when the object ended on its own close brace.
 */
static size_t extract_json(unsigned char *raw, char *js, uintptr_t addr, bool wide,
                           bool *closed) {
    *closed = false;
    size_t want = wide ? CAP * 2 : CAP;
    size_t got = 0;
    while (want >= 64) {                  /* shrink until the read fits the region */
        if (safe_read(addr, raw, want)) {
            got = want;
            break;
        }
        want /= 2;
    }
    if (got == 0) {
        return 0;
    }

    size_t n = 0;
    int depth = 0;
    bool instr = false, esc = false, started = false;
    size_t step = wide ? 2 : 1;
    for (size_t i = 0; i + step <= got && n < CAP - 1; i += step) {
        if (wide && raw[i + 1] != 0) {
            break;                        /* not a BMP ASCII char, end of the string */
        }
        unsigned char c = raw[i];
        if (c == 0) {
            break;                        /* NUL terminates */
        }
        if ((c < 0x20 || c > 0x7e) && c != '\t' && c != '\n' && c != '\r') {
            break;                        /* non JSON byte, end of the object */
        }
        js[n++] = (char)c;
        if (esc) {
            esc = false;
            continue;
        }
        if (instr) {
            if (c == '\\') {
                esc = true;
            } else if (c == '"') {
                instr = false;
            }
            continue;
        }
        if (c == '"') {
            instr = true;
        } else if (c == '{' || c == '[') {
            depth++;
            started = true;
        } else if (c == '}' || c == ']') {
            depth--;
            if (started && depth == 0) {
                *closed = true;
                break;
            }
        }
    }
    js[n] = '\0';
    return n;
}

/* Log a captured body uncapped, one header line, one line per SEG chunk with a
 * segment index, one footer line. os_log truncates a single long argument, so the
 * body is split so the operator can concatenate the segments back exactly. */
static void log_body(uintptr_t addr, bool wide, const char *js, size_t n, int score,
                     bool closed) {
    unsigned id = ++g_capture_id;
    os_log(g_log, "%{public}s CAPTURE #%u addr=0x%lx enc=%{public}s len=%zu score=%d %{public}s BEGIN",
           TAG, id, (unsigned long)addr, wide ? "utf16" : "ascii", n, score,
           closed ? "closed" : "TRUNCATED");
    size_t segs = (n + SEG - 1) / SEG;
    if (segs == 0) {
        segs = 1;
    }
    char part[SEG + 1];
    for (size_t k = 0; k < segs; k++) {
        size_t off = k * SEG;
        size_t len = n - off;
        if (len > SEG) {
            len = SEG;
        }
        memcpy(part, js + off, len);
        part[len] = '\0';
        os_log(g_log, "%{public}s #%u seg %zu/%zu %{public}s", TAG, id, k + 1, segs, part);
    }
    os_log(g_log, "%{public}s CAPTURE #%u END", TAG, id);
}

/* Detect a JSON object prefix in the chunk, then extract, score, dedup, and log. */
static void scan_chunk(uintptr_t base, const unsigned char *buf, size_t len,
                       unsigned char *raw, char *js) {
    if (len < 4) {
        return;
    }
    for (size_t i = 0; i + 4 <= len; i++) {
        bool wide;
        if (buf[i] == '{' && buf[i + 1] == '"') {
            wide = false;
        } else if (buf[i] == '{' && buf[i + 1] == 0 && buf[i + 2] == '"' && buf[i + 3] == 0) {
            wide = true;
        } else {
            continue;
        }
        bool closed = false;
        size_t n = extract_json(raw, js, base + i, wide, &closed);
        if (n < 8) {
            continue;
        }
        bool definitive = false;
        int score = marker_score(js, &definitive);
        if (!definitive && score < 2) {
            continue;
        }
        uint32_t h = hash_str(js, n);
        if (seen_before(h)) {
            continue;
        }
        log_body(base + i, wide, js, n, score, closed);
    }
}

static void process_region(uintptr_t base, size_t size, unsigned char *scratch,
                           unsigned char *raw, char *js) {
    size_t off = 0;
    while (off < size) {
        size_t want = size - off;
        if (want > CHUNK) {
            want = CHUNK;
        }
        if (!safe_read(base + off, scratch, want)) {
            off += 0x1000;                /* skip a page, part of the region may fault */
            continue;
        }
        scan_chunk(base + off, scratch, want, raw, js);
        if (want < CHUNK) {
            break;
        }
        off += CHUNK - OVERLAP;
    }
}

static void *json_thread(void *arg) {
    (void)arg;
    unsigned char *scratch = (unsigned char *)malloc(CHUNK);
    unsigned char *raw = (unsigned char *)malloc(CAP * 2);
    char *js = (char *)malloc(CAP + 1);
    if (scratch == NULL || raw == NULL || js == NULL) {
        os_log(g_log, "%{public}s buffer alloc failed", TAG);
        free(scratch);
        free(raw);
        free(js);
        return NULL;
    }

    os_log(g_log, "%{public}s sweeping writable heap for the batch body, tap check for update", TAG);
    time_t start = time(NULL);
    long passes = 0;
    while (time(NULL) - start < RUN_SECONDS) {
        mach_vm_address_t addr = 0;
        while (1) {
            mach_vm_size_t rsize = 0;
            natural_t depth = 0;
            vm_region_submap_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
            kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &addr, &rsize, &depth,
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
            if (readable && writable && rsize <= MAX_REGION) {
                process_region((uintptr_t)addr, (size_t)rsize, scratch, raw, js);
            }
            addr += rsize;
        }
        passes++;
        if (passes % 50 == 0) {
            os_log(g_log, "%{public}s pass %ld, %u captures so far", TAG, passes, g_capture_id);
        }
        usleep(PASS_PAUSE_US);
    }

    os_log(g_log, "%{public}s sweep finished, %ld passes, %u captures", TAG, passes, g_capture_id);
    free(scratch);
    free(raw);
    free(js);
    return NULL;
}

__attribute__((constructor))
static void scjson_init(void) {
    g_log = os_log_create("com.soundcore.research", "json");
    os_log(g_log, "%{public}s loaded", TAG);
    pthread_t th;
    if (pthread_create(&th, NULL, json_thread, NULL) == 0) {
        pthread_detach(th);
    } else {
        os_log(g_log, "%{public}s pthread_create failed", TAG);
    }
}
