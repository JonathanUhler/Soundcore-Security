/*
 * scbody.m -- deterministic batch-request-body capturer for the OTA Batch Request
 * Capture plan. Replaces the passive heap race in scjson.c, which never caught the
 * body because the serialized string is freed faster than a full heap sweep.
 *
 * The vehicle is still the same passive, file backed, app signed dylib, and it is
 * still not a Frida agent and not an inline hook. It captures the body by ObjC
 * method swizzling, which the reinforcement SDK does not detect. The distinction
 * that matters, and the reason this survives where Frida dies, is that swizzling
 * changes DATA, not code. method_setImplementation swaps an IMP pointer inside a
 * class method list, a __DATA structure. The replacement function is ordinary,
 * validly signed code inside this dylib's __TEXT, which AMFI runs happily because
 * it is file backed. Nothing patches an existing instruction, nothing builds a
 * trampoline, and nothing allocates anonymous executable memory. Every detector the
 * SDK has demonstrated, HOOK_ATTACK, code integrity of function bytes, the _dladdr
 * code redirection checks, targets code tampering, so a data only IMP swap is
 * invisible to them. See the pivot writeup in
 * research/notes/2026-09-04_OTA-Batch-Request-Capture/Summary.md.
 *
 * Two choke points, both confirmed present in the binary, are swizzled.
 *
 *   +[NSJSONSerialization dataWithJSONObject:options:error:]. ObjectMapper and
 *     HandyJSON both funnel their dict to string step through this Foundation
 *     method, so the serialized JSON Data is captured at the instant it is
 *     produced, before it can be freed. There is no race, we are inside the call
 *     that makes it.
 *
 *   -[NSMutableURLRequest setHTTPBody:]. The network boundary. Whatever bytes the
 *     app is about to send, however they were built, pass through here. Filtered by
 *     the request URL so only the batch check body is logged.
 *
 * The replacement functions call the original implementation and return its result
 * unchanged, so behavior is identical and there is no functional tell. A captured
 * body is logged uncapped, chunked across os_log lines exactly like scjson, and
 * deduped by content so a body logs once across many taps.
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <os/log.h>
#include <os/lock.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define TAG "SCBODY"
#define SEG 160                   /* chars per os_log segment line */
#define MAX_BODY (256 * 1024)     /* sanity cap on a logged body */
#define SEEN_MAX 256              /* distinct bodies remembered for dedup */

static os_log_t g_log;
static uint32_t g_seen[SEEN_MAX];
static int g_seen_n;
static unsigned g_capture_id;
/* The two swizzles fire from whatever queue serializes or sends, so the dedup set
 * and the capture counter are guarded. A logged body holds the lock so its chunk
 * lines cannot interleave with another capture in the unified log. */
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;

/* OTA field markers, same set scjson used. firmwareList and firmware_list are the
 * definitive wrapper keys, the rest are item fields from the SCOTAMultipleItemStruct
 * reflection metadata in both key styles. The quoted forms carry their quotes so
 * they do not fire on substrings of longer keys like wifiVersion. */
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

/* Case sensitive substring search over a byte buffer that is not NUL terminated. */
static bool mem_contains(const char *hay, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (m == 0 || m > n) {
        return false;
    }
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, needle, m) == 0) {
            return true;
        }
    }
    return false;
}

static int marker_score(const char *b, size_t n, bool *definitive) {
    *definitive = false;
    int score = 0;
    for (int i = 0; i < MARKER_COUNT; i++) {
        if (mem_contains(b, n, MARKERS[i])) {
            score++;
            if (i < 2) {                 /* firmwareList / firmware_list */
                *definitive = true;
            }
        }
    }
    return score;
}

/* djb2 over the body, used to dedup captures without storing the strings. */
static uint32_t hash_bytes(const char *b, size_t n) {
    uint32_t h = 5381;
    for (size_t i = 0; i < n; i++) {
        h = h * 33u + (unsigned char)b[i];
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

/* Log a captured body uncapped, one header line, one line per SEG chunk with a
 * segment index, one footer line, because os_log truncates a single long argument.
 * The operator concatenates the seg payloads to get the exact body. */
static void log_body(const char *b, size_t n, const char *source, const char *url, int score) {
    unsigned id = ++g_capture_id;
    os_log(g_log, "%{public}s CAPTURE #%u src=%{public}s url=%{public}s len=%zu score=%d BEGIN",
           TAG, id, source, url ? url : "(none)", n, score);
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
        memcpy(part, b + off, len);
        part[len] = '\0';
        os_log(g_log, "%{public}s #%u seg %zu/%zu %{public}s", TAG, id, k + 1, segs, part);
    }
    os_log(g_log, "%{public}s CAPTURE #%u END", TAG, id);
}

/* Score, dedup, and log a candidate body. url is optional context. force logs
 * regardless of markers, used when the request URL already identifies the batch
 * endpoint so an unexpected body shape is still captured. */
static void consider(NSData *data, const char *source, const char *url, bool force) {
    if (data == nil) {
        return;
    }
    size_t n = (size_t)data.length;
    if (n < 8 || n > MAX_BODY) {
        return;
    }
    const char *b = (const char *)data.bytes;
    if (b == NULL) {
        return;
    }
    bool definitive = false;
    int score = marker_score(b, n, &definitive);
    if (!force && !definitive && score < 2) {
        return;
    }
    uint32_t h = hash_bytes(b, n);
    os_unfair_lock_lock(&g_lock);
    if (!seen_before(h)) {
        log_body(b, n, source, url, score);
    }
    os_unfair_lock_unlock(&g_lock);
}

/* Swizzle of +[NSJSONSerialization dataWithJSONObject:options:error:]. Calls the
 * original by saved IMP, never by objc_msgSend, so there is no recursion. */
typedef NSData *(*json_imp_t)(id, SEL, id, NSUInteger, NSError **);
static json_imp_t g_orig_json;

static NSData *hook_dataWithJSONObject(id self, SEL _cmd, id obj, NSUInteger opt, NSError **err) {
    NSData *result = g_orig_json(self, _cmd, obj, opt, err);
    @try {
        consider(result, "json", NULL, false);
    } @catch (__unused NSException *e) {
    }
    return result;
}

/* The request body is an encrypted envelope, not the plaintext JSON, and its
 * replay needs the exact headers the app paired with it, especially the token and
 * timestamp and any signature over the body. So the header setters are swizzled
 * too, filtered to the firmware endpoints, and the current header set is also
 * snapshotted when the body is set, since the app's adapter may add headers either
 * before or after the body. */
static NSString *req_url_string(id req) {
    @try {
        NSURL *u = [(NSURLRequest *)req URL];
        return u ? [u absoluteString] : nil;
    } @catch (__unused NSException *e) {
        return nil;
    }
}

static bool url_is_target(NSString *us) {
    if (us == nil) {
        return false;
    }
    return [us containsString:@"upgrade_check"] || [us containsString:@"firmware/upgrade"] ||
           [us containsString:@"speaker/firmware"];
}

static void dump_headers(id req) {
    @try {
        NSDictionary *h = [(NSURLRequest *)req allHTTPHeaderFields];
        for (id k in h) {
            os_log(g_log, "%{public}s HDRSNAP %{public}s: %{public}s", TAG,
                   [[k description] UTF8String], [[h[k] description] UTF8String]);
        }
    } @catch (__unused NSException *e) {
    }
}

/* Swizzle of -[NSMutableURLRequest setHTTPBody:]. Reads the request URL for context
 * and to force a capture when it is the batch endpoint, snapshots the headers set so
 * far, then calls the original. */
typedef void (*sethttpbody_imp_t)(id, SEL, NSData *);
static sethttpbody_imp_t g_orig_sethttpbody;

static void hook_setHTTPBody(id self, SEL _cmd, NSData *body) {
    @try {
        NSString *us = req_url_string(self);
        bool target = url_is_target(us);
        consider(body, "httpBody", us ? [us UTF8String] : NULL, target);
        if (target) {
            dump_headers(self);
        }
    } @catch (__unused NSException *e) {
    }
    g_orig_sethttpbody(self, _cmd, body);
}

/* Swizzle of -[NSMutableURLRequest setValue:forHTTPHeaderField:]. Logs each header
 * set on a firmware request, so a token or timestamp added after the body is still
 * captured. */
typedef void (*setvalue_imp_t)(id, SEL, NSString *, NSString *);
static setvalue_imp_t g_orig_setvalue;

static void hook_setValueForHTTPHeaderField(id self, SEL _cmd, NSString *value, NSString *field) {
    @try {
        NSString *us = req_url_string(self);
        if (url_is_target(us)) {
            os_log(g_log, "%{public}s HDR %{public}s: %{public}s", TAG,
                   field ? [field UTF8String] : "?", value ? [value UTF8String] : "");
        }
    } @catch (__unused NSException *e) {
    }
    g_orig_setvalue(self, _cmd, value, field);
}

/* Swizzle of -[NSMutableURLRequest setAllHTTPHeaderFields:]. Logs headers applied
 * wholesale, the way Alamofire's HTTPHeaders are. */
typedef void (*setallheaders_imp_t)(id, SEL, NSDictionary *);
static setallheaders_imp_t g_orig_setallheaders;

static void hook_setAllHTTPHeaderFields(id self, SEL _cmd, NSDictionary *fields) {
    @try {
        NSString *us = req_url_string(self);
        if (url_is_target(us)) {
            for (id k in fields) {
                os_log(g_log, "%{public}s HDRALL %{public}s: %{public}s", TAG,
                       [[k description] UTF8String], [[fields[k] description] UTF8String]);
            }
        }
    } @catch (__unused NSException *e) {
    }
    g_orig_setallheaders(self, _cmd, fields);
}

static void swizzle_class_method(const char *cls_name, SEL sel, IMP repl, IMP *saved) {
    Class cls = objc_getClass(cls_name);
    if (cls == Nil) {
        os_log(g_log, "%{public}s class %{public}s not found", TAG, cls_name);
        return;
    }
    Method m = class_getClassMethod(cls, sel);
    if (m == NULL) {
        os_log(g_log, "%{public}s class method %{public}s not found", TAG, cls_name);
        return;
    }
    *saved = method_getImplementation(m);
    method_setImplementation(m, repl);
    os_log(g_log, "%{public}s swizzled +[%{public}s ...]", TAG, cls_name);
}

static void swizzle_instance_method(const char *cls_name, SEL sel, IMP repl, IMP *saved) {
    Class cls = objc_getClass(cls_name);
    if (cls == Nil) {
        os_log(g_log, "%{public}s class %{public}s not found", TAG, cls_name);
        return;
    }
    Method m = class_getInstanceMethod(cls, sel);
    if (m == NULL) {
        os_log(g_log, "%{public}s instance method %{public}s not found", TAG, cls_name);
        return;
    }
    *saved = method_getImplementation(m);
    method_setImplementation(m, repl);
    os_log(g_log, "%{public}s swizzled -[%{public}s ...]", TAG, cls_name);
}

__attribute__((constructor))
static void scbody_init(void) {
    g_log = os_log_create("com.soundcore.research", "body");
    os_log(g_log, "%{public}s loaded, installing swizzles", TAG);

    swizzle_class_method("NSJSONSerialization",
                         @selector(dataWithJSONObject:options:error:),
                         (IMP)hook_dataWithJSONObject, (IMP *)&g_orig_json);

    swizzle_instance_method("NSMutableURLRequest",
                            @selector(setHTTPBody:),
                            (IMP)hook_setHTTPBody, (IMP *)&g_orig_sethttpbody);

    swizzle_instance_method("NSMutableURLRequest",
                            @selector(setValue:forHTTPHeaderField:),
                            (IMP)hook_setValueForHTTPHeaderField, (IMP *)&g_orig_setvalue);

    swizzle_instance_method("NSMutableURLRequest",
                            @selector(setAllHTTPHeaderFields:),
                            (IMP)hook_setAllHTTPHeaderFields, (IMP *)&g_orig_setallheaders);

    os_log(g_log, "%{public}s ready, tap check for update", TAG);
}
