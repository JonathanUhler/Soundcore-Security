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
 *   +[NSJSONSerialization JSONObjectWithData:options:error:]. The deserialization
 *     side. The batch response is an encrypted envelope, so the app decrypts it and
 *     parses the plaintext here. Capturing the input reads the decrypted response,
 *     needUpdate and any lastPackage url, with no key needed.
 *
 * The MONITOR_ONLY flag at the top forces strictly read only operation. It makes no
 * edits at all, no tamper strip, no value scrub, no matched inject, and it captures
 * every body it sees by bypassing the marker score filter, so nothing is missed. It
 * overrides every active test below. Use it to survey a new device before rewriting.
 *
 * Mostly the hooks only observe, but the serialization hook can also modify the
 * outgoing body before the app encrypts and signs it, for the active tests set at the
 * top of the file. strip_tamper_events drops the reinforcement SDK's three tamper
 * telemetry events from the object graph before serialization. rewrite_body then
 * rewrites identifying values, the version, serial, MAC, and analytics anonymous id,
 * across every outgoing body, the telemetry and the check alike, because the backend
 * cross references telemetry so a value must move everywhere at once. INJECT_MATCHED
 * adds matched:true to the firmware_list request. All are data only changes, the app
 * does its own crypto, so the anti tamper sees nothing, and auth is body independent so
 * the token and unique-sign still verify. A captured body is logged uncapped, chunked
 * across os_log lines exactly like scjson, and deduped by content so a body logs once
 * across many taps.
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

/* Master switch, monitor mode. When true the library is strictly read only. It makes no
 * edits at all, no tamper event strip, no value scrub, no matched inject, and it captures
 * every body it sees, bypassing the marker score filter so nothing is missed. This
 * overrides all the active test flags below. Use it to survey a new device, like the
 * Sleep A30, D1301S, and see what differs before deciding what to rewrite. */
static const bool MONITOR_ONLY = true;

/* Active test one, the matched flag. Tested and had no effect on the response, the
 * server ignores it for this device, so it is off. When true the serialization hook
 * injects "matched":true into the outgoing firmware_list body. */
static const bool INJECT_MATCHED = false;

/* Active test two, the value scrub. rewrite_body rewrites each FROM value to its TO
 * value in every outgoing body before the app encrypts and sends it, across the device
 * report telemetry and the upgrade check alike. The backend cross references telemetry,
 * so lowering the version only in the check is rejected but lowering it everywhere at
 * once is accepted. The serial, MAC, and analytics anonymous id are scrubbed the same
 * way to strip identity the backend could pin on. All are data only changes, the app
 * does its own crypto so the anti tamper sees nothing, and auth is body independent so
 * the token and unique-sign still verify. An empty FROM disables that one rewrite. */
static const char *VERSION_FROM = "14.43";
static const char *VERSION_TO = "14.42";

static const char *SN_FROM = "3949E7BDE52DB6F4";
static const char *SN_TO = "3949000000000000";

static const char *MAC_UPPER_FROM = "F4:B6:2D:E5:BD:E7";
static const char *MAC_UPPER_TO = "00:00:00:00:00:00";
static const char *MAC_LOWER_FROM = "f4:b6:2d:e5:bd:e7";
static const char *MAC_LOWER_TO = "00:00:00:00:00:00";

/* The analytics anonymous id. anonymous_id and distinct_id come from the
 * SensorsAnalytics SDK and are the only identifiers that survive an app reinstall,
 * because the SDK keychain-persists them on iOS. They ride the analytics collector,
 * not the firmware host, but the backend cross references telemetry, so a stable
 * device identity is scrubbed to a synthetic one. The value is replaced globally, by
 * its literal, so anonymous_id, distinct_id, and $identity_anonymous_id all change
 * together. Empty ANON_FROM disables the scrub. */
static const char *ANON_FROM = "25175005-856F-4AAB-A276-01988F6459F5";
static const char *ANON_TO = "7F3C1A2B-4D5E-4F6A-9B8C-0D1E2F3A4B5C";

/* Active test three, the tamper telemetry strip. On detecting this dylib the
 * reinforcement SDK emits three telemetry events. When STRIP_TAMPER is true they are
 * dropped from any outgoing body before it is serialized, so the backend never receives
 * a tamper flag for this install. The names are matched exactly against event.name. */
static const bool STRIP_TAMPER = true;
static const char *const TAMPER_EVENT_NAMES[] = {
    "APP_FIRM_NON_APPSTORE_DOWNLOAD",
    "APP_FIRM_SIGNATURE_TAMPER",
    "JMDetectionResultJailBreak",
};
#define TAMPER_NAME_COUNT ((int)(sizeof(TAMPER_EVENT_NAMES) / sizeof(TAMPER_EVENT_NAMES[0])))

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
    /* response side fields, so a decrypted upgrade_check response is caught too */
    "needUpdate", "lastPackage", "currentFirmware", "change_log", "firmware_code",
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
    if (!force && !MONITOR_ONLY && !definitive && score < 2) {
        return;
    }
    uint32_t h = hash_bytes(b, n);
    os_unfair_lock_lock(&g_lock);
    if (!seen_before(h)) {
        log_body(b, n, source, url, score);
    }
    os_unfair_lock_unlock(&g_lock);
}

/* If body is the outgoing firmware_list request and does not already carry a matched
 * field, return a copy with "matched":true inserted as the first key of the item
 * object, otherwise return nil. The insert point is right after the item open "[{",
 * which the batch body has exactly once, so the result is well formed JSON. The app
 * then encrypts and signs this returned Data, and auth is body independent, so the
 * token and unique-sign still verify. */
static NSData *inject_matched(NSData *body) {
    if (body == nil) {
        return nil;
    }
    size_t n = (size_t)body.length;
    const char *b = (const char *)body.bytes;
    if (b == NULL || n < 16 || n > MAX_BODY) {
        return nil;
    }
    if (!mem_contains(b, n, "firmware_list") || mem_contains(b, n, "\"matched\"")) {
        return nil;
    }
    long at = -1;
    for (size_t i = 0; i + 1 < n; i++) {
        if (b[i] == '[' && b[i + 1] == '{') {
            at = (long)(i + 2);         /* just inside the item object */
            break;
        }
    }
    if (at < 0) {
        return nil;
    }
    const char *ins = "\"matched\":true,";
    NSMutableData *out = [NSMutableData dataWithCapacity:n + 16];
    [out appendBytes:b length:(NSUInteger)at];
    [out appendBytes:ins length:strlen(ins)];
    [out appendBytes:b + at length:n - (NSUInteger)at];
    return out;
}

/* Drop the reinforcement SDK's anti tamper telemetry from an outgoing object before it
 * is serialized. The telemetry is a top level dictionary with an "events" array, each
 * event a dictionary with a "name". Any event whose name is in TAMPER_EVENT_NAMES is
 * removed, and a shallow mutable copy of the dictionary with the filtered array is
 * returned, or nil if nothing matched so the caller serializes the original untouched.
 * This is object graph editing, still data only, and it yields guaranteed valid JSON,
 * unlike excising an object from the serialized string. */
static bool is_tamper_name(NSString *name) {
    for (int i = 0; i < TAMPER_NAME_COUNT; i++) {
        if ([name isEqualToString:@(TAMPER_EVENT_NAMES[i])]) {
            return true;
        }
    }
    return false;
}

static id strip_tamper_events(id obj) {
    if (!STRIP_TAMPER || ![obj isKindOfClass:[NSDictionary class]]) {
        return nil;
    }
    NSDictionary *dict = (NSDictionary *)obj;
    id events = dict[@"events"];
    if (![events isKindOfClass:[NSArray class]]) {
        return nil;
    }
    NSArray *in = (NSArray *)events;
    NSMutableArray *kept = [NSMutableArray arrayWithCapacity:in.count];
    NSMutableArray *removed = [NSMutableArray array];
    for (id e in in) {
        id name = [e isKindOfClass:[NSDictionary class]] ? ((NSDictionary *)e)[@"name"] : nil;
        if ([name isKindOfClass:[NSString class]] && is_tamper_name(name)) {
            [removed addObject:name];
            continue;
        }
        [kept addObject:e];
    }
    if (removed.count == 0) {
        return nil;
    }
    NSMutableDictionary *out = [dict mutableCopy];
    out[@"events"] = kept;
    os_log(g_log, "%{public}s STRIP removed %lu tamper event(s): %{public}s", TAG,
           (unsigned long)removed.count, [[removed componentsJoinedByString:@","] UTF8String]);
    return out;
}

/* Rewrite identifying values in an outgoing serialized body, returning a modified copy
 * or nil if nothing changed. The version is field qualified so only the true version
 * fields move and a value like an app version is left alone. The serial, MAC, and
 * analytics anonymous id are scrubbed by their literal value, so every field that
 * carries them, "sn", "device_sn", "identity_deviceid_sn", "anonymous_id",
 * "distinct_id", "$identity_anonymous_id", is caught at once. The app re-encrypts, so
 * the replacement need not preserve length, and auth is body independent so the token
 * and unique-sign still verify. An empty FROM disables that one rewrite. */
static NSData *rewrite_body(NSData *body) {
    if (body == nil) {
        return nil;
    }
    NSUInteger n = body.length;
    if (n < 8 || n > MAX_BODY) {
        return nil;
    }
    NSString *s = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (s == nil) {
        return nil;
    }
    NSMutableArray<NSArray<NSString *> *> *subs = [NSMutableArray array];
    if (strlen(VERSION_FROM) > 0) {
        NSString *vf = @(VERSION_FROM), *vt = @(VERSION_TO);
        [subs addObject:@[ [NSString stringWithFormat:@"\"firmware_version\":\"%@\"", vf],
                           [NSString stringWithFormat:@"\"firmware_version\":\"%@\"", vt] ]];
        [subs addObject:@[ [NSString stringWithFormat:@"\"version\":\"%@\"", vf],
                           [NSString stringWithFormat:@"\"version\":\"%@\"", vt] ]];
    }
    if (strlen(SN_FROM) > 0) {
        [subs addObject:@[ @(SN_FROM), @(SN_TO) ]];
    }
    if (strlen(MAC_UPPER_FROM) > 0) {
        [subs addObject:@[ @(MAC_UPPER_FROM), @(MAC_UPPER_TO) ]];
    }
    if (strlen(MAC_LOWER_FROM) > 0) {
        [subs addObject:@[ @(MAC_LOWER_FROM), @(MAC_LOWER_TO) ]];
    }
    if (strlen(ANON_FROM) > 0) {
        [subs addObject:@[ @(ANON_FROM), @(ANON_TO) ]];
    }
    NSString *out = s;
    for (NSArray<NSString *> *pair in subs) {
        out = [out stringByReplacingOccurrencesOfString:pair[0] withString:pair[1]];
    }
    if ([out isEqualToString:s]) {
        return nil;
    }
    return [out dataUsingEncoding:NSUTF8StringEncoding];
}

/* Swizzle of +[NSJSONSerialization dataWithJSONObject:options:error:]. Calls the
 * original by saved IMP, never by objc_msgSend, so there is no recursion. It applies
 * the active tests, the tamper event strip, the value scrub, and the matched
 * injection, to the outgoing body before the app encrypts and sends it. */
typedef NSData *(*json_imp_t)(id, SEL, id, NSUInteger, NSError **);
static json_imp_t g_orig_json;

static NSData *hook_dataWithJSONObject(id self, SEL _cmd, id obj, NSUInteger opt, NSError **err) {
    /* Object graph edit before serialization, drop the anti tamper telemetry events so
     * the serialized body the app encrypts never carries a tamper flag. Skipped whole in
     * monitor mode, where the library never edits anything. */
    id to_serialize = obj;
    if (!MONITOR_ONLY) {
        @try {
            id cleaned = strip_tamper_events(obj);
            if (cleaned != nil) {
                to_serialize = cleaned;
            }
        } @catch (__unused NSException *e) {
        }
    }
    NSData *result = g_orig_json(self, _cmd, to_serialize, opt, err);
    @try {
        consider(result, to_serialize == obj ? "json" : "json-strip", NULL, to_serialize != obj);
        if (!MONITOR_ONLY) {
            NSData *mod = result;
            if (INJECT_MATCHED) {
                NSData *m = inject_matched(mod);
                if (m != nil) {
                    mod = m;
                }
            }
            NSData *v = rewrite_body(mod);
            if (v != nil) {
                mod = v;
            }
            if (mod != result) {
                os_log(g_log, "%{public}s MODIFY %lu -> %lu bytes", TAG,
                       (unsigned long)result.length, (unsigned long)mod.length);
                consider(mod, "json-mod", NULL, true);
                return mod;             /* the app encrypts and signs this instead */
            }
        }
    } @catch (__unused NSException *e) {
    }
    return result;
}

/* Swizzle of +[NSJSONSerialization JSONObjectWithData:options:error:]. This is the
 * deserialization side, where HandyJSON turns a JSON string into a dictionary. The
 * batch response is an encrypted envelope, so the app decrypts it and then parses the
 * plaintext through this method. Capturing the input Data here reads the decrypted
 * response, needUpdate and any lastPackage or currentFirmware url, with no key needed.
 * The input is inspected, never modified, so parsing is unaffected. */
typedef id (*jsonobject_imp_t)(id, SEL, NSData *, NSUInteger, NSError **);
static jsonobject_imp_t g_orig_jsonobject;

static id hook_JSONObjectWithData(id self, SEL _cmd, NSData *data, NSUInteger opt, NSError **err) {
    id result = g_orig_jsonobject(self, _cmd, data, opt, err);
    @try {
        consider(data, "resp", NULL, false);
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
    os_log(g_log, "%{public}s loaded, installing swizzles, mode=%{public}s", TAG,
           MONITOR_ONLY ? "MONITOR (read only)" : "ACTIVE (rewrites on)");

    swizzle_class_method("NSJSONSerialization",
                         @selector(dataWithJSONObject:options:error:),
                         (IMP)hook_dataWithJSONObject, (IMP *)&g_orig_json);

    swizzle_class_method("NSJSONSerialization",
                         @selector(JSONObjectWithData:options:error:),
                         (IMP)hook_JSONObjectWithData, (IMP *)&g_orig_jsonobject);

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
