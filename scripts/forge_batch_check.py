#!/usr/bin/env python3
"""Forge and probe the Soundcore OTA batch firmware check, reusing a captured request.

The batch endpoint api/v2/speaker/firmware/upgrade_check/batch does not take plaintext
JSON. The wire body is an encrypted envelope, base64( ts_ascii[16] || ciphertext ),
where the 16 byte prefix is a microsecond timestamp used as the cipher IV and the
ciphertext is a stream cipher, AES-CTR shaped, over the JSON. See
research/notes/2026-09-04_OTA-Batch-Request-Capture/Summary.md.

Two facts make this forgeable without the key. The cipher has no MAC, so it is
malleable, and the scbody.m dylib captured both the plaintext, at NSJSONSerialization,
and the ciphertext, at setHTTPBody, for the same request. XOR of the two recovers the
keystream, so any same length edit to the plaintext, for example lowering the version,
can be re encrypted by XOR with that keystream. A live replay confirmed the auth
headers, token and unique-sign, are body independent, so the captured headers are
reused unchanged with a forged body.

This script reads scbody.log, recovers the keystream, the IV prefix, and the headers
from the most recent captured batch request, then forges the body for each candidate
version. It prints the requests and does not send unless --send is given. Because the
response is itself an encrypted envelope, an update is inferred from the response data
length, the no update baseline is small and an update payload with lastPackage is much
larger. Reading lastPackage.url in the clear is a separate step, see the notes.

This posts to a third party production gateway. Be respectful, it sends one request per
candidate with a short delay.
"""
import argparse
import base64
import json
import re
import sys
import time
import urllib.request

BEGIN_RE = re.compile(r"SCBODY CAPTURE #(\d+) src=(\S+) url=(\S+) .*BEGIN")
SEG_RE = re.compile(r"SCBODY #(\d+) seg \d+/\d+ (.*)$")
HDRSNAP_RE = re.compile(r"SCBODY HDRSNAP ([^:]+): (.*)$")
VERSION_RE = re.compile(rb'"version":"([^"]*)"')

BATCH_PATH = "api/v2/speaker/firmware/upgrade_check/batch"


def b64d(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


def load_captures(lines):
    """Return a list of captures, each {num, src, url, line, payload}, in log order."""
    caps = []
    cur = None
    segs = {}
    for idx, ln in enumerate(lines):
        m = BEGIN_RE.search(ln)
        if m:
            cur = {"num": int(m.group(1)), "src": m.group(2), "url": m.group(3),
                   "line": idx, "payload": ""}
            caps.append(cur)
            segs[cur["num"]] = []
            continue
        ms = SEG_RE.search(ln)
        if ms:
            segs.setdefault(int(ms.group(1)), []).append(ms.group(2))
    for c in caps:
        c["payload"] = "".join(segs.get(c["num"], []))
    return caps


def load_header_sets(lines):
    """Parse contiguous runs of HDRSNAP lines into header dicts, in log order."""
    sets = []
    cur = None
    for ln in lines:
        m = HDRSNAP_RE.search(ln)
        if m:
            if cur is None:
                cur = {}
                sets.append(cur)
            cur[m.group(1).strip()] = m.group(2).strip()
        else:
            if "HDR " not in ln:      # a plain HDR line does not break the snapshot run
                cur = None
    return sets


def pick_request(caps, header_sets, want_ts):
    """Pick a batch httpBody capture, its paired plaintext, and its header set.

    Defaults to the most recent batch request. want_ts, if given, selects the request
    whose embedded timestamp seconds match it, so an older capture can be targeted.
    """
    bodies = [c for c in caps if c["src"] == "httpBody" and BATCH_PATH in c["url"]]
    if not bodies:
        sys.exit("no batch httpBody capture found in the log")
    chosen = None
    for c in reversed(bodies):
        secs = b64d(c["payload"])[:16].decode("latin1")[:10]
        if want_ts is None or secs == want_ts:
            chosen = c
            chosen["secs"] = secs
            break
    if chosen is None:
        sys.exit("no batch request matched --ts %s" % want_ts)

    # The plaintext is the nearest preceding json capture carrying firmware_list.
    plain = None
    for c in caps:
        if c["line"] < chosen["line"] and c["src"] == "json" and "firmware_list" in c["payload"]:
            plain = c
    if plain is None:
        sys.exit("no plaintext firmware_list json capture found before the body")

    # The header set is the snapshot whose X-Request-Ts matches the body timestamp.
    headers = None
    for hs in header_sets:
        if hs.get("X-Request-Ts") == chosen["secs"]:
            headers = hs
    if headers is None and header_sets:
        headers = header_sets[-1]
    if not headers:
        sys.exit("no HDRSNAP header set found in the log")
    return chosen, plain, headers


def recover(body_b64, plaintext):
    raw = b64d(body_b64)
    ts_prefix, ct = raw[:16], raw[16:]
    pt = plaintext.encode() if isinstance(plaintext, str) else plaintext
    if len(ct) != len(pt):
        sys.exit("ciphertext %d and plaintext %d length mismatch, wrong pair"
                 % (len(ct), len(pt)))
    ks = bytes(c ^ p for c, p in zip(ct, pt))
    return ts_prefix, ks, pt


def forge(ts_prefix, ks, pt, cur_ver, new_ver):
    if len(new_ver) != len(cur_ver):
        return None
    npt = pt.replace(b'"version":"%s"' % cur_ver.encode(),
                     b'"version":"%s"' % new_ver.encode())
    nct = bytes(p ^ k for p, k in zip(npt, ks))
    return base64.b64encode(ts_prefix + nct).decode(), npt


def send(url, headers, body, timeout):
    req = urllib.request.Request(url, data=body.encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            j = json.loads(r.read())
    except Exception as e:
        return None, "ERROR %s" % e, 0
    data = j.get("data") or ""
    dlen = len(b64d(data)) if data else 0
    return j.get("res_code"), j.get("message"), dlen


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default="scbody.log", help="scbody.dylib log to read")
    ap.add_argument("--ts", default=None,
                    help="target a specific captured request by its X-Request-Ts seconds, "
                         "default is the most recent batch request")
    ap.add_argument("--versions", default="14.42,14.00,13.00,10.00,01.00",
                    help="comma separated candidate versions, each must be the same length "
                         "as the captured version so the keystream stays aligned")
    ap.add_argument("--host", default="speaker.eufylife.com")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--delay", type=float, default=0.6, help="seconds between sent requests")
    ap.add_argument("--send", action="store_true", help="actually send, default prints only")
    args = ap.parse_args()

    try:
        lines = open(args.log).read().splitlines()
    except OSError as e:
        sys.exit("cannot read %s: %s" % (args.log, e))

    caps = load_captures(lines)
    header_sets = load_header_sets(lines)
    body_cap, plain_cap, headers = pick_request(caps, header_sets, args.ts)
    ts_prefix, ks, pt = recover(body_cap["payload"], plain_cap["payload"])

    m = VERSION_RE.search(pt)
    cur_ver = m.group(1).decode() if m else ""
    url = "https://%s/%s" % (args.host, BATCH_PATH)

    print("=== recovered from %s ===" % args.log)
    print("  batch body capture : #%d" % body_cap["num"])
    print("  plaintext capture  : #%d  %s" % (plain_cap["num"], pt.decode()))
    print("  IV prefix (ts)     : %s" % ts_prefix.decode("latin1"))
    print("  X-Request-Ts       : %s" % headers.get("X-Request-Ts"))
    print("  token / unique-sign: %s / %s" % (headers.get("token"), headers.get("unique-sign")))
    print("  current version    : %s (candidates must be %d chars)" % (cur_ver, len(cur_ver)))
    print("  url                : %s" % url)

    # The captured version is the control, it should report no update.
    candidates = [cur_ver] + [v for v in args.versions.split(",") if v and v != cur_ver]

    print("\n=== %s ===" % ("sending" if args.send else "dry run, pass --send to POST"))
    for v in candidates:
        f = forge(ts_prefix, ks, pt, cur_ver, v)
        if f is None:
            print("%8s -> skipped, length != %d" % (v, len(cur_ver)))
            continue
        body, npt = f
        if not args.send:
            print("%8s -> %s" % (v, body))
            continue
        code, msg, dlen = send(url, headers, body, args.timeout)
        flag = "  <== update?" if code == 1 and dlen > 128 else ""
        print("%8s -> res_code=%s msg=%s data_len=%d%s" % (v, code, msg, dlen, flag))
        time.sleep(args.delay)

    if not args.send:
        print("\n[dry-run] no requests sent. Re-run with --send to probe the endpoint.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
