#!/usr/bin/env python3
"""Signed firmware check-for-update client for the Soundcore speaker API.

This reproduces the Anker commonkit aknetwork request signing recovered from the
iOS binary, so the firmware update endpoint returns lastPackage.url for the P20i.
Once the URL is in hand the firmware itself downloads from an unpinned CDN with no
signing, see research/notes/2026-08-30_App-Dex-Analysis/Capture-Resolution-And-OTA-API.md.

Signing scheme, session tier, recovered from FUN_102d78190 in the iOS app. See
research/notes/2026-09-03_iOS-Custom-Dylib-Monitor/Signing-Scheme-iOS-Recovery.md.

  X-Signature = lowercase_hex( HMAC_SHA256( clientSecret, message ) )
  message     = ts + "+" + once                     (no body)
              = ts + "+" + once + "+" + body         (with body)

Headers, Client-id and X-Client-Credential both carry clientId, X-Request-Ts is
the timestamp, X-Request-Once is the nonce, X-Signature is the signature. The
interceptor reads the timestamp and nonce back from the request to sign them, so
this sends its own values and signs those exact values, which is self consistent.

Credentials are Swift string literals recovered from the iOS __TEXT, the clientId
at 0x103999660 and the clientSecret at 0x1039996b0.

This posts to a third party production gateway. It prints the request and does not
send unless --send is given, and it makes at most one request. Be respectful.
"""
import argparse
import hashlib
import hmac
import json
import secrets
import sys
import time

# Recovered iOS credentials. clientId is the paired identifier, clientSecret is
# the HMAC key. Swap with --swap if the assignment is reversed.
CLIENT_ID_DEFAULT = "109c01b71e210048304bd70a1c971d33"
CLIENT_SECRET_DEFAULT = "b1c3d818cc952ed054676a7b6a736ad4"

DEFAULT_HOST = "speaker.eufylife.com"
DEFAULT_PRODUCT = "A3949"          # the P20i
DEFAULT_SN = "3949E7BDE52DB6F4"    # derivable from the BT MAC, see MITM-Analysis.md
DEFAULT_VERSION = "1.00"           # a low version so the server reports an update


def build_body(args):
    # OtaRequestModel. Compact separators so the signed string is the exact byte
    # sequence sent as the body.
    body_obj = {
        "product_code": args.product_code,
        "sn": args.sn,
        "version": args.version,
        "matched": False,
    }
    return json.dumps(body_obj, separators=(",", ":"))


def sign(client_secret, ts, once, body, include_body):
    if include_body and body is not None:
        message = "%s+%s+%s" % (ts, once, body)
    else:
        message = "%s+%s" % (ts, once)
    mac = hmac.new(client_secret.encode("utf-8"), message.encode("utf-8"),
                   hashlib.sha256).hexdigest()
    return message, mac


def build_request(args):
    client_id = args.client_id
    client_secret = args.client_secret
    if args.swap:
        client_id, client_secret = client_secret, client_id

    ts = str(int(time.time() * (1000 if args.ts_unit == "ms" else 1)))
    once = args.once if args.once else secrets.token_hex(16)

    body = build_body(args)
    message, signature = sign(client_secret, ts, once, body, not args.no_body)

    url = "https://%s/v1/speaker/sound_core/%s/firmware/update" % (args.host, args.product_code)
    headers = {
        "Content-Type": "application/json",
        # The recovered signing headers.
        "X-Signature": signature,
        "X-Request-Ts": ts,
        "X-Request-Once": once,
        "Client-id": client_id,
        "X-Client-Credential": client_id,
        # Contextual identity headers, matching the iOS app.
        "AnkerBG": "SPEAKER",
        "country": args.country,
        "language": args.language,
        "uid": "",
        "app_version": args.app_version,
        "os_type": "ios",
        "os_version": "26.5.1",
        "phone_model": "iPhone",
        "timezone": "America/Los_Angeles",
        "openudid": args.openudid,
        "User-Agent": args.user_agent,
    }
    if args.key_ident:
        headers["X-Key-Ident"] = args.key_ident
    # The endpoint gates on an access token before it evaluates the signature.
    # The unsigned probe and this signed request both return 406 "Access token
    # expired" until a valid token is supplied. gtoken is the app level token,
    # Authorization is the user bearer token. Pass whichever the endpoint needs,
    # captured live from the app. Authorization usually wants a "Bearer " prefix.
    if args.gtoken:
        headers["gtoken"] = args.gtoken
    if args.authorization:
        headers["Authorization"] = args.authorization
    return url, headers, body, message, client_id, client_secret


def show(url, headers, body, message, client_id, client_secret):
    print("=== signing ===")
    print("  clientId    : %s" % client_id)
    print("  clientSecret: %s" % client_secret)
    print("  message     : %s" % message)
    print("  X-Signature : %s" % headers["X-Signature"])
    print("=== request ===")
    print("POST", url)
    for k, v in headers.items():
        print("  %s: %s" % (k, v))
    print("  body: %s" % body)


def interpret(status):
    if status == 200:
        return ("200. If the body carries firmware metadata, the signature was accepted. Look for a\n"
                "lastPackage.url and an md5. If the body is an error envelope, read its code, the\n"
                "gateway accepted the request but the app layer rejected it.")
    if status in (401, 403):
        return "%d. The signature was rejected. Try --swap, --no-body, or --ts-unit s." % status
    if status == 404:
        return ("404. APISIX hides routes from clients it does not authenticate, so this most likely\n"
                "means the signature was not accepted and the request was dropped. Try --swap,\n"
                "--no-body, --ts-unit s, then reconsider the credentials with a live re-dump.")
    return "%d. Unexpected. Inspect the body and headers above." % status


def main():
    ap = argparse.ArgumentParser(description="Signed probe of the Soundcore firmware upgrade API.")
    ap.add_argument("--client-id", default=CLIENT_ID_DEFAULT)
    ap.add_argument("--client-secret", default=CLIENT_SECRET_DEFAULT)
    ap.add_argument("--swap", action="store_true",
                    help="swap the clientId and clientSecret roles")
    ap.add_argument("--no-body", action="store_true",
                    help="sign ts+once only, omit the body from the signed message")
    ap.add_argument("--ts-unit", choices=["ms", "s"], default="ms",
                    help="timestamp unit, milliseconds or seconds")
    ap.add_argument("--once", default="", help="fixed nonce, default is random")
    ap.add_argument("--key-ident", default="", help="optional X-Key-Ident header value")
    ap.add_argument("--gtoken", default="", help="app level token, captured live from the app")
    ap.add_argument("--authorization", default="",
                    help="user bearer token, usually needs a 'Bearer ' prefix")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--product-code", default=DEFAULT_PRODUCT)
    ap.add_argument("--sn", default=DEFAULT_SN)
    ap.add_argument("--version", default=DEFAULT_VERSION,
                    help="current firmware version, a low value asks for an update")
    ap.add_argument("--country", default="US")
    ap.add_argument("--language", default="en")
    ap.add_argument("--app-version", default="5.0.02")
    ap.add_argument("--openudid", default="00000000-0000-0000-0000-000000000000")
    ap.add_argument("--user-agent", default="Soundcore-iOS-5.0.02")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--send", action="store_true", help="actually send, default prints only")
    args = ap.parse_args()

    url, headers, body, message, client_id, client_secret = build_request(args)
    show(url, headers, body, message, client_id, client_secret)

    if not args.send:
        print("\n[dry-run] not sending. Pass --send to POST one request.")
        return 0

    try:
        import requests
    except ImportError:
        print("\nrequests is not installed. Run: pip install requests", file=sys.stderr)
        return 2

    print("\n=== sending (one request) ===")
    try:
        r = requests.post(url, headers=headers, data=body.encode("utf-8"), timeout=args.timeout)
    except Exception as e:
        print("request failed: %s" % e)
        return 1

    print("HTTP %d" % r.status_code)
    for k, v in r.headers.items():
        print("  %s: %s" % (k, v))
    print("\n=== body ===")
    try:
        print(json.dumps(r.json(), indent=2)[:4000])
    except ValueError:
        print(r.text[:4000])

    print("\n=== interpretation ===")
    print(interpret(r.status_code))
    return 0


if __name__ == "__main__":
    sys.exit(main())
