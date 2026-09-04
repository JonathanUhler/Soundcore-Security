#!/usr/bin/env python3
"""Signed firmware check-for-update client for the Soundcore speaker API.

This reproduces the Anker commonkit aknetwork request signing recovered from the
iOS binary, so the firmware update endpoint returns lastPackage.url for the P20i.
Once the URL is in hand the firmware itself downloads from an unpinned CDN with no
signing, see research/notes/2026-08-30_App-Dex-Analysis/Capture-Resolution-And-OTA-API.md.

Signing scheme, session tier, recovered from FUN_102d78190 in the iOS app. See
research/notes/2026-09-03_iOS-Custom-Dylib-Monitor/Signing-Scheme-iOS-Recovery.md
and the offline resolution in Signature-Offline-Resolution.md.

  X-Signature = lowercase_hex( HMAC_SHA256( clientSecret, message ) )
  message     = ts + "+" + once                     (no body)
              = ts + "+" + once + "+" + body         (with body)

X-Client-Credential is not the clientId literal. The interceptor FUN_102d7097c
computes it from the bootstrap signer FUN_102d78e9c, a plain SHA-256, over the
Client-id header value concatenated with ts, once, and the bootstrap secret, no
separators. The base header builder FUN_102d388ec sends Client-id empty for a
logged out app level call, and nothing in the pipeline fills it, so:

  X-Client-Credential = lowercase_hex( SHA256( clientId + ts + once + secret ) )
  Client-id           = ""      (empty, logged out)
  secret              = ""      (bootstrap secret, empty in this config)
                      => X-Client-Credential = SHA256_hex( ts + once )

The same ts and once feed both the signature and the credential hash, matching the
interceptor. X-Request-Ts is the timestamp, X-Request-Once is the nonce.

Credentials are Swift string literals recovered from the iOS __TEXT, the clientId
at 0x103999660 and the clientSecret at 0x1039996b0. The clientSecret is the HMAC
key. The clientId is available for --client-id-header but is not sent by default.

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
import uuid

# Recovered iOS credentials. clientId is the paired identifier, clientSecret is
# the HMAC key. Swap with --swap if the assignment is reversed.
CLIENT_ID_DEFAULT = "109c01b71e210048304bd70a1c971d33"
CLIENT_SECRET_DEFAULT = "b1c3d818cc952ed054676a7b6a736ad4"

DEFAULT_HOST = "speaker.eufylife.com"
DEFAULT_PRODUCT = "A3949"          # the P20i
DEFAULT_SN = "3949E7BDE52DB6F4"    # derivable from the BT MAC, see MITM-Analysis.md
DEFAULT_VERSION = "1.00"           # a low version so the server reports an update

# A live token+timestamp pair captured off the unpinned log.eufylife.com telemetry.
# The server checks only that token == md5(timestamp + secret), not that the timestamp
# is recent, so this pair does not expire and is a reusable credential. Confirmed still
# accepted, res_code 1 SUCCESS, on a later day. See Eufy-Token-Scheme.md.
DEFAULT_EUFY_TIMESTAMP = "1788043091"
DEFAULT_EUFY_TOKEN = "361ec02987361d207d05392b9f0d89e4"


def build_body(args):
    # Raw override for fast iteration. The eufy token is body independent, so any body
    # can be tried without re-auth. Use this to probe the batch schema by hand.
    if args.raw_body:
        return args.raw_body
    # Two request shapes. The simple sound_core endpoint takes an OtaRequestModel.
    # The iOS app actually checks firmware through the batch endpoint, which takes
    # SCOTAMultipleRequestModel, an object with a firmware_list of FirmwareRequestModel.
    # The batch entry carries product_component and product_language, which the P20i
    # per component firmware likely needs, and which the simple model has no field for.
    if args.batch:
        entry = {
            "product_code": args.product_code,
            "sn": args.sn,
            "version": args.version,
            "matched": args.matched,
        }
        if args.product_component != "":
            entry["product_component"] = args.product_component
        if args.product_language != "":
            entry["product_language"] = args.product_language
        if args.base_version != "":
            entry["base_version"] = args.base_version
        # The iOS model SCOTAMultipleRequestModel wraps the list under firmwareList,
        # camelCase. The snake_case firmware_list from the Android model is not in the
        # iOS binary and returned 400 Err_InvalidRequest, so the default is firmwareList.
        body_obj = {args.batch_key: [entry]}
    else:
        body_obj = {
            "product_code": args.product_code,
            "sn": args.sn,
            "version": args.version,
            "matched": args.matched,
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


def client_credential(client_id_header, ts, once, bootstrap_secret):
    # The bootstrap signer FUN_102d78e9c, a plain SHA-256 over the concatenation
    # with no separators. clientIdValue is the Client-id header value, empty for a
    # logged out app level call, and secret is the bootstrap secret, empty here.
    message = "%s%s%s%s" % (client_id_header, ts, once, bootstrap_secret)
    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return message, digest


def gtoken(identity):
    # gtoken = md5_hex(identity). The hasher FUN_102d42cbc, initialised by
    # FUN_102d41b38 which fills the 64-entry MD5 sine constant table, so it is MD5.
    # The identity is the userId when logged in, the touristId for a guest. This
    # matches the public gtoken = md5(user_id) recovery.
    return hashlib.md5(identity.encode("utf-8")).hexdigest()


def eufy_token(timestamp_s, localkey):
    # The eufylife.com hosts, speaker and log, sign with a token header, not the
    # soundcore X-Signature. The MITM flows show token = md5(timestamp + secret),
    # body and path independent, keyed on an app global secret, the makeitreal
    # regional localKey. See MITM-Analysis.md and Eufy-Token-Scheme.md. The exact
    # concatenation is a guess until the localKey is recovered, so this is only for
    # the localKey path. The capture and replay path passes token directly.
    return hashlib.md5((timestamp_s + localkey).encode("utf-8")).hexdigest()


def build_request(args):
    client_id = args.client_id
    client_secret = args.client_secret
    if args.swap:
        client_id, client_secret = client_secret, client_id

    ts = str(int(time.time() * (1000 if args.ts_unit == "ms" else 1)))
    once = args.once if args.once else secrets.token_hex(16)

    body = build_body(args)
    message, signature = sign(client_secret, ts, once, body, not args.no_body)

    # The Client-id header value, empty by default to match the logged out app.
    # X-Client-Credential is the bootstrap SHA-256 over that value plus ts, once,
    # and the bootstrap secret, using the same ts and once as the signature.
    client_id_header = args.client_id_header
    cred_message, client_cred = client_credential(client_id_header, ts, once, args.bootstrap_secret)

    # Guest identity. The app authenticates logged out calls with a tourist session,
    # not a user account. The identity injector FUN_102ee542c sets uid to the tourist
    # or user id and gtoken to md5 of it, when the session flag is set. A guest has an
    # empty user token, so Authorization stays empty. --tourist-id supplies the id,
    # --gen-tourist-id makes a random one, and --gtoken overrides the computed hash if
    # a real value was captured from the app.
    tourist_id = args.tourist_id
    if args.gen_tourist_id and not tourist_id:
        tourist_id = str(uuid.uuid4())
    uid_header = tourist_id
    gtoken_header = args.gtoken if args.gtoken else (gtoken(tourist_id) if tourist_id else "")

    if args.batch:
        url = "https://%s/%s" % (args.host, args.batch_path.lstrip("/"))
    else:
        url = "https://%s/v1/speaker/sound_core/%s/firmware/update" % (args.host, args.product_code)
    headers = {
        "Content-Type": "application/json",
        # The recovered signing headers.
        "X-Signature": signature,
        "X-Request-Ts": ts,
        "X-Request-Once": once,
        "Client-id": client_id_header,
        "X-Client-Credential": client_cred,
        # Contextual identity headers, matching the iOS app.
        "AnkerBG": "SPEAKER",
        "country": args.country,
        "language": args.language,
        "uid": uid_header,
        "app_version": args.app_version,
        "os_type": "ios",
        "os_version": "26.5.1",
        "phone_model": "iPhone",
        "timezone": "America/Los_Angeles",
        "openudid": args.openudid,
        "User-Agent": args.user_agent,
    }
    if gtoken_header:
        headers["gtoken"] = gtoken_header
    if args.key_ident:
        headers["X-Key-Ident"] = args.key_ident
    # The endpoint gates on a session token before it evaluates the signature. The
    # app authenticates logged out calls with a tourist session, so the missing input
    # is gtoken, computed above from the tourist id. Authorization is the user bearer
    # token, only present when signed into an account, usually with a "Bearer " prefix.
    if args.authorization:
        headers["Authorization"] = args.authorization

    # Eufy scheme. The firmware host speaker.eufylife.com is eufy infrastructure and
    # signs with a token plus timestamp, the same headers the unpinned log.eufylife.com
    # telemetry carries. The token is md5(timestamp + localKey), body and path
    # independent, so a token captured for a timestamp is valid for any request at that
    # timestamp within the freshness window. Two ways to supply it.
    #   Capture and replay, no secret needed. Grab a live timestamp and token pair off
    #     log.eufylife.com, which is unpinned, and pass --eufy-timestamp and --eufy-token.
    #   localKey, once recovered. Pass --eufy-localkey and the token is computed for a
    #     fresh timestamp.
    if args.eufy or args.eufy_token or args.eufy_localkey:
        ts_s = args.eufy_timestamp if args.eufy_timestamp else str(int(time.time()))
        # localKey wins when given, so it recomputes the token rather than using the
        # default captured token. With the default timestamp this also verifies the
        # localKey, the computed token must equal the known captured token.
        if args.eufy_localkey:
            token = eufy_token(ts_s, args.eufy_localkey)
        elif args.eufy_token:
            token = args.eufy_token
        else:
            token = ""
        if not args.keep_soundcore:
            # Send only the eufy scheme, since the soundcore signing headers belong to
            # a different backend and are what the earlier probes wrongly sent.
            for k in ("X-Signature", "X-Request-Ts", "X-Request-Once", "Client-id",
                      "X-Client-Credential", "gtoken", "uid", "X-Key-Ident"):
                headers.pop(k, None)
        headers["timestamp"] = ts_s
        if token:
            headers["token"] = token
        headers["phone_virtual_id"] = args.phone_virtual_id or args.openudid
    return url, headers, body, message, cred_message, client_secret


def show(url, headers, body, message, cred_message, client_secret):
    print("=== signing ===")
    if "X-Signature" in headers:
        print("  clientSecret : %s" % client_secret)
        print("  sign message : %s" % message)
        print("  X-Signature  : %s" % headers["X-Signature"])
        print("  cred message : %s" % cred_message)
        print("  Client-id    : %r" % headers["Client-id"])
        print("  X-Client-Cred: %s" % headers["X-Client-Credential"])
        print("  uid          : %r" % headers["uid"])
        print("  gtoken       : %s" % headers.get("gtoken", "(none)"))
    if "token" in headers:
        print("  eufy scheme  : token+timestamp")
        print("  timestamp    : %s" % headers["timestamp"])
        print("  token        : %s" % headers["token"])
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
    if status == 406:
        return ("406 Access token expired. The session token gate ran before the signature. If this\n"
                "was sent without a gtoken, add a guest identity with --gen-tourist-id. If a generated\n"
                "tourist id still 406s, the server only accepts a tourist id it issued, so capture a\n"
                "real one from the logged out app and pass it with --tourist-id, or --gtoken directly.")
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
    ap.add_argument("--client-id-header", default="",
                    help="Client-id header value, empty by default to match the logged out app. "
                         "This value also feeds the X-Client-Credential hash.")
    ap.add_argument("--bootstrap-secret", default="",
                    help="bootstrap secret in the credential hash, empty in this config")
    ap.add_argument("--swap", action="store_true",
                    help="swap the clientId and clientSecret roles")
    ap.add_argument("--no-body", action="store_true",
                    help="sign ts+once only, omit the body from the signed message")
    ap.add_argument("--ts-unit", choices=["ms", "s"], default="ms",
                    help="timestamp unit, milliseconds or seconds")
    ap.add_argument("--once", default="", help="fixed nonce, default is random")
    ap.add_argument("--key-ident", default="", help="optional X-Key-Ident header value")
    ap.add_argument("--tourist-id", default="",
                    help="guest identity. Sets uid and gtoken=md5(touristId). Pass a value captured "
                         "from the logged out app, or use --gen-tourist-id for a random one.")
    ap.add_argument("--gen-tourist-id", action="store_true",
                    help="generate a random tourist id when --tourist-id is not given")
    ap.add_argument("--gtoken", default="",
                    help="override the computed gtoken with a raw value captured from the app")
    ap.add_argument("--authorization", default="",
                    help="user bearer token, only when signed into an account, usually 'Bearer ...'")
    ap.add_argument("--eufy", action="store_true",
                    help="use the eufy token+timestamp scheme (speaker.eufylife.com), dropping the "
                         "soundcore signing headers unless --keep-soundcore is given")
    ap.add_argument("--eufy-token", default=DEFAULT_EUFY_TOKEN,
                    help="token paired with --eufy-timestamp. Defaults to a captured pair that does "
                         "not expire, since the server does not check timestamp freshness")
    ap.add_argument("--eufy-timestamp", default=DEFAULT_EUFY_TIMESTAMP,
                    help="timestamp (unix seconds) matching --eufy-token, or for --eufy-localkey")
    ap.add_argument("--eufy-localkey", default="",
                    help="the recovered app localKey. token = md5(timestamp + localKey)")
    ap.add_argument("--phone-virtual-id", default="",
                    help="phone_virtual_id header, defaults to --openudid")
    ap.add_argument("--keep-soundcore", action="store_true",
                    help="keep the soundcore X-Signature headers alongside the eufy scheme")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--product-code", default=DEFAULT_PRODUCT)
    ap.add_argument("--sn", default=DEFAULT_SN)
    ap.add_argument("--version", default=DEFAULT_VERSION,
                    help="current firmware version, a low value asks for an update")
    ap.add_argument("--matched", action="store_true",
                    help="set the matched flag true, default false")
    ap.add_argument("--raw-body", default="",
                    help="send this exact JSON as the body, overriding the built one. The eufy token "
                         "is body independent, so this iterates the batch schema with no re-auth")
    ap.add_argument("--batch", action="store_true",
                    help="use the batch endpoint SCOTAMultipleRequestModel that the iOS app uses, a "
                         "firmware_list of entries, instead of the simple sound_core endpoint")
    ap.add_argument("--batch-path", default="api/v2/speaker/firmware/upgrade_check/batch",
                    help="path for --batch, try with and without the api prefix if it 404s")
    ap.add_argument("--batch-key", default="firmwareList",
                    help="JSON key wrapping the list, firmwareList on iOS, firmware_list on Android")
    ap.add_argument("--product-component", default="",
                    help="firmware component for the batch entry, omitted when empty")
    ap.add_argument("--product-language", default="en",
                    help="product_language for the batch entry, omitted when empty")
    ap.add_argument("--base-version", default="",
                    help="base_version for the batch entry, omitted when empty")
    ap.add_argument("--country", default="US")
    ap.add_argument("--language", default="en")
    ap.add_argument("--app-version", default="5.0.02")
    ap.add_argument("--openudid", default="00000000-0000-0000-0000-000000000000")
    ap.add_argument("--user-agent", default="Soundcore-iOS-5.0.02")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--send", action="store_true", help="actually send, default prints only")
    args = ap.parse_args()

    url, headers, body, message, cred_message, client_secret = build_request(args)
    show(url, headers, body, message, cred_message, client_secret)

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
