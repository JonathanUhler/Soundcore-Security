#!/usr/bin/env python3
"""Probe the Soundcore firmware upgrade endpoint with an UNSIGNED request.

Purpose. Test whether the eufylife firmware check endpoint enforces the request
signature at all. The script sends a well-formed OtaRequestModel body and the
contextual headers, but deliberately omits every signature and auth header
(X-Signature, X-Request-Ts, X-Request-Once, X-Key-Ident, X-Encryption-Info,
X-Client-Credential, Client-id, gtoken, Authorization).

  - If the server answers with firmware metadata, the signature is NOT enforced,
    and this same script becomes the driver once the request body is finalized.
  - If it rejects the request, the signature IS enforced, and we need the signing
    from the Ijiami Byte Buffer Scrape plan before this endpoint is reachable.

Endpoint and schema were recovered by static analysis, see
research/notes/2026-08-30_App-Dex-Analysis/Capture-Resolution-And-OTA-API.md.

  POST https://speaker.eufylife.com/v1/speaker/sound_core/{product_code}/firmware/update
  body  OtaRequestModel { product_code, sn, version, matched }
  resp  BaseResponse<OtaResultModel>. The richer batch and A3910 endpoints return
        FirmwareResultModel.lastPackage.url, the firmware download link.

This makes ONE minimal request to a third party production gateway. Be respectful.
Use --dry-run to print the request without sending.

Interpreting a 404. The gateway is APISIX and, per earlier probing in
research/notes/2026-08-29_APK-Firmware-Upgrade-Analysis/MITM-Analysis.md, it hides
route existence from unsigned clients, returning a generic 404 whether or not the
path is real. So a 404 here most likely means the signature was required and the
request was dropped, not that the path is wrong.
"""
import argparse
import json
import sys

DEFAULT_HOST = "speaker.eufylife.com"
DEFAULT_PRODUCT = "A3949"           # the P20i
DEFAULT_SN = "3949E7BDE52DB6F4"     # derivable from the BT MAC, see MITM-Analysis.md
DEFAULT_VERSION = "1.00"            # a low version so the server reports an update

# The signature and auth headers this experiment deliberately leaves out. Listed
# so the omission is explicit in the output.
OMITTED_SIGNATURE_HEADERS = [
    "X-Signature", "X-Request-Ts", "X-Request-Once", "X-Key-Ident",
    "X-Encryption-Info", "X-Client-Credential", "Client-id",
    "gtoken", "Authorization",
]


def build_request(args):
    url = "https://%s/v1/speaker/sound_core/%s/firmware/update" % (args.host, args.product_code)
    # OtaRequestModel. product_code carries a Gson @SerializedName, the rest map by
    # field name.
    body = {
        "product_code": args.product_code,
        "sn": args.sn,
        "version": args.version,
        "matched": False,
    }
    # Contextual headers only. These mirror the app and the captured telemetry
    # flow, and none of them authenticate the request. uid is empty because the
    # firmware check runs app level, with no logged in user.
    headers = {
        "Content-Type": "application/json",
        "AnkerBG": "SPEAKER",
        "country": args.country,
        "language": args.language,
        "uid": "",
        "app_version": args.app_version,
        "os_type": "android",
        "os_version": "14",
        "phone_model": "Pixel 9a",
        "timezone": "America/Los_Angeles",
        "openudid": args.openudid,
        "User-Agent": args.user_agent,
    }
    return url, headers, body


def show_request(url, headers, body):
    print("=== request ===")
    print("POST", url)
    for k, v in headers.items():
        print("  %s: %s" % (k, v))
    print("  body: %s" % json.dumps(body))
    print("  omitted (signature/auth): %s" % ", ".join(OMITTED_SIGNATURE_HEADERS))


def interpret(status):
    if status == 200:
        return ("200. If the body carries firmware metadata or an upgrade list, the signature is NOT\n"
                "enforced. Look for a lastPackage.url. If the body is an error envelope, read its\n"
                "code, the gateway may accept the request but the app layer may still reject it.")
    if status in (401, 403):
        return "%d. The signature is enforced, the request was rejected for auth." % status
    if status == 404:
        return ("404. APISIX hides routes from unsigned clients, so this most likely means the\n"
                "signature was required and the request was dropped, not that the path is wrong.\n"
                "See MITM-Analysis.md endpoint probing.")
    return "%d. Unexpected. Inspect the body and headers above." % status


def main():
    ap = argparse.ArgumentParser(description="Unsigned probe of the Soundcore firmware upgrade API.")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--product-code", default=DEFAULT_PRODUCT)
    ap.add_argument("--sn", default=DEFAULT_SN)
    ap.add_argument("--version", default=DEFAULT_VERSION,
                    help="current firmware version, a low value asks the server for an update")
    ap.add_argument("--country", default="US")
    ap.add_argument("--language", default="en")
    ap.add_argument("--app-version", default="5.0.21")
    ap.add_argument("--openudid", default="00000000-0000-0000-0000-000000000000")
    ap.add_argument("--user-agent", default="Soundcore-Android-5.0.21")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--dry-run", action="store_true", help="print the request and exit, do not send")
    args = ap.parse_args()

    url, headers, body = build_request(args)
    show_request(url, headers, body)

    if args.dry_run:
        print("\n[dry-run] not sending.")
        return 0

    try:
        import requests
    except ImportError:
        print("\nrequests is not installed. Run: pip install requests", file=sys.stderr)
        return 2

    print("\n=== sending (one request) ===")
    try:
        r = requests.post(url, headers=headers, json=body, timeout=args.timeout)
    except requests.exceptions.SSLError as e:
        print("TLS error: %s" % e)
        print("The host is pinned inside the app, but a plain client should still complete a normal\n"
              "TLS handshake against the public cert. An error here is a connection issue, not app\n"
              "pinning.")
        return 1
    except requests.exceptions.RequestException as e:
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
