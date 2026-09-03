#!/usr/bin/env bash
#
# build.sh -- cross compile scprobe.dylib for arm64 iOS.
#
# Runs on the Mac operator host. The known good host is an Intel Mac with only
# the Command Line Tools, no full Xcode, so this script does not assume the Xcode
# toolchain. It does need an iPhoneOS SDK. With full Xcode present, xcrun finds
# the SDK automatically. Without it, point SDK at a standalone iOS SDK, for
# example one shipped with a Theos install under $THEOS/sdks.
#
# The output is an UNSIGNED arm64 dylib. Do not sign it here. Sideloadly signs
# the injected dylib with the app's own re-sign identity, which is the signature
# the reinforcement SDK already tolerates on the sideloaded app.

set -euo pipefail
cd "$(dirname "$0")"

MARKER="SCPROBE_HELLO_WORLD"
MIN_IOS="${MIN_IOS:-14.0}"
OUT="${OUT:-scprobe.dylib}"

# Locate an iPhoneOS SDK.
SDK="${SDK:-$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null || true)}"
if [ -z "${SDK}" ]; then
  echo "error: no iPhoneOS SDK found." >&2
  echo "  With full Xcode this is automatic. Without it, set SDK to an iOS SDK path," >&2
  echo "  e.g.  SDK=\$THEOS/sdks/iPhoneOS16.5.sdk ./build.sh" >&2
  exit 1
fi

# clang from the Command Line Tools is sufficient. No full Xcode required.
CLANG="$(xcrun --find clang 2>/dev/null || command -v clang || true)"
if [ -z "${CLANG}" ]; then
  echo "error: no clang found. Install the Command Line Tools: xcode-select --install" >&2
  exit 1
fi

echo "SDK   = ${SDK}"
echo "clang = ${CLANG}"
echo "min   = iOS ${MIN_IOS}"
echo "arch  = arm64 (match the app and all its images, NOT arm64e)"

"${CLANG}" \
  -arch arm64 \
  -isysroot "${SDK}" \
  -mios-version-min="${MIN_IOS}" \
  -dynamiclib \
  -install_name "@executable_path/${OUT}" \
  -Wall -Wextra -O2 \
  -o "${OUT}" scprobe.c

echo
echo "built ${OUT}:"
file "${OUT}" || true
otool -L "${OUT}" 2>/dev/null || true
echo
echo "next: add ${OUT} to Sideloadly's dylib inject box, re-sign, install, then"
echo "verify with:  pymobiledevice3 syslog live | grep ${MARKER}"
