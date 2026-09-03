# Goal 2, The Credential Reader

Goal 1 passed on device. The app boots with a custom dylib in the bundle and the constructor log is
recoverable, so there is no load time library whitelist and a passive in-process reader is viable.
This note records the Goal 2 approach, the signer analysis that scopes it, and the reader dylib.

## Approach And Why

The chosen method is a passive reader dylib that dumps the credential material, paired with a host
side script that reproduces a signed firmware check-for-update call. This is approach 1 in the plan.

The reader keeps the exact footprint Goal 1 proved safe. It only reads memory, through
`mach_vm_read_overwrite` so a bad pointer returns an error instead of faulting, and it logs through
`os_log`. It hooks nothing and patches no code, so it stays clear of the `HOOK_ATTACK` and memory
scan surface that killed Frida. Driving the signed call from inside the dylib was rejected. That
needs either a hook, whose detection risk cannot be tested cheaply, or a blind Swift and Kotlin ABI
call, where every mistake is a crash and an operator round trip.

Extracting the credentials also lets the host send an artificially low firmware `version`, which
forces the server to return `lastPackage.url` even when the earbuds are already current. The CDN URL
needs no signing to download, per
`../2026-08-30_App-Dex-Analysis/Capture-Resolution-And-OTA-API.md`, so one signed check is the whole
game.

## The Signer, Read From The iOS Binary

The iOS binary carries the real signer bodies, unlike the Android stubs. The bootstrap signer is the
Kotlin function at Ghidra `0x102d78e9c`, reached from the `encryptByHMAC256` @objc thunk at
`0x102eee3bc`. Reading it settled the config read chain and the message format.

The config read chain, taken directly from the signer.

```
holder = *(main_base + 0x5446558)   config holder pointer, global slot, set by FUN_102d5e4dc
sub    = *(holder + 0x10)           config data object
secret = *(sub + 0x48)              the HMAC secret string
```

`FUN_102d5e4dc` is the lazy initializer for the holder, and it writes the holder pointer into the
`0x105446558` slot, which confirms the slot holds a pointer rather than the object inline.

The HMAC message format. The signer builds two strings. The first is a debug log line with labels
that decode to `|tsMsg:` and `|onceMsg:` from the constants at `0x1042c5b60` and `0x1042c5b90`, under
an `encryptByHMAC/...` tag. The second is the actual signed message, and it concatenates the fields
with no separators.

```
message = clientId + tsMsg + onceMsg + secret
```

`clientId` is `param_1` to the signer, `tsMsg` is `param_2`, `onceMsg` is `param_3`, and `secret` is
read from the config at `sub + 0x48`. The result becomes `X-Signature`. This matches the structural
recovery in `../2026-08-31_Ijiami-Buffer-Scrape/Signing-Scheme-Static-Recovery.md`, and it fills the
field order and the no-separator detail that were unknown there.

## Kotlin/Native String Layout

The string constants confirm the object layout, which the reader needs to decode fields.

```
[ TypeInfo* 8 bytes ][ count 4 bytes ][ hash 4 bytes ][ chars ]
```

All the string constants share the same TypeInfo, `0x1041c4a31` at the preferred base. Constant
strings store chars as UTF-16LE. Runtime strings may store ASCII as Latin-1 instead. The reader does
not care which. It reads `count` at `+8`, reads the char region at `+16`, drops non printable bytes,
and prints what remains, which reads correctly for both encodings.

## The Reader Dylib

`scripts/ios-dylib/screader.c`. A constructor starts a background thread that polls the config slot
until the holder and its data object are populated, since the constructor runs during dyld init well
before the app's `initConfig`. Once populated it waits two seconds for `initConfig` to finish, then
dumps.

It does not assume the offsets of `clientId`, `clientSecret`, and `presetKey`. It walks the data
object and the holder, treats each 8-byte field as a candidate string pointer, and dumps any that
decode to printable text. That surfaces all the credentials plus the `+0x48` secret in one run, and
is robust to a config layout that is only partly known. Every read is fault proof, so walking the
unknown struct cannot crash the app.

Marker is `SCREAD`. Build and inject as in `README.md`, using `SRC=screader.c ./build.sh`, then read
the dump.

```bash
pymobiledevice3 syslog live | grep SCREAD
```

## Open Question, Which Signing Tier The Firmware Endpoint Needs

The scheme has two tiers. Bootstrap, keyed off the client identity, authenticates the first requests
including the key exchange. Session, keyed off the ECDH shared secret, signs later requests. The
firmware update endpoint is a normal business call, so it likely uses the session tier, but that is
not yet confirmed from the iOS request builder.

This is the next decision and it sets the host side scope.

- If bootstrap suffices, the host needs only `clientId` and the secret, and reproduces
  HMAC-SHA256 over `clientId + ts + once + secret`. Small.
- If session is required, the host also needs the ECDH session key. Rather than reimplement the
  P-256 exchange, the plan is to extend the reader to locate and dump the live 32-byte session key,
  the `uniqueSign`, from `EcdhKeyUtils` state, which turns the session case back into a
  concatenate-and-HMAC reproduction.

The dumped credentials from the first `screader` run, plus a short trace of the OTA request builder
to name the tier, decide this before the host signer in `scripts/probe_firmware_endpoint.py` is
extended from an unsigned probe to a signed call.
