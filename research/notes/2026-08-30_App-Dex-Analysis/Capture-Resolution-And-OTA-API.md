# Notes: Capture Resolution And OTA API Findings

These notes continue `Summary.md` and `Decompilation-Diagnosis.md` in this directory. The earlier
diagnosis left Goal 0 blocked, since the first recovered dexes were structurally dead. This note
records the `emu-freeze/` fixes that produced a clean capture, the code paging limit that clean
capture exposed, and the OTA firmware API contract read from the result.

## Status

Goal 0 is resolved. A clean capture of 18 app dexes at 100 percent class resolution was produced
by `emu-freeze/capture.sh`. Goal 2, the OTA API contract, is answered. Goal 1, the request
signing, is partly answered, the scheme is known but the algorithm and keys are not. Goal 3,
firmware handling, is mapped but not answered. The reason for the two gaps is lazy code paging,
explained below.

## Part 1: Capture Pipeline Issues Resolved

Recovery went through several failures, each fixed in the tooling. Usage is in
`emu-freeze/README.md`. The fixes, in order.

| Symptom | Cause | Fix |
| --- | --- | --- |
| jadx `Bad dex file checksum` | ART patches the in-memory dex Adler-32 and SHA-1 | recompute both (`fix_inmemory_dex.py`) |
| jadx crash reading `map_list` | tail map page truncated, zeroed, or a garbage count | rebuild a valid map in place from the header |
| dex 0 percent class resolution | froze at the self kill, caught mid teardown, page walk read reused frames | freeze earlier, at dex load |
| app died before the dex mapped | `get_pid` locked onto the ijiami watchdog, the app re-execs | follow every package process, pick the one that maps the dex |
| 0 candidate PGDs | the app PGD sat above the 2 GB dump | dump every RAM bank from `info mtree -f`, try all CPU CR3s |
| `pmemsave` `invalid char 'h'` | the monitor parses the filename as an expression, `/` is divide | bare filenames, find QEMU cwd from `/proc` |
| tiny 768 KB low bank | per-CPU FlatViews give duplicate, overlapping RAM leaves | dedup and coalesce overlaps, never merge across 4 GB |
| a fluke 1 PGD seed won | the first non-empty CR3 was used | pick the CR3 yielding the most PGDs, auto-detect the kernel half if none do |

The working path is now one command. `capture.sh` launches the app, polls `/proc/<pid>/maps` for
the in-memory dex, freezes the VM with a hypervisor monitor `stop` that is invisible to the
in-guest anti-tamper, dumps every RAM bank, reassembles, and health checks. No gdb, kallsyms, or
kernel breakpoints. New tools, `capture.sh`, `mon.py`, `snapshot.py`, plus multi-CR3 and
auto-kernel-half logic in `reassemble_dex.py`.

## Part 2: The Lazy Code Paging Limit

A clean capture at dex load gives full dex structure but not all method bytecode. ART's
`InMemoryDexClassLoader` faults each method's `code_item` in lazily, only when the method runs or
its class is verified. At the dex-load freeze most methods have not run, so their code pages are
absent and get zero filled by the reassembly. A dex can score 100 percent class resolution on
names and still have most method bodies empty.

Code residency is per dex, set by what executed during the app's brief startup.

| Code | Best dex | Bytecode present |
| --- | --- | --- |
| eufylife networking layer | `7433fc878000` | 92.7 percent |
| `gtoken` and `openudid` signing headers | `743400a18000` | 84.6 percent |
| `FirmwareUpdateRequestModel` | `7433f21a8000` | 26.9 percent |
| `AbOtaVersionCheckUtils` | `7433fee68000` | 3.0 percent |

`dex_health.py` measures class name resolvability, not code, so it over reports these as USABLE. A
code integrity metric, the fraction of `code_item`s with non zero insns, should be added. This is
recorded in project memory.

## Part 3: The OTA Firmware API

All of this is recoverable from the scrape because endpoints are Retrofit annotations, models are
field schemas, and paths are string constants. None of those are `code_item`s, so none were lost.

### Host

Production `speaker.eufylife.com`. Mirrors and environments also present in the scrape,
`speaker-api.anker-in.com`, `speaker-qa.eufylife.com`, `speaker-beta.eufylife.com`,
`speaker-dev.eufylife.com`, and the `speaker-api-qa` and `speaker-api-beta` anker-in variants.

### Endpoints

From `com/oceanwing/soundcore/widget/ota/OtaApi`, `com/oceanwing/ota/request/api/OtaApi`, and
`com/oceanwing/common/constants/URLConstants`.

| Method and path | Request body | Response |
| --- | --- | --- |
| `POST /v1/speaker/sound_core/{productCode}/firmware/update` | `OtaRequestModel` | `BaseResponse<OtaResultModel>` |
| `POST api/v2/speaker/firmware/upgrade_check/batch` | `CheckOtaUpgradeCommand` | `BaseResponse<CheckOtaUpgradeResponse>` |
| `POST v1/speaker/A3910/firmware/update` | `A3910FirmwareRequestModel` | `BaseResponse<FirmwareResultModel>` |
| `/v1/speaker/up_firmware_version` | | |
| `/v1/speaker/A3600/firmware/list` | | |

For the P20i the product code is `A3949`, so the path is
`/v1/speaker/sound_core/A3949/firmware/update`.

### Request

`OtaRequestModel`, the body for the `sound_core/{productCode}` endpoint.

```json
{ "product_code": "A3949", "sn": "3949E7BDE52DB6F4", "version": "1.00", "matched": false }
```

Send a low `version` so the server reports an update. The `sn` is derivable from the Bluetooth
MAC, see `../2026-08-29_APK-Firmware-Upgrade-Analysis/MITM-Analysis.md`.

### Response And The Download URL

`OtaResultModel` is minimal, just `needUpdate`. The firmware detail is in `FirmwareResultModel`,
used by the batch and A3910 endpoints, which is `needUpdate` plus `lastPackage`, a
`LastPackageModel`.

`LastPackageModel` fields, each with a Gson `@SerializedName`.

| Field | Meaning |
| --- | --- |
| `url` | firmware download URL |
| `md5` | firmware MD5 |
| `size` | byte size |
| `version` | firmware version |
| `is_forced`, `force_option` | forced upgrade flags |
| `firmware_code`, `change_log`, `component_name` | metadata |
| `product_code`, `product_component`, `product_language` | product identity |
| `update_time`, `upgrade_scheme` | metadata |
| `ext` | a `FirmwareExt` |

`FirmwareExt` carries the flashing layout, `file_name`, `addr_begin`, `addr_offset`,
`base_version`, `instruction_set`, `require_box_version`, `description`, and per platform upgrade
times.

So `LastPackageModel.url` is the firmware file. Per the earlier notes it is likely on an unpinned
object store or CDN, so the download itself needs no signing.

### Request Signing

The scheme is recovered from the header constants in
`com/anker/commonkit/aknetwork/config/HeaderBuilderKt`. The signing algorithm itself is not, since
the `HMAC` methods are stubbed. They never ran on the emulator because no signed request was made.

Header constants, the newer Anker HMAC scheme.

| Constant | Header |
| --- | --- |
| `HEADER_SIGNATURE` | `X-Signature` |
| `HEADER_REQUEST_TS` | `X-Request-Ts` |
| `HEADER_REQUEST_ONCE` | `X-Request-Once`, the nonce |
| `HEADER_KEY_IDENT` | `X-Key-Ident` |
| `HEADER_ENCRYPTION_INFO` | `X-Encryption-Info` |
| `HEADER_CLIENT_CREDENTIAL` | `X-Client-Credential` |
| `HEADER_CLIENT_ID` | `Client-id` |
| `HEADER_GTOKEN` | `gtoken` |
| `HEADER_AUTH_TOKEN` | `Authorization` |
| `HEADER_OPEN_UUID` | `openudid` |
| others | `uid`, `country`, `language`, `sn`, `app_version`, `os_type`, `model-type`, `timezone`, `mcc`, `mnc` |

The `X-Signature`, `X-Request-Ts`, `X-Request-Once`, and `X-Key-Ident` set, plus the
`FLAG_REQUEST_AFTER_KEY_EXCHANGE` and `ENCRYPT_APP_PUBLICKEY` constants, match the HMAC-SHA256
with ECDH key exchange scheme in the charliex2 write up, see
`../2026-08-29_APK-Firmware-Upgrade-Analysis/Prior-Work.md`. The crypto package is present as
structure, `com/anker/commonkit/aknetwork/crypto` with `HMAC`, `SHA256`, `Cipher`, `PBKDF2`,
`Hasher`, and the cipher modes and paddings, plus a parallel `com/anker/esiotkit/crypto`. The
bodies are stubbed.

Missing to sign a request, the exact signed string with its field order, and the key. The
charliex2 write up says four hardcoded keys per environment, each encoded as the hex string taken
as UTF-8.

### Firmware Handling, Structure Only

On device flashing is chip specific and present as structure only, bodies stubbed. The P20i is a
Jieli chip, handled under `com/oceanwing/ota/sdk/jl` with the `com.jieli.jl_bt_ota` library, 174
classes, alongside a BES path under `com/oceanwing/ota/sdk/bes`.
`com/oceanwing/ota/utils/CryptoUtils` exists. This maps Goal 3 but does not answer it, the crypto
and flash bodies did not run.

## Artifacts

- Decompilation, `apk/ram-scrape/`, 371 MB, 45886 Java files, 10878 `com/oceanwing/soundcore`
  classes. Full structure, plus real bodies for the classes that executed at startup.
- RAM dump, `emu-freeze/ram-low.bin` at 3 GB and `ram-high.bin` at 1 GB, and the reassembled dexes
  in `emu-freeze/carved_virt/`. These are large working artifacts.

## What Remains

The endpoint and contract are known. The one blocker to pulling firmware is the signing. Options,
cheapest first.

1. Grep the resident strings for the hardcoded keys and any `app_key` or secret. Strings survive.
2. Read the signing interceptor's resident logic, the class that assembles the timestamp, nonce,
   and body and calls the HMAC. It runs on every request, so it may be intact where the HMAC leaf
   is not.
3. Re-capture forcing a signed request to execute, or full class verification, so the signing
   bytecode faults in. See Part 2.
4. Reconstruct from the header scheme plus the charliex2 write up.
