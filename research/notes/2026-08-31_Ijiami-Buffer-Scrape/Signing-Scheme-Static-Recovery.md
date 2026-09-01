# Request Signing, Recovered From What Survives Extraction

The method bodies are extracted, see `Method-Extraction-Finding.md`. But strings, kotlin metadata,
`static final` constants, and the `<clinit>`s survive. That is enough to recover most of the signing
scheme structurally. This file records what is now known and what is still unknown. Everything here
comes from `carved_virt/dex_0000aeaa2000_743400a18000.dex` and the `apk/ram-scrape/` decompilation
of it, except where noted. Claims are marked as read or inferred.

## The Signer Is Kotlin, Not Native

The signing lives in `com/anker/commonkit/aknetwork`, a Kotlin crypto stack with a from-scratch
`SHA256` (see `coreUpdate`, `coreDigest`) and `HMAC` built on it. There is a parallel copy in
`com/anker/esiotkit/network/util/EncryptKeyFactory`, in dex `7433f4954000`, with the same method
set. Both are extracted. This confirms the signer is not in the native `libsc*` or `libecc*`
libraries, so Ghidra on those will not recover it.

## Two Tiers Of Signature

`EncryptUtil` exposes two HMAC signers, read from its metadata signatures.

- Bootstrap, before a key exchange has happened.
  `encryptByHMAC256(clientId, tsMsg, onceMsg)`. Keyed off the client identity, over the timestamp
  and the nonce, no body. Used to authenticate the very first requests, including the key exchange
  call itself.
- Session, after a key exchange.
  `encryptByHMAC(ecdhKey, tsMsg, onceMsg, bodyMsg)`. Keyed off the ECDH-derived session key, over
  the timestamp, the nonce, and the request body. There is also a 3-arg `encryptByHMAC(tsMsg,
  onceMsg, bodyMsg)` that pulls the key from state.

Inferred from the parameter order, the signed message is the concatenation of timestamp, nonce, and
body, in that order, HMAC-SHA256 under the selected key, and the result is the `X-Signature` header.
`X-Request-Ts` is the timestamp, `X-Request-Once` is the nonce. The exact separator between fields
and the output encoding, hex or base64, are in the extracted body and are not yet known.

`X-Key-Ident` selects which key signed, produced by `EcdhKeyUtils.generateKeyIdent` and
`EncryptUtil.generateKeyIdent`. Its constant name is `KEY_IDENT_KEY = "X-Key-Ident"`.

## The ECDH Exchange

Read from constants and entity metadata.

- Endpoint, `EXCHANGE_KEY_REQUEST = "/openapi/oauth/key/exchange"`. This is new, the prior notes did
  not have the exchange path.
- Request, `ExchangeKeyRequest { clientPublicKey }`. Response,
  `ExchangeKeyResponse { serverPublicKey }`. Both are `kotlinx.serialization` types with
  `$serializer` classes present.
- Key material, `EcdhKey { appPublicKey, appPrivateKey, serverPublicKey }`. So the app generates its
  own P-256 keypair, sends `appPublicKey` as `clientPublicKey`, receives `serverPublicKey`, and
  derives a shared key.
- `KeyExchangeManager.performKeyExchange(caller, forceExchange)` drives it, guarded by a mutex and a
  `CompletableDeferred` so only one exchange runs at a time. `needsKeyExchange` gates it.

`EcdhKeyUtils` manages the derived key and its lifecycle.

| Constant | Value | Meaning |
| --- | --- | --- |
| `ECDH_KEY` | `ecdh-key` | storage key for the shared key |
| `KEY_IDENT_KEY` | `X-Key-Ident` | storage key for the key identifier |
| `ENCRYPT_APP_PUBLIC_KEY` | `encrypt-app-publickey` | storage key for the encrypted app public key |
| `SERVER_PUBLIC_KEY_UPDATE_TIME` | `server-public-key-update-time` | last refresh time |
| `SERVER_PUBLIC_KEY_EXPIRE_TIME` | `259200000` | server key lifetime, 3 days in ms |

The methods `getSharedKey(presetKey)`, `getSecurityKey(presetKey)`, `updateShareKey(presetKey,
serverPublicKey)`, and `getEcdhKey(presetKey)` are all keyed by a `presetKey` argument, which names
the storage namespace, an MMKV or preferences instance. The server public key is refreshed every 3
days, so a reproduction must re-exchange on that cadence or on a signature rejection.

## The Embedded P-256 Public Key

The signing dex carries one hardcoded 65-byte constant that is not a standard curve parameter.

```
04c5c00c4f8d1197cc7c3167c52bf7acb054d722f0ef08dcd7e0883236e0d72a
3868d9750cb47fa4619248f3d83f0f662671dadc6e2d31c2f41db0161651c7c076
```

It is 65 bytes, prefix `0x04`, the uncompressed EC point encoding. Its X and Y validate as a point
on P-256, `y^2 == x^3 - 3x + b mod p`, confirmed. It is not the P-256 or secp256k1 generator, so it
is app-specific. It is the embedded server or bootstrap public key. The most likely role, given the
`encrypt-app-publickey` constant and the log string "Encrypting AES encryption key with RSA public
key", is that the app encrypts its own generated public key toward this key before sending, and
uses it as the initial trust anchor for the exchange. The nearby `ClientSecretInfo { public_key }`
entity and `getClientSecret` support a stored server-credential model.

Note, the neighboring dex `7433f2460000` is the EC math library and is full of standard curve
constants, both the P-256 and the secp256k1 generators appear there. Those are not app secrets. The
`04c5c00c` key is the only non-standard embedded point, and it is in the signing dex.

## Crypto Primitives Present

All read from class names and algorithm strings in the signing dex.

- HMAC, `hmacSHA256`, `hmacSHA1`, `hmacMD5`, over a pluggable `Hasher`.
- SHA256, a from-scratch implementation, its constant table survives in `<clinit>`.
- PBKDF2, present as `com/anker/commonkit/aknetwork/crypto/PBKDF2`.
- AES, `AES/CBC/PKCS5Padding`, plus `AES256`, `AES128CBC`, and `CipherPaddingPKCS7`.
- ECDH, `com/anker/commonkit/aknetwork/ecdh/ECDHJava`, with `AES256` and `Base64` helpers.
- RSA, `RSA/ECB/PKCS1Padding`, used to wrap an AES key per the log strings.
- Base64, a full custom `Base64` with encoder, decoder, and streams.

## Body Encryption And The Session Key

Separate from the signature, request bodies can be encrypted. `X-Encryption-Info` is the header.
`EncryptUtil.encryptBodyByPresetKey` and `decryptBodyByPresetKey` handle the bootstrap case, and
`encryptByUniqueSign(plainText, uniqueSign)` and `decryptByUniqueSign` handle the session case.
`getKeyByUniqueSign(uniqueSign)` derives the AES key bytes, and `generateEncryptIv` the IV. The
`uniqueSign` is the session key, and a log assertion fixes its length, "uniqueSign.size must be 32,
actual is:", so it is 32 bytes, consistent with a P-256 shared secret or a 256-bit key derived from
it.

## Full Header Set

Confirmed present as constants in this dex. `X-Signature`, `X-Request-Ts`, `X-Request-Once`,
`X-Key-Ident`, `X-Encryption-Info`, `X-Client-Credential`, `Client-id`, `HEADER_GTOKEN` (`gtoken`),
`HEADER_UNIQUE_SIGN`, and the identity headers `uid`, `country`, `language`, `sn`, `app_version`,
`os_type`, `model-type`, `timezone`, `mcc`, `mnc`. `gtoken` is produced by
`generateGTOKEN$CommonKit_release`, which lives in `WebSocketManager`.

## What Is Still Unknown

These sit in extracted bodies and cannot be read from this dump.

1. The exact signed string. Field order is inferred as ts, once, body, but the separators and the
   output encoding are not confirmed.
2. The key derivation. Whether `uniqueSign` is the raw ECDH shared secret, or SHA256 or PBKDF2 of
   it, and what salt or info. `SHA256.<clinit>` and `PBKDF2` are present but their call sites are
   stubs.
3. `X-Key-Ident`. The exact output of `generateKeyIdent`.
4. The bootstrap key. The `clientId` and `X-Client-Credential` values, and whether the bootstrap
   HMAC key is `clientId` directly or a transform of it.
5. The `presetKey` value, the storage namespace seed.

Every one of these is answerable from a single real signed request captured on hardware, matched
against a reproduction that uses the scheme above and the embedded key. That is the cheapest path to
closing the signing, and it does not require the extracted bytecode.
