# Wipe.me unified encrypted envelope v1

Status: development preview. This document is the canonical cryptographic contract
for Wipe.me SDK implementations. All multibyte integers are unsigned big-endian.

## Private link

`https://wipe.me/<message-id>#<secret>`

IDs and secrets use Base58BTC (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`),
are case-sensitive, and contain 12 and 16 canonical characters respectively. ASCII
hyphens and spaces are presentation separators and are removed before validation.
Canonical values are commonly displayed in groups of four. The fragment secret must
never be transmitted to the service.

## Key schedule

The production Argon2id v1.3 parameters are 65,536 KiB memory, 3 iterations,
parallelism 1, and a 32-byte output. Production writers MUST use these parameters.
Readers accept encoded parameters only within the v1 compatibility bounds: 64 through
65,536 KiB memory, 1 through 3 iterations, and parallelism exactly 1. This admits the
cheap interoperability fixtures while bounding attacker-controlled work.

```text
salt = SHA-256(UTF-8("wipe.me/envelope/v1/kdf-salt/" + canonical_id))
root = Argon2id(UTF-8(canonical_secret), salt, 65536 KiB, 3, 1, 32)
encryption_root = HKDF-SHA-256(root, salt="", info="wipe.me/envelope/v1/encryption", 32)
deletion_key   = HKDF-SHA-256(root, salt="", info="wipe.me/envelope/v1/deletion", 32)
manifest_key   = HKDF-SHA-256(encryption_root, salt="", info="wipe.me/envelope/v1/manifest", 32)
attachment_key = HKDF-SHA-256(encryption_root, salt="",
  info=UTF-8("wipe.me/envelope/v1/attachment/") || raw_16_byte_attachment_id, 32)
```

AES-256-GCM uses 12-byte nonces and 16-byte tags. Writers MUST NOT reuse a nonce with
the same key and MUST generate unique 16-byte attachment IDs. Deletion capabilities
are sent as unpadded base64url; the service stores only a verifier.

## Binary envelope

The 61-byte public header is also the manifest AES-GCM AAD:

| Offset | Size | Value |
|---:|---:|---|
| 0 | 8 | `57 49 50 45 4d 45 00 01` (`WIPEME`, NUL, v1) |
| 8 | 4 | Argon2id memory KiB |
| 12 | 4 | Argon2id iterations |
| 16 | 1 | Argon2id parallelism |
| 17 | 32 | deterministic salt |
| 49 | 12 | random manifest nonce |
| 61 | 4 | encrypted manifest length, tag included |
| 65 | variable | encrypted compact UTF-8 JSON manifest |

The manifest fields are `version`, optional `message`, `chunk_size`, and
optional ordered `attachments`. Attachment fields are lowercase-hex `id`, `name`,
`type`, `kind`, byte `size`, optional positive `width`/`height`, `chunks`, and
lowercase-hex 8-byte `nonce_prefix`.

Each attachment chunk is:

```text
0x01 || uint32(attachment_index) || uint32(chunk_index) || uint32(plaintext_length)
|| AES-256-GCM ciphertext and tag
```

The nonce is `nonce_prefix || uint32(chunk_index)`. AAD is the 8-byte magic/version,
the 13-byte frame header, `uint32(total_chunks)`, and the raw attachment ID. Frames
are strictly ordered. Empty files have zero frames. A single `0x00` ends the envelope;
trailing bytes are invalid.

## Strict parsing

Writers default `chunk_size` to 524,288 bytes and MAY select a power of two from
65,536 through 4,194,304 bytes. Readers MUST accept every value in that range. This
controls attachment AES-GCM frames only, not HTTP or TCP chunks. The manifest remains
one AES-GCM operation in v1; framing a large manifest is reserved for protocol v2.

Readers MUST bound KDF parameters and manifest length before allocation, recompute
and compare the ID-derived salt before Argon2id, authenticate the manifest before
frames, validate canonical metadata and unique IDs, reject malformed/reordered frames,
enforce the recorded safe chunk size and declared totals, and reject missing end/trailing data.
Wrong-secret and damaged-ciphertext failures should be indistinguishable to users.

## Compatibility

Every implementation MUST consume `fixtures/v1/*.json`. Cheap Argon2 parameters are
allowed only in explicitly marked test vectors and are never production guidance.
The HTTP contract remains canonical in the backend repository's
`openapi/wipe-api.v1.yaml`; `specification/upstreams.json` pins the expected copies.
