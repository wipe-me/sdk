# Version 1 fixtures

`message-only.json` is the byte-for-byte vector already enforced by the reference Go
CLI. Its 64 KiB, one-iteration Argon2id settings exist only to keep tests fast.

`link-cases.json` covers canonicalization, grouped presentation, path handling, case
sensitivity, invalid lengths, and the ambiguous characters excluded by Base58BTC.

Before release this directory will also contain production deletion-key, attachment,
chunk-boundary, Unicode, empty-file, multi-attachment, and malformed-envelope vectors.
Multi-attachment vectors must use distinct deterministic attachment IDs; a repeated
byte random source would accidentally create AES-GCM nonce reuse.
