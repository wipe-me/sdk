# Progress implementation benchmark

Run `node javascript/scripts/benchmark-progress.mjs` on representative empty, 32 KiB,
and 2.8 MiB inputs. The benchmark uses production Argon2id settings and the 512 KiB
attachment-frame default. Results are environment-specific and are recorded during
release verification; progress reporting does not weaken or bypass Argon2id.

Reference run (Node 22 Linux container, 2026-07-16):

| Input | Envelope | Encrypt | Decrypt |
|---|---:|---:|---:|
| Empty | 115 B | 230.6 ms | 168.9 ms |
| 32 KiB | 33,117 B | 168.6 ms | 172.7 ms |
| 2.8 MiB | 2,867,701 B | 225.9 ms | 225.7 ms |

The important scaling property is bounded AES-GCM work per attachment frame. Empty
and small inputs may legitimately publish a single 100% crypto event. Transport timing
is intentionally excluded because network conditions dominate it.
