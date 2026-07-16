# API decisions for public SDK clients

The backend OpenAPI document remains the HTTP source of truth. Decisions are recorded
centrally in the backend workspace under `docs/decisions/`.

1. JavaScript, Python, and Go expose create, retrieve, delete, and health operations.
2. `X-Wipe-Client` is an extensible lowercase identifier, not a closed enum.
3. Every v1 message is one-time. The obsolete `X-Wipe-On-Read` header is rejected.
4. The per-message Durable Object's persistent claim marker is the retirement
   tombstone after the active D1 row and R2 object are removed.
5. Free anonymous clients enforce a 3 MiB encrypted limit and 14-day maximum expiry.
6. SDKs expose typed API errors with status, stable code, message, and optional retry
   delay. The central `docs/api-errors-and-auth.md` owns current and reserved codes.

The CLI handoff document is now an implemented-status pointer to the central contract.
