# API decisions for public SDK clients

The backend OpenAPI document remains the HTTP source of truth. Decisions are recorded
centrally in the backend workspace under `docs/decisions/`.

1. JavaScript, Python, and Go expose create, retrieve, delete, health, effective-limit
   discovery, bounded upload/download measurement, and privacy-safe performance-report
   operations.
2. `X-Wipe-Client` is an extensible lowercase identifier, not a closed enum.
3. Every v1 message is one-time. The obsolete `X-Wipe-On-Read` header is rejected.
4. The per-message Durable Object's persistent claim marker is the retirement
   tombstone after the active D1 row and R2 object are removed.
5. Free anonymous clients enforce a 3 MiB encrypted limit and 14-day maximum expiry.
6. SDKs expose typed API errors with status, stable code, message, and optional retry
   delay. The central `docs/api-errors-and-auth.md` owns current and reserved codes.
7. Network tests accept 1 through 1 MiB per request and report locally measured elapsed
   time and bytes per second. The server response is not a promise about physical chunking.
8. Performance reports are validated locally against schema v1, capped at 8 KiB, and
   may never contain message identifiers, capabilities, content, attachment metadata,
   raw user agents, IP addresses, or arbitrary exception text.

The CLI handoff document is now an implemented-status pointer to the central contract.
