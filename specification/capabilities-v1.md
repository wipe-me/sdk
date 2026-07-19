# API v1 client capabilities

The backend workspace's `openapi/wipe-api.v1.yaml` is authoritative. This document
records the common public-SDK behavior layered over that HTTP contract.

## Effective limits

`GET /api/limits` returns the server-authoritative limits for the current caller. SDKs
must not substitute compiled free-tier constants for this response. Anonymous v1
currently reports a 3 MiB message limit, a 14-day maximum expiry, three creations per
minute, 30 MiB of message uploads per hour, and a separate 1 MiB/request and 10 MiB/hour
network-test allowance.

## Bounded network measurement

Upload and download samples contain 1 through 1,048,576 bytes. SDKs measure elapsed
time locally with a monotonic clock and return received bytes, elapsed time, and bytes
per second. Progress remains byte-based. Generated download bytes are opaque and must
not be interpreted or persisted. Network tests never consume message quota.

## Retrieval headers

Clients may observe `Content-Length`, `X-Wipe-Content-Hash`, and
`X-Wipe-Cipher-Version` after a destructive retrieval succeeds but before consuming
the response stream. Metadata must be validated before invoking the observer. Observer
failures do not alter retrieval.

## Performance reports

`POST /api/performance-reports` accepts schema version 1 and is capped at 8 KiB. SDKs
validate flow-specific timings, result categories, byte counts, estimate rates, model
and client identifiers before sending. Reports must never contain message IDs, links,
fragment secrets, deletion capabilities, filenames, MIME types, plaintext, wallet
identity, IP addresses, raw user agents, or arbitrary exception text. Telemetry failure
must remain isolated from message creation and destructive retrieval.

The stable capability-specific error codes are `invalid_speed_test_size`,
`speed_test_rate_limited`, `invalid_performance_report`, and
`performance_report_rate_limited`.
