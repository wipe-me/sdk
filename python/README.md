# wipe-me

The official Python SDK for Wipe.me. This package is not yet published to PyPI.

```python
import time
from wipeme import Client, parse_private_link

api = Client("https://wipe.me", client_id="sdk-python")
health = api.health()

# `envelope` is already encrypted locally; the API never receives the URL secret.
created = api.create(
    "1K7mQ2xR8VpC",
    envelope,
    deletion_key=derived_deletion_key,
    expires_at=int(time.time() * 1000) + 24 * 60 * 60 * 1000,
)
download = api.retrieve("1K7mQ2xR8VpC")
```

The synchronous client supports create, atomic one-time retrieve, idempotent delete,
and health operations. Free anonymous messages are validated at 3 MiB and 14 days.
API failures raise `APIError` with `status`, stable `code`, human-readable `message`,
and optional `retry_after` attributes.

`create(..., on_progress=...)` and `retrieve(..., on_progress=...)` expose byte-based
upload/download events. Retrieval reads in configurable logical chunks (100 KiB by
default); physical network boundaries remain runtime-controlled.
