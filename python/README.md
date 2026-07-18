# wipe-me

The official Python SDK for Wipe.me. The synchronized 0.3 alpha supports the same
v1 encryption, configurable framing, progress, link, and HTTP operations as the
JavaScript and Go SDKs.

```bash
python -m pip install --pre wipe-me==0.3.0a1
```

```python
import time
from wipeme import Client, decrypt, encrypt, generate_message_id, generate_secret

api = Client("https://wipe.me", client_id="sdk-python")
message_id, secret = generate_message_id(), generate_secret()
encrypted = encrypt(message_id, secret, "Private hello", on_progress=print)
created = api.create(
    message_id,
    encrypted.envelope,
    deletion_key=encrypted.deletion_key_header,
    content_hash=encrypted.content_hash,
    expires_at=int(time.time() * 1000) + 24 * 60 * 60 * 1000,
)
download = api.retrieve(message_id)
opened = decrypt(download.body, message_id, secret)
```

The synchronous client supports create, atomic one-time retrieve, idempotent delete,
and health operations. Free anonymous messages are validated at 3 MiB and 14 days.
API failures raise `APIError` with `status`, stable `code`, human-readable `message`,
and optional `retry_after` attributes.

`create(..., on_progress=...)` and `retrieve(..., on_progress=...)` expose byte-based
upload/download events. Retrieval reads in configurable logical chunks (100 KiB by
default); physical network boundaries remain runtime-controlled.

Crypto uses Argon2id, HKDF-SHA-256, and AES-256-GCM through `argon2-cffi` and
PyCA `cryptography`. The fragment secret remains local and is never sent to the API.
