# @wipe-me/sdk

Browser and Node.js SDK for Wipe.me. The initial alpha provides private-link helpers
and the create, retrieve, delete, and health HTTP operations. Envelope encryption and
decryption will be added before the stable release.

```sh
npm install @wipe-me/sdk@next
```

```js
import { WipeClient } from "@wipe-me/sdk";

const api = new WipeClient({ clientId: "sdk-js" });
const health = await api.health();
const created = await api.createMessage({ messageId, envelope, deletionKey, expiresAt });
const downloaded = await api.retrieveMessage(messageId);
await api.deleteMessage(messageId, deletionKey);
```

The API receives only opaque encrypted bytes and derived capabilities. API failures
throw `APIError` with `status`, stable `code`, human-readable `message`, and optional
`retryAfter`. Free anonymous messages are validated at 3 MiB and 14 days.
