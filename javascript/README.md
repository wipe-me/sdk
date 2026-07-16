# @wipe-me/sdk

Browser and Node.js SDK for Wipe.me. The alpha provides client-side v1 envelope
encryption/decryption, private-link helpers, deletion-key derivation, and the create,
retrieve, delete, and health HTTP operations.

```sh
npm install @wipe-me/sdk@next
```

```js
import {
  WipeClient,
  bytesToBase64Url,
  createV1Envelope,
  generateMessageId,
  generateSecret,
  readV1Envelope,
} from "@wipe-me/sdk";

const api = new WipeClient({ clientId: "sdk-js" });
const messageId = generateMessageId();
const secret = generateSecret();
const encrypted = await createV1Envelope({ messageId, secret, message: "Private hello" });
const created = await api.createMessage({
  messageId,
  envelope: encrypted.envelope,
  deletionKey: encrypted.deletionKeyHeader,
  contentHash: encrypted.contentHash,
  expiresAt: Date.now() + 24 * 60 * 60 * 1000,
});
const downloaded = await api.retrieveMessage(messageId);
const opened = await readV1Envelope({ messageId, secret, envelope: downloaded.envelope });
await api.deleteMessage(messageId, bytesToBase64Url(opened.deletionKey));
```

All long operations accept `onProgress`; events contain `phase`, `processedBytes`,
`totalBytes`, and `percent`. Attachment writers default to 512 KiB AES-GCM frames and
accept power-of-two `cryptoChunkBytes` from 64 KiB through 4 MiB. Transport reporting
defaults to a logical 100 KiB threshold. Browser uploads can use
`createXHRTransport()` for real upload progress; downloads consume response streams.

The API receives only opaque encrypted bytes and derived capabilities. API failures
throw `APIError` with `status`, stable `code`, human-readable `message`, and optional
`retryAfter`. Free anonymous messages are validated at 3 MiB and 14 days.

The fragment secret never enters an API request. Crypto requires modern Web Crypto
and WebAssembly support; browsers should run in a secure context. Production writers
always use the fixed v1 Argon2id parameters. The underscored `_test` encryption option
exists solely for deterministic interoperability vectors and must not be used by apps.
