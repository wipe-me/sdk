import { performance } from "node:perf_hooks";
import { createV1Envelope, readV1Envelope } from "../src/index.js";

const cases = [["empty", 0], ["small", 32 * 1024], ["near-limit", 2800 * 1024]];
for (const [name, size] of cases) {
  const input = size ? [{ name: `${name}.bin`, data: new Uint8Array(size) }] : [];
  const startEncrypt = performance.now();
  const encrypted = await createV1Envelope({ messageId: "1K7mQ2xR8VpC", secret: "7YWHMfk9JCB7P4eG", message: size ? "benchmark" : "", attachments: input });
  const encryptedAt = performance.now();
  await readV1Envelope({ messageId: "1K7mQ2xR8VpC", secret: "7YWHMfk9JCB7P4eG", envelope: encrypted.envelope });
  const done = performance.now();
  console.log(`${name}: envelope=${encrypted.envelope.length} encrypt=${(encryptedAt-startEncrypt).toFixed(1)}ms decrypt=${(done-encryptedAt).toFixed(1)}ms`);
}
