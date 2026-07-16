import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  ProtocolError,
  bytesToBase64Url,
  createV1Envelope,
  deriveV1DeletionKey,
  generateMessageId,
  generateSecret,
  readV1Envelope,
} from "../src/index.js";

const fixture = JSON.parse(await readFile(new URL("../../fixtures/v1/message-only.json", import.meta.url), "utf8"));
const cheapKdf = {
  memoryKiB: fixture.kdf.memory_kib,
  iterations: fixture.kdf.iterations,
  parallelism: fixture.kdf.parallelism,
};
const repeatedBytes = (size) => new Uint8Array(size).fill(Number.parseInt(fixture.random.byte_hex, 16));

test("encrypts the canonical Go v1 vector exactly", async () => {
  const result = await createV1Envelope({
    messageId: fixture.message_id,
    secret: fixture.secret,
    message: fixture.message,
    _test: { kdf: cheapKdf, randomBytes: repeatedBytes },
  });
  assert.equal(Buffer.from(result.envelope).toString("base64"), fixture.expected_envelope_base64);
});

test("decrypts the canonical Go v1 vector", async () => {
  const result = await readV1Envelope({
    messageId: fixture.message_id,
    secret: fixture.secret,
    envelope: Buffer.from(fixture.expected_envelope_base64, "base64"),
  });
  assert.equal(result.manifest.message, fixture.message);
  assert.deepEqual(result.attachments, []);
});

test("reads the legacy 4 MiB manifest and reports real monotonic progress", async () => {
  const legacy = await createV1Envelope({
    messageId: fixture.message_id, secret: fixture.secret, message: fixture.message,
    cryptoChunkBytes: 4 * 1024 * 1024,
    _test: { kdf: cheapKdf, randomBytes: repeatedBytes },
  });
  assert.equal(legacy.manifest.chunk_size, 4 * 1024 * 1024);
  const events = [];
  const opened = await readV1Envelope({ messageId: fixture.message_id, secret: fixture.secret, envelope: legacy.envelope, onProgress: (event) => events.push(event) });
  assert.equal(opened.manifest.message, fixture.message);
  assert.equal(events.at(-1).percent, 100);
  assert.ok(events.every((event, index) => index === 0 || event.processedBytes >= events[index - 1].processedBytes));
});

test("uses 512 KiB frames and emits exact multi-chunk encryption totals", async () => {
  const data = new Uint8Array(600 * 1024);
  const events = [];
  const result = await createV1Envelope({
    messageId: fixture.message_id, secret: fixture.secret, attachments: [{ data }],
    onProgress: (event) => events.push(event), progressChunkBytes: 1,
    _test: { kdf: cheapKdf, randomBytes: repeatedBytes },
  });
  assert.equal(result.manifest.chunk_size, 512 * 1024);
  assert.equal(result.manifest.attachments[0].chunks, 2);
  assert.equal(events.at(-1).processedBytes, events.at(-1).totalBytes);
  assert.equal(events.at(-1).percent, 100);
  await createV1Envelope({ messageId: fixture.message_id, secret: fixture.secret, message: "callback", onProgress: () => { throw new Error("observer"); }, _test: { kdf: cheapKdf, randomBytes: repeatedBytes } });
});

test("rejects unsafe recorded crypto chunk sizes", async () => {
  await assert.rejects(() => createV1Envelope({ messageId: fixture.message_id, secret: fixture.secret, cryptoChunkBytes: 100_000, _test: { kdf: cheapKdf, randomBytes: repeatedBytes } }), RangeError);
});

test("derives the canonical production deletion capability", async () => {
  const key = await deriveV1DeletionKey({ messageId: fixture.message_id, secret: fixture.secret });
  assert.equal(bytesToBase64Url(key), fixture.expected_production_deletion_key_base64url);
});

test("attachment frames round trip and reject tampering", async () => {
  const encrypted = await createV1Envelope({
    messageId: fixture.message_id,
    secret: fixture.secret,
    message: "attachment",
    attachments: [{
      name: "note.txt",
      type: "text/plain",
      kind: "text",
      data: new TextEncoder().encode("private attachment"),
    }],
    _test: { kdf: cheapKdf, randomBytes: repeatedBytes },
  });
  const opened = await readV1Envelope({
    messageId: fixture.message_id,
    secret: fixture.secret,
    envelope: encrypted.envelope,
  });
  assert.equal(new TextDecoder().decode(opened.attachments[0].data), "private attachment");

  const damaged = encrypted.envelope.slice();
  damaged[damaged.length - 2] ^= 1;
  await assert.rejects(
    readV1Envelope({ messageId: fixture.message_id, secret: fixture.secret, envelope: damaged }),
    (error) => error instanceof ProtocolError && error.code === "decryption_failed",
  );
});

test("generates canonical private capabilities using rejection sampling", () => {
  const randomBytes = (size) => Uint8Array.from({ length: size }, (_, index) => index === 0 ? 255 : index);
  assert.match(generateMessageId({ randomBytes }), /^[1-9A-HJ-NP-Za-km-z]{12}$/);
  assert.match(generateSecret({ randomBytes }), /^[1-9A-HJ-NP-Za-km-z]{16}$/);
});

test("rejects malformed randomness and duplicate attachment identifiers", async () => {
  assert.throws(() => generateSecret({ randomBytes: () => new Uint8Array(1) }), /exactly/);
  await assert.rejects(createV1Envelope({
    messageId: fixture.message_id,
    secret: fixture.secret,
    attachments: [
      { data: new Uint8Array([1]) },
      { data: new Uint8Array([2]) },
    ],
    _test: { kdf: cheapKdf, randomBytes: repeatedBytes },
  }), (error) => error instanceof ProtocolError && error.code === "random_collision");
});
