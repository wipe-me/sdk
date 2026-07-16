import test from "node:test";
import assert from "node:assert/strict";
import { APIError, MAX_FREE_MESSAGE_BYTES, WipeClient } from "../src/index.js";

const id = "1K7mQ2xR8VpC";
const deletionKey = "A".repeat(43);
const now = 1_800_000_000_000;

test("implements create, retrieve, delete, and health without the obsolete header", async () => {
  const requests = [];
  const fetch = async (url, init = {}) => {
    requests.push({ url, init });
    if (init.method === "PUT") return Response.json({ id, created: true }, { status: 201 });
    if (init.method === "DELETE") return Response.json({ deleted: true });
    if (url.endsWith("/health")) return Response.json({ status: "ok" });
    return new Response(Uint8Array.of(1, 2, 3), { headers: { "x-wipe-content-hash": "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81", "x-wipe-cipher-version": "1" } });
  };
  const client = new WipeClient({ baseURL: "https://stage.wipe.me", clientId: "mobile-ios", fetch, now: () => now });
  assert.deepEqual(await client.createMessage({ messageId: id, envelope: Uint8Array.of(9), deletionKey, expiresAt: now + 1000 }), { id, created: true });
  assert.deepEqual((await client.retrieveMessage(id)).envelope, Uint8Array.of(1, 2, 3));
  assert.deepEqual(await client.deleteMessage(id, deletionKey), { deleted: true });
  assert.deepEqual(await client.health(), { status: "ok" });
  assert.equal(requests[0].init.headers["x-wipe-client"], "mobile-ios");
  assert.ok(!requests.some(({ init }) => Object.keys(init.headers ?? {}).some((key) => key.toLowerCase() === "x-wipe-on-read")));
  assert.ok(requests.slice(1).every(({ init }) => !("x-wipe-client" in (init.headers ?? {}))));
});

test("parses stable and legacy API errors", async () => {
  const client = new WipeClient({ fetch: async () => Response.json({ error: "Slow down", code: "message_rate_limited", retryAfter: 42 }, { status: 429 }) });
  await assert.rejects(client.health(), (error) => error instanceof APIError && error.status === 429 && error.code === "message_rate_limited" && error.retryAfter === 42);
  const legacy = new WipeClient({ fetch: async () => new Response("", { status: 503, statusText: "Unavailable" }) });
  await assert.rejects(legacy.health(), (error) => error instanceof APIError && error.code === "http_503");
});

test("rejects a retrieved envelope whose declared content hash does not match", async () => {
  const client = new WipeClient({ fetch: async () => new Response(Uint8Array.of(1, 2, 3), {
    headers: { "x-wipe-content-hash": "b".repeat(64), "x-wipe-cipher-version": "1" },
  }) });
  await assert.rejects(
    client.retrieveMessage(id),
    (error) => error instanceof APIError && error.code === "content_hash_mismatch",
  );
});

test("validates free limits, client identifiers, and canonical IDs", async () => {
  assert.throws(() => new WipeClient({ clientId: "Wallet App" }));
  assert.throws(() => new WipeClient({ baseURL: "https://wipe.me/#private-secret" }));
  const client = new WipeClient({ fetch: async () => { throw new Error("must not send"); }, now: () => now });
  await assert.rejects(client.createMessage({ messageId: id, envelope: new Uint8Array(MAX_FREE_MESSAGE_BYTES + 1), deletionKey, expiresAt: now + 1 }), /3 MiB/);
  await assert.rejects(client.createMessage({ messageId: "0K7mQ2xR8VpC", envelope: Uint8Array.of(1), deletionKey, expiresAt: now + 1 }), /canonical/);
});
