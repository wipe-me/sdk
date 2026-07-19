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

test("implements limits and measured network-test operations", async () => {
  const calls = [];
  const limits = { authenticated: false, plan: "anonymous", limits: {
    messageBytes: 3145728, maxExpirySeconds: 1209600, devices: 0, apiKeys: 0,
    messagesPerMinute: 3, uploadBytesPerHour: 31457280,
    speedTestBytesPerRequest: 1048576, speedTestBytesPerHour: 10485760,
  }, usage: null };
  const fetch = async (url, init = {}) => {
    calls.push({ url, init });
    if (url.endsWith("/api/limits")) return Response.json(limits);
    if (url.endsWith("/api/network-test/upload")) return Response.json({ receivedBytes: init.body.byteLength });
    return new Response(new Uint8Array(64), { headers: { "content-length": "64", "cache-control": "no-store" } });
  };
  const client = new WipeClient({ fetch });
  assert.deepEqual(await client.getLimits(), limits);
  const upload = await client.testUploadSpeed(new Uint8Array(32));
  const download = await client.testDownloadSpeed(64);
  assert.equal(upload.receivedBytes, 32);
  assert.ok(upload.bytesPerSecond > 0);
  assert.equal(download.receivedBytes, 64);
  assert.equal(download.data.byteLength, 64);
  assert.ok(download.bytesPerSecond > 0);
  assert.equal(calls[1].init.headers["content-type"], "application/octet-stream");
  await assert.rejects(client.testDownloadSpeed(1048577), /1048576/);
});

test("submits only schema-valid privacy-safe performance reports", async () => {
  let sent;
  const fetch = async (_url, init) => {
    sent = JSON.parse(init.body);
    return Response.json({ accepted: true, id: "123e4567-e89b-42d3-a456-426614174000" }, { status: 201 });
  };
  const client = new WipeClient({ fetch });
  const report = {
    schemaVersion: 1, flow: "create", result: "success", encryptedBytes: 65536, plaintextBytes: 64000,
    estimated: { encryptMs: 210, uploadMs: 800, totalMs: 1010 },
    actual: { encryptMs: 225, uploadMs: 920, totalMs: 1145 },
    completedBytes: { upload: 65536 },
    networkEstimate: { uploadBytesPerSecond: 81920, sampleAgeMs: 12000 },
    cryptoEstimate: { encryptBytesPerSecond: 5000000, sampleAgeMs: 60000 },
    estimateModel: "client-baseline-v1",
    client: { kind: "web", version: "0.4.0", platform: "desktop", browserFamily: "chrome" },
  };
  assert.equal((await client.submitPerformanceReport(report)).accepted, true);
  assert.deepEqual(sent, report);
  await assert.rejects(client.submitPerformanceReport({ ...report, messageId: id }), /invalid performance report/);
});

test("retrieval exposes authenticated headers before body progress", async () => {
  const order = [];
  const client = new WipeClient({ fetch: async () => new Response(Uint8Array.of(1, 2, 3), {
    headers: { "content-length": "3", "x-wipe-content-hash": "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81", "x-wipe-cipher-version": "1" },
  }) });
  await client.retrieveMessage(id, { onHeaders: (metadata) => order.push(["headers", metadata.totalBytes]), onProgress: () => order.push(["progress"]) });
  assert.deepEqual(order[0], ["headers", 3]);
  assert.equal(order.at(-1)[0], "progress");
});
