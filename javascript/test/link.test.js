import test from "node:test";
import assert from "node:assert/strict";
import { formatPrivateLink, normalizeBase58, parsePrivateLink } from "../src/index.js";

test("normalizes presentation separators", () => {
  assert.equal(normalizeBase58("1K7m-Q2xR 8VpC", 12), "1K7mQ2xR8VpC");
});

test("rejects ambiguous Base58 characters", () => {
  assert.throws(() => normalizeBase58("0K7mQ2xR8VpC", 12));
});

test("formats and parses private links without sending the fragment", () => {
  const link = formatPrivateLink("https://wipe.me", "1K7mQ2xR8VpC", "7YWHMfk9JCB7P4eG");
  assert.equal(link, "https://wipe.me/1K7m-Q2xR-8VpC#7YWH-Mfk9-JCB7-P4eG");
  assert.deepEqual(parsePrivateLink(link), { messageId: "1K7mQ2xR8VpC", secret: "7YWHMfk9JCB7P4eG" });
});
