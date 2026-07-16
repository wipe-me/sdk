export { APIError, WipeClient } from "./api.js";
export {
  BASE58BTC_ALPHABET,
  CHUNK_SIZE,
  MAX_FREE_EXPIRY_MS,
  MAX_FREE_MESSAGE_BYTES,
  MESSAGE_ID_LENGTH,
  PROTOCOL_VERSION,
  SECRET_LENGTH,
} from "./constants.js";

import {
  BASE58BTC_ALPHABET,
  MESSAGE_ID_LENGTH,
  SECRET_LENGTH,
} from "./constants.js";


export function normalizeBase58(value, expectedLength) {
  if (typeof value !== "string") throw new TypeError("Base58 value must be a string");
  const canonical = value.replaceAll("-", "").replaceAll(" ", "");
  if (canonical.length !== expectedLength) {
    throw new Error(`Expected ${expectedLength} Base58 characters, got ${canonical.length}`);
  }
  for (const character of canonical) {
    if (!BASE58BTC_ALPHABET.includes(character)) throw new Error(`Invalid Base58 character ${JSON.stringify(character)}`);
  }
  return canonical;
}

export function groupBase58(value, size = 4) {
  if (!Number.isInteger(size) || size < 1) throw new RangeError("Group size must be positive");
  return Array.from({ length: Math.ceil(value.length / size) }, (_, index) => value.slice(index * size, (index + 1) * size)).join("-");
}

export function parsePrivateLink(value) {
  const url = new URL(value);
  const segment = url.pathname.split("/").filter(Boolean).at(-1) ?? "";
  return {
    messageId: normalizeBase58(segment, MESSAGE_ID_LENGTH),
    secret: normalizeBase58(url.hash.slice(1), SECRET_LENGTH),
  };
}

export function formatPrivateLink(site, messageId, secret) {
  const url = new URL(site);
  url.pathname = `${url.pathname.replace(/\/$/, "")}/${groupBase58(normalizeBase58(messageId, MESSAGE_ID_LENGTH))}`;
  url.hash = groupBase58(normalizeBase58(secret, SECRET_LENGTH));
  return url.toString();
}

export {
  CIPHER_VERSION,
  DEFAULT_KDF,
  MAX_ENVELOPE_BYTES,
  ProtocolError,
  bytesToBase64Url,
  createV1Envelope,
  deriveV1DeletionKey,
  estimateV1EnvelopeBytes,
  generateMessageId,
  generateSecret,
  randomBase58,
  readV1Envelope,
} from "./crypto.js";
