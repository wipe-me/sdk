import { argon2id } from "hash-wasm";
import {
  BASE58BTC_ALPHABET,
  CHUNK_SIZE,
  MAX_FREE_MESSAGE_BYTES,
  MESSAGE_ID_LENGTH,
  PROTOCOL_VERSION,
  SECRET_LENGTH,
} from "./constants.js";

export const CIPHER_VERSION = PROTOCOL_VERSION;
export const DEFAULT_KDF = Object.freeze({ memoryKiB: 64 * 1024, iterations: 3, parallelism: 1 });
export const MAX_ENVELOPE_BYTES = MAX_FREE_MESSAGE_BYTES;

const MAGIC = Uint8Array.of(0x57, 0x49, 0x50, 0x45, 0x4d, 0x45, 0x00, 0x01);
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export class ProtocolError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "ProtocolError";
    this.code = code;
  }
}

function fail(code, message, options) {
  throw new ProtocolError(code, message, options);
}

function concatBytes(...parts) {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function uint32(value) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function bytesToBase64Url(bytes) {
  const value = asBytes(bytes, "bytes");
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function secureRandomBytes(size) {
  if (!globalThis.crypto?.getRandomValues) fail("crypto_unavailable", "Secure random generation requires Web Crypto");
  return crypto.getRandomValues(new Uint8Array(size));
}

export function randomBase58(length, randomBytes = secureRandomBytes) {
  if (!Number.isSafeInteger(length) || length < 1) throw new RangeError("length must be a positive integer");
  let result = "";
  while (result.length < length) {
    const batch = exactRandomBytes(randomBytes, Math.max(16, (length - result.length) * 2));
    for (const byte of batch) {
      if (byte >= 232) continue;
      result += BASE58BTC_ALPHABET[byte % BASE58BTC_ALPHABET.length];
      if (result.length === length) break;
    }
  }
  return result;
}

export function generateMessageId(options = {}) {
  return randomBase58(MESSAGE_ID_LENGTH, options.randomBytes ?? secureRandomBytes);
}

export function generateSecret(options = {}) {
  return randomBase58(SECRET_LENGTH, options.randomBytes ?? secureRandomBytes);
}

function exactRandomBytes(randomBytes, size) {
  const value = randomBytes(size);
  if (!(value instanceof Uint8Array) || value.length !== size) {
    throw new TypeError(`randomBytes must return exactly ${size} bytes as Uint8Array`);
  }
  return value;
}

function asBytes(value, name) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw new TypeError(`${name} must be a Uint8Array, ArrayBuffer, or ArrayBuffer view`);
}

async function sha256(bytes) {
  if (!globalThis.crypto?.subtle) fail("crypto_unavailable", "Encryption requires Web Crypto");
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function hkdf(inputKey, info) {
  const key = await crypto.subtle.importKey("raw", inputKey, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({
    name: "HKDF",
    hash: "SHA-256",
    salt: new Uint8Array(0),
    info: typeof info === "string" ? encoder.encode(info) : info,
  }, key, 256));
}

async function aesGcmEncrypt(keyBytes, nonce, plaintext, additionalData) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  return new Uint8Array(await crypto.subtle.encrypt({
    name: "AES-GCM", iv: nonce, additionalData, tagLength: 128,
  }, key, plaintext));
}

async function aesGcmDecrypt(keyBytes, nonce, ciphertext, additionalData) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({
      name: "AES-GCM", iv: nonce, additionalData, tagLength: 128,
    }, key, ciphertext));
  } catch (cause) {
    fail("decryption_failed", "Invalid secret or damaged envelope", { cause });
  }
}

function equalBytes(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function hexToBytes(value, expectedLength) {
  if (typeof value !== "string" || value.length !== expectedLength * 2 || !/^[a-f0-9]+$/.test(value)) {
    fail("invalid_manifest", "Invalid encrypted manifest metadata");
  }
  return Uint8Array.from({ length: expectedLength }, (_, index) => Number.parseInt(value.slice(index * 2, index * 2 + 2), 16));
}

function validateIdentifier(value, length, label) {
  if (typeof value !== "string" || value.length !== length || Array.from(value).some((character) => !BASE58BTC_ALPHABET.includes(character))) {
    fail("invalid_capability", `Invalid v1 ${label}`);
  }
}

async function deriveV1Keys(messageId, secret, kdf) {
  validateIdentifier(messageId, MESSAGE_ID_LENGTH, "message ID");
  validateIdentifier(secret, SECRET_LENGTH, "secret");
  const salt = await sha256(encoder.encode(`wipe.me/envelope/v1/kdf-salt/${messageId}`));
  const root = await argon2id({
    password: encoder.encode(secret), salt, iterations: kdf.iterations,
    parallelism: kdf.parallelism, memorySize: kdf.memoryKiB,
    hashLength: 32, outputType: "binary",
  });
  try {
    return {
      salt,
      encryptionRoot: await hkdf(root, "wipe.me/envelope/v1/encryption"),
      deletionKey: await hkdf(root, "wipe.me/envelope/v1/deletion"),
    };
  } finally {
    root.fill(0);
  }
}

export async function deriveV1DeletionKey({ messageId, secret }) {
  const { encryptionRoot, deletionKey } = await deriveV1Keys(messageId, secret, DEFAULT_KDF);
  encryptionRoot.fill(0);
  return deletionKey;
}

function normalizeAttachment(attachment, index, id, noncePrefix) {
  if (!attachment || typeof attachment !== "object" || !("data" in attachment)) {
    throw new TypeError(`attachments[${index}] must contain binary data`);
  }
  const data = asBytes(attachment.data, `attachments[${index}].data`);
  for (const field of ["name", "type", "kind"]) {
    if (attachment[field] != null && typeof attachment[field] !== "string") {
      throw new TypeError(`attachments[${index}].${field} must be a string`);
    }
  }
  const metadata = {
    id: bytesToHex(id),
    name: attachment.name || `Attachment ${index + 1}`,
    type: attachment.type || "application/octet-stream",
    kind: attachment.kind || "file",
    size: data.byteLength,
    chunks: Math.ceil(data.byteLength / CHUNK_SIZE),
    nonce_prefix: bytesToHex(noncePrefix),
  };
  if (Number.isInteger(attachment.width) && attachment.width > 0) metadata.width = attachment.width;
  if (Number.isInteger(attachment.height) && attachment.height > 0) metadata.height = attachment.height;
  return { data, metadata, id, noncePrefix };
}

function uniqueRandomId(randomBytes, usedIds) {
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const id = exactRandomBytes(randomBytes, 16);
    const hex = bytesToHex(id);
    if (!usedIds.has(hex)) {
      usedIds.add(hex);
      return id;
    }
  }
  fail("random_collision", "Unable to generate a unique attachment identifier");
}

export async function createV1Envelope({ messageId, secret, message, attachments = [], _test } = {}) {
  if (message != null && typeof message !== "string") throw new TypeError("message must be a string");
  if (!Array.isArray(attachments)) throw new TypeError("attachments must be an array");
  const kdf = _test?.kdf ?? DEFAULT_KDF;
  const randomBytes = _test?.randomBytes ?? secureRandomBytes;
  const manifestNonce = exactRandomBytes(randomBytes, 12);
  const usedIds = new Set();
  const normalizedAttachments = attachments.map((attachment, index) => normalizeAttachment(
    attachment, index, uniqueRandomId(randomBytes, usedIds), exactRandomBytes(randomBytes, 8),
  ));
  const manifest = { version: 1 };
  if (message) manifest.message = message;
  manifest.chunk_size = CHUNK_SIZE;
  if (normalizedAttachments.length) manifest.attachments = normalizedAttachments.map(({ metadata }) => metadata);

  const { salt, encryptionRoot, deletionKey } = await deriveV1Keys(messageId, secret, kdf);
  try {
    const publicHeader = concatBytes(MAGIC, uint32(kdf.memoryKiB), uint32(kdf.iterations), Uint8Array.of(kdf.parallelism), salt, manifestNonce);
    const manifestKey = await hkdf(encryptionRoot, "wipe.me/envelope/v1/manifest");
    const encryptedManifest = await aesGcmEncrypt(manifestKey, manifestNonce, encoder.encode(JSON.stringify(manifest)), publicHeader);
    manifestKey.fill(0);
    const parts = [publicHeader, uint32(encryptedManifest.length), encryptedManifest];
    for (let attachmentIndex = 0; attachmentIndex < normalizedAttachments.length; attachmentIndex += 1) {
      const attachment = normalizedAttachments[attachmentIndex];
      const attachmentKey = await hkdf(encryptionRoot, concatBytes(encoder.encode("wipe.me/envelope/v1/attachment/"), attachment.id));
      for (let chunkIndex = 0; chunkIndex < attachment.metadata.chunks; chunkIndex += 1) {
        const start = chunkIndex * CHUNK_SIZE;
        const plaintext = attachment.data.subarray(start, Math.min(start + CHUNK_SIZE, attachment.data.length));
        const frameHeader = concatBytes(Uint8Array.of(0x01), uint32(attachmentIndex), uint32(chunkIndex), uint32(plaintext.length));
        const nonce = concatBytes(attachment.noncePrefix, uint32(chunkIndex));
        const aad = concatBytes(MAGIC, frameHeader, uint32(attachment.metadata.chunks), attachment.id);
        parts.push(frameHeader, await aesGcmEncrypt(attachmentKey, nonce, plaintext, aad));
      }
      attachmentKey.fill(0);
    }
    parts.push(Uint8Array.of(0x00));
    const envelope = concatBytes(...parts);
    if (envelope.length > MAX_ENVELOPE_BYTES) fail("message_too_large", "The encrypted message exceeds the 3 MiB limit. Remove files and try again.");
    return {
      envelope, manifest, deletionKey,
      deletionKeyHeader: bytesToBase64Url(deletionKey),
      contentHash: bytesToHex(await sha256(envelope)),
    };
  } finally {
    encryptionRoot.fill(0);
  }
}

function validateManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest) || manifest.version !== 1 || manifest.chunk_size !== CHUNK_SIZE) {
    fail("unsupported_manifest", "Unsupported encrypted manifest");
  }
  if (manifest.message != null && typeof manifest.message !== "string") fail("invalid_manifest", "Invalid encrypted manifest message");
  if (manifest.attachments != null && !Array.isArray(manifest.attachments)) fail("invalid_manifest", "Invalid encrypted attachment list");
  const usedIds = new Set();
  for (const metadata of manifest.attachments ?? []) {
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) fail("invalid_manifest", "Invalid encrypted attachment metadata");
    for (const field of ["id", "nonce_prefix", "name", "type", "kind"]) {
      if (typeof metadata[field] !== "string") fail("invalid_manifest", "Invalid encrypted attachment metadata");
    }
    if (usedIds.has(metadata.id)) fail("invalid_manifest", "Duplicate encrypted attachment identifier");
    usedIds.add(metadata.id);
    if (!Number.isSafeInteger(metadata.size) || metadata.size < 0 || !Number.isInteger(metadata.chunks) || metadata.chunks !== Math.ceil(metadata.size / CHUNK_SIZE)) {
      fail("invalid_manifest", "Invalid encrypted attachment metadata");
    }
    for (const dimension of ["width", "height"]) {
      if (metadata[dimension] != null && (!Number.isInteger(metadata[dimension]) || metadata[dimension] <= 0)) fail("invalid_manifest", "Invalid attachment dimensions");
    }
  }
}

export async function readV1Envelope({ messageId, secret, envelope } = {}) {
  validateIdentifier(messageId, MESSAGE_ID_LENGTH, "message ID");
  validateIdentifier(secret, SECRET_LENGTH, "secret");
  const bytes = asBytes(envelope, "envelope");
  if (bytes.length < 82 || !equalBytes(bytes.subarray(0, 8), MAGIC)) fail("unsupported_envelope", "Unsupported envelope magic or version");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const kdf = { memoryKiB: view.getUint32(8, false), iterations: view.getUint32(12, false), parallelism: bytes[16] };
  if (kdf.memoryKiB < 64 || kdf.memoryKiB > DEFAULT_KDF.memoryKiB || kdf.iterations < 1 || kdf.iterations > DEFAULT_KDF.iterations || kdf.parallelism !== 1) {
    fail("unsupported_kdf", "Unsupported Argon2id parameters");
  }
  const expectedSalt = await sha256(encoder.encode(`wipe.me/envelope/v1/kdf-salt/${messageId}`));
  if (!equalBytes(expectedSalt, bytes.subarray(17, 49))) fail("message_id_mismatch", "Envelope does not match message ID");
  const manifestNonce = bytes.subarray(49, 61);
  const manifestLength = view.getUint32(61, false);
  const manifestStart = 65;
  const manifestEnd = manifestStart + manifestLength;
  if (manifestLength < 16 || manifestLength > 16 * 1024 * 1024 || manifestEnd > bytes.length) fail("invalid_envelope", "Invalid encrypted manifest length");

  const { encryptionRoot, deletionKey } = await deriveV1Keys(messageId, secret, kdf);
  try {
    const manifestKey = await hkdf(encryptionRoot, "wipe.me/envelope/v1/manifest");
    const manifestPlaintext = await aesGcmDecrypt(manifestKey, manifestNonce, bytes.subarray(manifestStart, manifestEnd), bytes.subarray(0, 61));
    manifestKey.fill(0);
    let manifest;
    try { manifest = JSON.parse(decoder.decode(manifestPlaintext)); }
    catch (cause) { fail("decryption_failed", "Invalid secret or damaged envelope", { cause }); }
    validateManifest(manifest);

    let offset = manifestEnd;
    const openedAttachments = [];
    for (let attachmentIndex = 0; attachmentIndex < (manifest.attachments ?? []).length; attachmentIndex += 1) {
      const metadata = manifest.attachments[attachmentIndex];
      const id = hexToBytes(metadata.id, 16);
      const noncePrefix = hexToBytes(metadata.nonce_prefix, 8);
      const attachmentKey = await hkdf(encryptionRoot, concatBytes(encoder.encode("wipe.me/envelope/v1/attachment/"), id));
      const plaintextChunks = [];
      let totalBytes = 0;
      for (let chunkIndex = 0; chunkIndex < metadata.chunks; chunkIndex += 1) {
        if (offset + 13 > bytes.length || bytes[offset] !== 0x01) fail("invalid_envelope", "Missing or reordered attachment frame");
        const frameHeader = bytes.subarray(offset, offset + 13);
        const frameView = new DataView(frameHeader.buffer, frameHeader.byteOffset, frameHeader.byteLength);
        const plaintextLength = frameView.getUint32(9, false);
        if (frameView.getUint32(1, false) !== attachmentIndex || frameView.getUint32(5, false) !== chunkIndex || plaintextLength > CHUNK_SIZE || totalBytes + plaintextLength > metadata.size) {
          fail("invalid_envelope", "Invalid attachment frame");
        }
        offset += 13;
        const ciphertextEnd = offset + plaintextLength + 16;
        if (ciphertextEnd > bytes.length) fail("invalid_envelope", "Truncated attachment frame");
        const nonce = concatBytes(noncePrefix, uint32(chunkIndex));
        const aad = concatBytes(MAGIC, frameHeader, uint32(metadata.chunks), id);
        const plaintext = await aesGcmDecrypt(attachmentKey, nonce, bytes.subarray(offset, ciphertextEnd), aad);
        plaintextChunks.push(plaintext);
        totalBytes += plaintext.length;
        offset = ciphertextEnd;
      }
      attachmentKey.fill(0);
      if (totalBytes !== metadata.size) fail("invalid_envelope", "Attachment size does not match manifest");
      openedAttachments.push({ metadata, data: concatBytes(...plaintextChunks) });
    }
    if (offset >= bytes.length || bytes[offset] !== 0x00) fail("invalid_envelope", "Missing envelope end frame");
    if (offset + 1 !== bytes.length) fail("invalid_envelope", "Unexpected data after envelope");
    return { manifest, attachments: openedAttachments, deletionKey, deletionKeyHeader: bytesToBase64Url(deletionKey) };
  } finally {
    encryptionRoot.fill(0);
  }
}

export function estimateV1EnvelopeBytes(messageBytes, attachmentSizes = []) {
  if (!Number.isSafeInteger(messageBytes) || messageBytes < 0 || !Array.isArray(attachmentSizes) || attachmentSizes.some((size) => !Number.isSafeInteger(size) || size < 0)) {
    throw new TypeError("messageBytes and attachmentSizes must be non-negative safe integers");
  }
  const encryptedManifestBytes = messageBytes + 512 + 16;
  const framedAttachmentBytes = attachmentSizes.reduce((total, size) => total + size + Math.ceil(size / CHUNK_SIZE) * (13 + 16), 0);
  return 65 + encryptedManifestBytes + framedAttachmentBytes + 1;
}
