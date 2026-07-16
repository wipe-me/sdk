import { MAX_FREE_EXPIRY_MS, MAX_FREE_MESSAGE_BYTES } from "./constants.js";
import { createProgressReporter } from "./progress.js";

const MESSAGE_ID = /^[1-9A-HJ-NP-Za-km-z]{12}$/;
const CLIENT_ID = /^[a-z][a-z0-9._-]{0,31}$/;
const DELETION_KEY = /^[A-Za-z0-9_-]{43}$/;
const CONTENT_HASH = /^[a-f0-9]{64}$/;

export class APIError extends Error {
  constructor({ status = null, code = "unknown_error", message = "Wipe.me API request failed", retryAfter = null }) {
    super(message);
    this.name = "APIError";
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

export class WipeClient {
  constructor({ baseURL = "https://wipe.me", clientId = "sdk-js", fetch: fetchImpl = globalThis.fetch, now = Date.now } = {}) {
    if (!CLIENT_ID.test(clientId)) throw new Error("clientId must match ^[a-z][a-z0-9._-]{0,31}$");
    if (typeof fetchImpl !== "function") throw new Error("A Fetch API implementation is required");
    const parsedBaseURL = new URL(baseURL);
    if (!/^https?:$/.test(parsedBaseURL.protocol) || parsedBaseURL.username || parsedBaseURL.password || parsedBaseURL.search || parsedBaseURL.hash) {
      throw new Error("baseURL must be an HTTP(S) URL without credentials, query, or fragment");
    }
    this.baseURL = parsedBaseURL.toString().replace(/\/$/, "");
    this.clientId = clientId;
    this.fetch = fetchImpl;
    this.now = now;
  }

  async createMessage({ messageId, envelope, deletionKey, expiresAt, contentHash, onProgress, progressChunkBytes, signal } = {}) {
    validateMessageId(messageId);
    const body = asBytes(envelope);
    if (body.byteLength === 0) throw new Error("envelope must not be empty");
    if (body.byteLength > MAX_FREE_MESSAGE_BYTES) throw new Error("envelope exceeds the 3 MiB free limit");
    if (!DELETION_KEY.test(deletionKey ?? "")) throw new Error("deletionKey must be 43-character unpadded base64url");
    const now = this.now();
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= now || expiresAt > now + MAX_FREE_EXPIRY_MS) {
      throw new Error("expiresAt must be in the future and no more than 14 days away");
    }
    const hash = contentHash ?? await sha256Hex(body);
    if (!CONTENT_HASH.test(hash)) throw new Error("contentHash must be a lowercase hexadecimal SHA-256 digest");

    const response = await this.request(`/api/messages/${messageId}`, {
      method: "PUT",
      headers: {
        "content-type": "application/octet-stream",
        "x-wipe-content-hash": hash,
        "x-wipe-deletion-key": deletionKey,
        "x-wipe-cipher-version": "1",
        "x-wipe-client": this.clientId,
        "x-wipe-expires-at": String(expiresAt),
      },
      body,
      signal,
      wipeProgress: { phase: "uploading", totalBytes: body.byteLength, onProgress, progressChunkBytes },
    });
    const result = await response.json();
    if (result.id !== messageId || typeof result.created !== "boolean") {
      throw new APIError({ code: "invalid_response", message: "API returned an invalid creation response" });
    }
    return result;
  }

  async retrieveMessage(messageId, { onProgress, progressChunkBytes, signal } = {}) {
    validateMessageId(messageId);
    const response = await this.request(`/api/messages/${messageId}`, { signal });
    const lengthHeader = response.headers.get("content-length");
    const parsedLength = lengthHeader == null ? null : Number(lengthHeader);
    const totalBytes = Number.isSafeInteger(parsedLength) && parsedLength >= 0 ? parsedLength : null;
    let envelope;
    if (response.body?.getReader) {
      const chunks = [];
      let received = 0;
      const reporter = totalBytes == null ? null : createProgressReporter({ phase: "downloading", totalBytes, onProgress, progressChunkBytes });
      const reader = response.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          received += value.byteLength;
          reporter?.set(received);
        }
      } finally { reader.releaseLock(); }
      if (totalBytes != null && received !== totalBytes) throw new APIError({ code: "invalid_response", message: "Encrypted-message length did not match Content-Length" });
      envelope = concatChunks(chunks, received);
      if (totalBytes == null) safeProgress(onProgress, { phase: "downloading", processedBytes: received, totalBytes: received, percent: 100 });
      else reporter.finish();
    } else {
      envelope = new Uint8Array(await response.arrayBuffer());
      if (totalBytes != null && envelope.byteLength !== totalBytes) throw new APIError({ code: "invalid_response", message: "Encrypted-message length did not match Content-Length" });
      safeProgress(onProgress, { phase: "downloading", processedBytes: envelope.byteLength, totalBytes: totalBytes ?? envelope.byteLength, percent: 100 });
    }
    const contentHash = response.headers.get("x-wipe-content-hash");
    const cipherVersion = Number(response.headers.get("x-wipe-cipher-version"));
    if (envelope.byteLength === 0 || !CONTENT_HASH.test(contentHash ?? "") || cipherVersion !== 1) {
      throw new APIError({ code: "invalid_response", message: "API returned invalid encrypted-message metadata" });
    }
    if (await sha256Hex(envelope) !== contentHash) {
      throw new APIError({ code: "content_hash_mismatch", message: "Encrypted message failed its integrity check" });
    }
    return { envelope, contentHash, cipherVersion };
  }

  async deleteMessage(messageId, deletionKey) {
    validateMessageId(messageId);
    if (!DELETION_KEY.test(deletionKey ?? "")) throw new Error("deletionKey must be 43-character unpadded base64url");
    const response = await this.request(`/api/messages/${messageId}`, {
      method: "DELETE",
      headers: { "x-wipe-deletion-key": deletionKey },
    });
    const result = await response.json();
    if (result.deleted !== true) throw new APIError({ code: "invalid_response", message: "API returned an invalid deletion response" });
    return result;
  }

  async health() {
    const response = await this.request("/health");
    const result = await response.json();
    if (result.status !== "ok") throw new APIError({ code: "invalid_response", message: "API returned an invalid health response" });
    return result;
  }

  async request(path, init = {}) {
    let response;
    try {
      response = await this.fetch(`${this.baseURL}${path}`, init);
    } catch (cause) {
      if (cause?.name === "AbortError") throw cause;
      throw new APIError({ code: "transport_error", message: cause instanceof Error ? cause.message : "Network request failed" });
    }
    if (!response.ok) throw await parseAPIError(response);
    return response;
  }
}

export function createXHRTransport({ createRequest = () => new XMLHttpRequest() } = {}) {
  return (url, init = {}) => new Promise((resolve, reject) => {
    const request = createRequest();
    request.open(init.method ?? "GET", url);
    request.responseType = "arraybuffer";
    new Headers(init.headers).forEach((value, name) => request.setRequestHeader(name, value));
    const config = init.wipeProgress;
    const reporter = config ? createProgressReporter(config) : null;
    request.upload.addEventListener("progress", (event) => reporter?.set(event.loaded));
    request.addEventListener("load", () => {
      reporter?.finish();
      const headers = new Headers();
      for (const line of request.getAllResponseHeaders().trim().split(/[\r\n]+/)) {
        const separator = line.indexOf(":");
        if (separator > 0) headers.append(line.slice(0, separator).trim(), line.slice(separator + 1).trim());
      }
      resolve(new Response(request.response ?? new ArrayBuffer(0), { status: request.status, statusText: request.statusText, headers }));
    });
    request.addEventListener("error", () => reject(new TypeError("Network request failed")));
    request.addEventListener("abort", () => reject(init.signal?.reason ?? new DOMException("Aborted", "AbortError")));
    if (init.signal) {
      if (init.signal.aborted) { request.abort(); return; }
      init.signal.addEventListener("abort", () => request.abort(), { once: true });
    }
    request.send(init.body ?? null);
  });
}

function safeProgress(callback, event) { try { callback?.(event); } catch { /* observer only */ } }
function concatChunks(chunks, length) {
  const result = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}

function validateMessageId(value) {
  if (!MESSAGE_ID.test(value ?? "")) throw new Error("messageId must contain 12 canonical Base58BTC characters");
}

function asBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new TypeError("envelope must be a Uint8Array or ArrayBuffer");
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function parseAPIError(response) {
  let value = {};
  try { value = await response.json(); } catch { /* legacy/non-JSON error */ }
  const retryValue = value.retryAfter ?? response.headers.get("retry-after");
  const retryAfter = retryValue == null || !Number.isFinite(Number(retryValue)) ? null : Number(retryValue);
  return new APIError({
    status: response.status,
    code: typeof value.code === "string" ? value.code : `http_${response.status}`,
    message: typeof value.error === "string" ? value.error : response.statusText || `HTTP ${response.status}`,
    retryAfter,
  });
}
