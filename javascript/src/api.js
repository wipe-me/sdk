import { MAX_FREE_EXPIRY_MS, MAX_FREE_MESSAGE_BYTES } from "./constants.js";
import { createProgressReporter } from "./progress.js";

const MESSAGE_ID = /^[1-9A-HJ-NP-Za-km-z]{12}$/;
const CLIENT_ID = /^[a-z][a-z0-9._-]{0,31}$/;
const DELETION_KEY = /^[A-Za-z0-9_-]{43}$/;
const CONTENT_HASH = /^[a-f0-9]{64}$/;
const PERFORMANCE_MODEL = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const CLIENT_VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_SPEED_TEST_BYTES = 1024 * 1024;
const MAX_PERFORMANCE_REPORT_BYTES = 8 * 1024;
const MAX_REPORTED_BYTES = 1024 * 1024 * 1024;
const MAX_REPORTED_DURATION_MS = 24 * 60 * 60 * 1000;
const MAX_REPORTED_BPS = 2 ** 40;

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
    if (hash !== await sha256Hex(body)) throw new Error("contentHash does not match envelope");

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

  async retrieveMessage(messageId, { onHeaders, onProgress, progressChunkBytes, signal } = {}) {
    validateMessageId(messageId);
    const response = await this.request(`/api/messages/${messageId}`, { signal });
    const lengthHeader = response.headers.get("content-length");
    const parsedLength = lengthHeader == null ? null : Number(lengthHeader);
    const totalBytes = Number.isSafeInteger(parsedLength) && parsedLength >= 0 ? parsedLength : null;
    const contentHash = response.headers.get("x-wipe-content-hash");
    const cipherVersion = Number(response.headers.get("x-wipe-cipher-version"));
    if (!CONTENT_HASH.test(contentHash ?? "") || cipherVersion !== 1) {
      throw new APIError({ code: "invalid_response", message: "API returned invalid encrypted-message metadata" });
    }
    safeObserver(onHeaders, { totalBytes, contentHash, cipherVersion });
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
    if (envelope.byteLength === 0) {
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

  async getLimits({ signal } = {}) {
    const response = await this.request("/api/limits", { signal });
    const result = await response.json();
    validateLimitsResponse(result);
    return result;
  }

  async testUploadSpeed(sample, { onProgress, progressChunkBytes, signal } = {}) {
    const body = asSpeedTestBytes(sample);
    const startedAt = monotonicNow();
    const response = await this.request("/api/network-test/upload", {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body,
      signal,
      wipeProgress: { phase: "uploading", totalBytes: body.byteLength, onProgress, progressChunkBytes },
    });
    const result = await response.json();
    if (result?.receivedBytes !== body.byteLength) throw invalidResponse("API returned an invalid upload-test response");
    const elapsedMs = Math.max(monotonicNow() - startedAt, 0.001);
    return { receivedBytes: result.receivedBytes, elapsedMs, bytesPerSecond: Math.round(body.byteLength * 1000 / elapsedMs) };
  }

  async testDownloadSpeed(bytes, { onProgress, progressChunkBytes, signal } = {}) {
    validateSpeedTestSize(bytes);
    const startedAt = monotonicNow();
    const response = await this.request(`/api/network-test/download?bytes=${bytes}`, { signal });
    const declared = Number(response.headers.get("content-length"));
    if (declared !== bytes || response.headers.get("cache-control") !== "no-store") {
      throw invalidResponse("API returned invalid download-test metadata");
    }
    const data = await readResponseBytes(response, bytes, { phase: "downloading", onProgress, progressChunkBytes });
    const elapsedMs = Math.max(monotonicNow() - startedAt, 0.001);
    return { data, receivedBytes: data.byteLength, elapsedMs, bytesPerSecond: Math.round(data.byteLength * 1000 / elapsedMs) };
  }

  async submitPerformanceReport(report, { keepalive = false, signal } = {}) {
    validatePerformanceReport(report);
    const body = JSON.stringify(report);
    if (new TextEncoder().encode(body).byteLength > MAX_PERFORMANCE_REPORT_BYTES) {
      throw new Error("performance report exceeds 8 KiB");
    }
    const response = await this.request("/api/performance-reports", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      keepalive,
      signal,
    });
    const result = await response.json();
    if (result?.accepted !== true || !UUID.test(result.id ?? "")) throw invalidResponse("API returned an invalid performance-report response");
    return result;
  }

  async createPerformanceReport(report, options) {
    return this.submitPerformanceReport(report, options);
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

function safeObserver(callback, event) { try { callback?.(event); } catch { /* observer only */ } }
function safeProgress(callback, event) { safeObserver(callback, event); }
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

function asSpeedTestBytes(value) {
  const bytes = asBytes(value);
  validateSpeedTestSize(bytes.byteLength);
  return bytes;
}

function validateSpeedTestSize(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_SPEED_TEST_BYTES) {
    throw new RangeError("speed-test size must be between 1 and 1048576 bytes");
  }
}

function monotonicNow() { return globalThis.performance?.now?.() ?? Date.now(); }

async function readResponseBytes(response, totalBytes, { phase, onProgress, progressChunkBytes }) {
  if (!response.body?.getReader) {
    const result = new Uint8Array(await response.arrayBuffer());
    if (result.byteLength !== totalBytes) throw invalidResponse("Response length did not match Content-Length");
    safeProgress(onProgress, { phase, processedBytes: totalBytes, totalBytes, percent: 100 });
    return result;
  }
  const reporter = createProgressReporter({ phase, totalBytes, onProgress, progressChunkBytes });
  const chunks = []; let received = 0; const reader = response.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value); received += value.byteLength; reporter.set(received);
    }
  } finally { reader.releaseLock(); }
  if (received !== totalBytes) throw invalidResponse("Response length did not match Content-Length");
  reporter.finish();
  return concatChunks(chunks, received);
}

function invalidResponse(message) { return new APIError({ code: "invalid_response", message }); }

function integer(value, minimum, maximum) { return Number.isSafeInteger(value) && value >= minimum && value <= maximum; }
function objectWithKeys(value, allowed) {
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).every((key) => allowed.includes(key));
}

function validateLimitsResponse(value) {
  const names = ["messageBytes", "maxExpirySeconds", "devices", "apiKeys", "messagesPerMinute", "uploadBytesPerHour", "speedTestBytesPerRequest", "speedTestBytesPerHour"];
  if (!objectWithKeys(value, ["authenticated", "plan", "limits", "usage"]) || typeof value.authenticated !== "boolean" || typeof value.plan !== "string" || !objectWithKeys(value.limits, names) || !names.every((key) => integer(value.limits[key], 0, Number.MAX_SAFE_INTEGER))) {
    throw invalidResponse("API returned an invalid limits response");
  }
}

function validatePerformanceReport(value) {
  const rootKeys = ["schemaVersion", "flow", "result", "encryptedBytes", "plaintextBytes", "estimated", "actual", "completedBytes", "networkEstimate", "cryptoEstimate", "estimateModel", "client"];
  if (!objectWithKeys(value, rootKeys) || value.schemaVersion !== 1 || !["create", "open"].includes(value.flow)) throw new Error("invalid performance report");
  const create = value.flow === "create";
  const results = create ? ["success", "cancelled", "transport_error"] : ["success", "cancelled", "transport_error", "integrity_error", "decryption_error"];
  if (!results.includes(value.result) || !integer(value.encryptedBytes, 1, MAX_REPORTED_BYTES) || (value.plaintextBytes != null && !integer(value.plaintextBytes, 0, MAX_REPORTED_BYTES))) throw new Error("invalid performance report");
  validateTimings(value.estimated, create, true); validateTimings(value.actual, create, value.result === "success");
  validateEstimate(value.networkEstimate, create ? "uploadBytesPerSecond" : "downloadBytesPerSecond");
  validateEstimate(value.cryptoEstimate, create ? "encryptBytesPerSecond" : "decryptBytesPerSecond");
  const completedKey = create ? "upload" : "download";
  if (value.completedBytes != null && (!objectWithKeys(value.completedBytes, [completedKey]) || !integer(value.completedBytes[completedKey], 0, value.encryptedBytes))) throw new Error("invalid performance report");
  if (!PERFORMANCE_MODEL.test(value.estimateModel ?? "") || !objectWithKeys(value.client, ["kind", "version", "platform", "browserFamily"]) || !CLIENT_ID.test(value.client.kind ?? "") || !CLIENT_VERSION.test(value.client.version ?? "") || !["mobile", "desktop", "server", "unknown"].includes(value.client.platform) || (value.client.browserFamily != null && !["chrome", "firefox", "safari", "edge", "other", "unknown"].includes(value.client.browserFamily))) throw new Error("invalid performance report");
}

function validateTimings(value, create, required) {
  const phases = create ? ["encryptMs", "uploadMs"] : ["downloadMs", "decryptMs"];
  if (!objectWithKeys(value, [...phases, "totalMs"]) || !integer(value.totalMs, 0, MAX_REPORTED_DURATION_MS) || phases.some((key) => required ? !integer(value[key], 0, MAX_REPORTED_DURATION_MS) : value[key] != null && !integer(value[key], 0, MAX_REPORTED_DURATION_MS))) throw new Error("invalid performance report");
}

function validateEstimate(value, rateKey) {
  if (value == null) return;
  if (!objectWithKeys(value, [rateKey, "sampleAgeMs"]) || !integer(value[rateKey], 1, MAX_REPORTED_BPS) || !integer(value.sampleAgeMs, 0, 365 * 24 * 60 * 60 * 1000)) throw new Error("invalid performance report");
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
