import { DEFAULT_PROGRESS_CHUNK_BYTES } from "./constants.js";

export function validateProgressChunkBytes(value = DEFAULT_PROGRESS_CHUNK_BYTES) {
  if (!Number.isSafeInteger(value) || value < 1) throw new RangeError("progressChunkBytes must be a positive safe integer");
  return value;
}

export function createProgressReporter({ phase, totalBytes, onProgress, progressChunkBytes } = {}) {
  if (!Number.isSafeInteger(totalBytes) || totalBytes < 0) throw new RangeError("totalBytes must be a non-negative safe integer");
  const threshold = validateProgressChunkBytes(progressChunkBytes);
  let lastEmitted = -1;
  let processed = 0;
  const emit = (force, details) => {
    if (typeof onProgress !== "function") return;
    if (!force && lastEmitted >= 0 && processed - lastEmitted < threshold) return;
    lastEmitted = processed;
    const event = { phase, processedBytes: processed, totalBytes, percent: totalBytes === 0 ? 100 : Math.min(100, Math.floor(processed * 100 / totalBytes)), ...details };
    try { onProgress(event); } catch { /* observers cannot affect crypto or transport */ }
  };
  return {
    add(bytes, details) { processed = Math.min(totalBytes, processed + bytes); emit(processed === totalBytes, details); },
    set(bytes, details) { processed = Math.max(processed, Math.min(totalBytes, bytes)); emit(processed === totalBytes, details); },
    finish(details) { processed = totalBytes; emit(true, details); },
  };
}
