export const BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export const MESSAGE_ID_LENGTH = 12;
export const SECRET_LENGTH = 16;
export const PROTOCOL_VERSION = 1;
export const MIN_CRYPTO_CHUNK_BYTES = 64 * 1024;
export const DEFAULT_CRYPTO_CHUNK_BYTES = 512 * 1024;
export const MAX_CRYPTO_CHUNK_BYTES = 4 * 1024 * 1024;
export const DEFAULT_PROGRESS_CHUNK_BYTES = 100 * 1024;
// Backward-compatible name for callers that imported the original writer constant.
export const CHUNK_SIZE = DEFAULT_CRYPTO_CHUNK_BYTES;
export const MAX_FREE_MESSAGE_BYTES = 3 * 1024 * 1024;
export const MAX_FREE_EXPIRY_MS = 14 * 24 * 60 * 60 * 1000;
