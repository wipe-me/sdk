"""Wipe.me unified encrypted envelope v1."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import struct
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .link import BASE58BTC_ALPHABET, MESSAGE_ID_LENGTH, SECRET_LENGTH

PROTOCOL_VERSION = 1
MIN_CRYPTO_CHUNK_BYTES = 64 * 1024
DEFAULT_CRYPTO_CHUNK_BYTES = 512 * 1024
MAX_CRYPTO_CHUNK_BYTES = 4 * 1024 * 1024
MAX_ENVELOPE_BYTES = 3 * 1024 * 1024
MANIFEST_LIMIT = 16 * 1024 * 1024
DEFAULT_KDF = (64 * 1024, 3, 1)
MAGIC = b"WIPEME\x00\x01"
ProgressCallback = Callable[[Mapping[str, Any]], None]


class ProtocolError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AttachmentInput:
    data: bytes
    name: str = ""
    type: str = ""
    kind: str = ""
    width: int | None = None
    height: int | None = None


@dataclass(frozen=True)
class EncryptedEnvelope:
    envelope: bytes
    manifest: Mapping[str, Any]
    deletion_key: bytes
    deletion_key_header: str
    content_hash: str


@dataclass(frozen=True)
class DecryptedAttachment:
    metadata: Mapping[str, Any]
    data: bytes


@dataclass(frozen=True)
class DecryptedEnvelope:
    manifest: Mapping[str, Any]
    attachments: tuple[DecryptedAttachment, ...]
    deletion_key: bytes
    deletion_key_header: str


def _fail(code: str, message: str) -> None:
    raise ProtocolError(code, message)


def validate_crypto_chunk_bytes(value: int = DEFAULT_CRYPTO_CHUNK_BYTES) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < MIN_CRYPTO_CHUNK_BYTES or value > MAX_CRYPTO_CHUNK_BYTES or value & (value - 1):
        raise ValueError(f"crypto_chunk_bytes must be a power of two from {MIN_CRYPTO_CHUNK_BYTES} through {MAX_CRYPTO_CHUNK_BYTES}")
    return value


def _validate_capability(value: str, length: int, label: str) -> None:
    if not isinstance(value, str) or len(value) != length or any(ch not in BASE58BTC_ALPHABET for ch in value):
        _fail("invalid_capability", f"invalid v1 {label}")


def _random_base58(length: int, random_bytes: Callable[[int], bytes] = os.urandom) -> str:
    result = []
    while len(result) < length:
        batch = random_bytes(max(16, (length - len(result)) * 2))
        if not isinstance(batch, bytes):
            raise TypeError("random source must return bytes")
        for value in batch:
            if value < 232:
                result.append(BASE58BTC_ALPHABET[value % 58])
                if len(result) == length:
                    break
    return "".join(result)


def generate_message_id() -> str:
    return _random_base58(MESSAGE_ID_LENGTH)


def generate_secret() -> str:
    return _random_base58(SECRET_LENGTH)


def deletion_key_header(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")


def _hkdf(key: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=info).derive(key)


def _derive_keys(message_id: str, secret: str, kdf: tuple[int, int, int]) -> tuple[bytes, bytes, bytes]:
    _validate_capability(message_id, MESSAGE_ID_LENGTH, "message ID")
    _validate_capability(secret, SECRET_LENGTH, "secret")
    memory, iterations, parallelism = kdf
    salt = hashlib.sha256(f"wipe.me/envelope/v1/kdf-salt/{message_id}".encode()).digest()
    root = hash_secret_raw(secret.encode(), salt, iterations, memory, parallelism, 32, Type.ID, version=ARGON2_VERSION)
    return salt, _hkdf(root, b"wipe.me/envelope/v1/encryption"), _hkdf(root, b"wipe.me/envelope/v1/deletion")


def derive_deletion_key(message_id: str, secret: str) -> bytes:
    _, _, key = _derive_keys(message_id, secret, DEFAULT_KDF)
    return key


def _progress(callback: ProgressCallback | None, phase: str, processed: int, total: int, **details: int) -> None:
    if callback is None:
        return
    event: dict[str, Any] = {"phase": phase, "processedBytes": processed, "totalBytes": total, "percent": 100 if total == 0 else min(100, processed * 100 // total), **details}
    try:
        callback(event)
    except Exception:
        pass


def _manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def encrypt(
    message_id: str,
    secret: str,
    message: str = "",
    attachments: Sequence[AttachmentInput] = (),
    *,
    crypto_chunk_bytes: int = DEFAULT_CRYPTO_CHUNK_BYTES,
    on_progress: ProgressCallback | None = None,
    _kdf: tuple[int, int, int] = DEFAULT_KDF,
    _random_bytes: Callable[[int], bytes] = os.urandom,
) -> EncryptedEnvelope:
    chunk_size = validate_crypto_chunk_bytes(crypto_chunk_bytes)
    if not isinstance(message, str):
        raise TypeError("message must be a string")
    nonce = _random_bytes(12)
    if len(nonce) != 12:
        raise ValueError("random source returned the wrong number of bytes")
    manifest: dict[str, Any] = {"version": 1}
    if message:
        manifest["message"] = message
    manifest["chunk_size"] = chunk_size
    normalized: list[tuple[AttachmentInput, bytes, bytes, dict[str, Any]]] = []
    used: set[str] = set()
    for index, item in enumerate(attachments):
        if not isinstance(item, AttachmentInput) or not isinstance(item.data, bytes):
            raise TypeError(f"attachments[{index}] must be AttachmentInput with bytes data")
        attachment_id = b""
        for _ in range(32):
            candidate = _random_bytes(16)
            if len(candidate) != 16:
                raise ValueError("random source returned the wrong number of bytes")
            if candidate.hex() not in used:
                attachment_id = candidate
                used.add(candidate.hex())
                break
        if not attachment_id:
            _fail("random_collision", "unable to generate a unique attachment identifier")
        prefix = _random_bytes(8)
        if len(prefix) != 8:
            raise ValueError("random source returned the wrong number of bytes")
        metadata: dict[str, Any] = {
            "id": attachment_id.hex(), "name": item.name or f"Attachment {index + 1}",
            "type": item.type or "application/octet-stream", "kind": item.kind or "file",
            "size": len(item.data), "chunks": math.ceil(len(item.data) / chunk_size), "nonce_prefix": prefix.hex(),
        }
        if item.width is not None:
            if not isinstance(item.width, int) or item.width <= 0: raise ValueError("attachment width must be positive")
            metadata["width"] = item.width
        if item.height is not None:
            if not isinstance(item.height, int) or item.height <= 0: raise ValueError("attachment height must be positive")
            metadata["height"] = item.height
        normalized.append((item, attachment_id, prefix, metadata))
    if normalized:
        manifest["attachments"] = [item[3] for item in normalized]
    salt, encryption_root, deletion_key = _derive_keys(message_id, secret, _kdf)
    memory, iterations, parallelism = _kdf
    header = MAGIC + struct.pack(">IIB", memory, iterations, parallelism) + salt + nonce
    plain_manifest = _manifest_bytes(manifest)
    encrypted_manifest = AESGCM(_hkdf(encryption_root, b"wipe.me/envelope/v1/manifest")).encrypt(nonce, plain_manifest, header)
    total = len(plain_manifest) + sum(len(item.data) for item, *_ in normalized)
    processed = len(plain_manifest)
    _progress(on_progress, "encrypting", processed, total)
    parts = [header, struct.pack(">I", len(encrypted_manifest)), encrypted_manifest]
    for attachment_index, (item, attachment_id, prefix, metadata) in enumerate(normalized):
        key = _hkdf(encryption_root, b"wipe.me/envelope/v1/attachment/" + attachment_id)
        for chunk_index in range(metadata["chunks"]):
            plain = item.data[chunk_index * chunk_size:(chunk_index + 1) * chunk_size]
            frame = b"\x01" + struct.pack(">III", attachment_index, chunk_index, len(plain))
            aad = MAGIC + frame + struct.pack(">I", metadata["chunks"]) + attachment_id
            parts.extend((frame, AESGCM(key).encrypt(prefix + struct.pack(">I", chunk_index), plain, aad)))
            processed += len(plain)
            _progress(on_progress, "encrypting", processed, total, attachmentIndex=attachment_index, chunkIndex=chunk_index)
    parts.append(b"\x00")
    envelope = b"".join(parts)
    if len(envelope) > MAX_ENVELOPE_BYTES:
        _fail("message_too_large", "encrypted message exceeds the 3 MiB limit")
    _progress(on_progress, "encrypting", total, total)
    return EncryptedEnvelope(envelope, manifest, deletion_key, deletion_key_header(deletion_key), hashlib.sha256(envelope).hexdigest())


def _validate_manifest(manifest: Any) -> int:
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        _fail("unsupported_manifest", "unsupported encrypted manifest")
    try: chunk_size = validate_crypto_chunk_bytes(manifest.get("chunk_size"))
    except (TypeError, ValueError): _fail("unsupported_manifest", "unsupported encrypted manifest chunk_size")
    if "message" in manifest and not isinstance(manifest["message"], str): _fail("invalid_manifest", "invalid encrypted manifest message")
    attachments = manifest.get("attachments", [])
    if not isinstance(attachments, list): _fail("invalid_manifest", "invalid encrypted attachment list")
    used: set[str] = set()
    for item in attachments:
        if not isinstance(item, dict) or any(not isinstance(item.get(key), str) for key in ("id", "nonce_prefix", "name", "type", "kind")): _fail("invalid_manifest", "invalid attachment metadata")
        try: identifier, prefix = bytes.fromhex(item["id"]), bytes.fromhex(item["nonce_prefix"])
        except ValueError: _fail("invalid_manifest", "invalid attachment metadata")
        if len(identifier) != 16 or identifier.hex() != item["id"] or len(prefix) != 8 or prefix.hex() != item["nonce_prefix"] or item["id"] in used: _fail("invalid_manifest", "invalid or duplicate attachment identifier")
        used.add(item["id"])
        size, chunks = item.get("size"), item.get("chunks")
        if not isinstance(size, int) or size < 0 or size > MAX_ENVELOPE_BYTES or not isinstance(chunks, int) or chunks != math.ceil(size / chunk_size): _fail("invalid_manifest", "invalid attachment layout")
    return chunk_size


def decrypt(envelope: bytes, message_id: str, secret: str, *, on_progress: ProgressCallback | None = None) -> DecryptedEnvelope:
    _validate_capability(message_id, MESSAGE_ID_LENGTH, "message ID"); _validate_capability(secret, SECRET_LENGTH, "secret")
    if not isinstance(envelope, bytes): raise TypeError("envelope must be bytes")
    if len(envelope) < 82 or envelope[:8] != MAGIC: _fail("unsupported_envelope", "unsupported envelope magic or version")
    memory, iterations, parallelism = struct.unpack(">IIB", envelope[8:17])
    if memory < 64 or memory > DEFAULT_KDF[0] or iterations < 1 or iterations > DEFAULT_KDF[1] or parallelism != 1: _fail("unsupported_kdf", "unsupported Argon2id parameters")
    salt = hashlib.sha256(f"wipe.me/envelope/v1/kdf-salt/{message_id}".encode()).digest()
    if envelope[17:49] != salt: _fail("message_id_mismatch", "envelope does not match message ID")
    nonce = envelope[49:61]; manifest_length = struct.unpack(">I", envelope[61:65])[0]; manifest_end = 65 + manifest_length
    if manifest_length < 16 or manifest_length > MANIFEST_LIMIT or manifest_end > len(envelope): _fail("invalid_envelope", "invalid encrypted manifest length")
    _, encryption_root, deletion_key = _derive_keys(message_id, secret, (memory, iterations, parallelism))
    try: plain_manifest = AESGCM(_hkdf(encryption_root, b"wipe.me/envelope/v1/manifest")).decrypt(nonce, envelope[65:manifest_end], envelope[:61])
    except InvalidTag: _fail("decryption_failed", "invalid secret or damaged envelope")
    try: manifest = json.loads(plain_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): _fail("decryption_failed", "invalid secret or damaged envelope")
    chunk_size = _validate_manifest(manifest); total = len(plain_manifest) + sum(item["size"] for item in manifest.get("attachments", [])); processed = len(plain_manifest)
    _progress(on_progress, "decrypting", processed, total); offset = manifest_end; opened = []
    for attachment_index, metadata in enumerate(manifest.get("attachments", [])):
        identifier = bytes.fromhex(metadata["id"]); prefix = bytes.fromhex(metadata["nonce_prefix"]); key = _hkdf(encryption_root, b"wipe.me/envelope/v1/attachment/" + identifier); chunks = []
        for chunk_index in range(metadata["chunks"]):
            if offset + 13 > len(envelope) or envelope[offset] != 1: _fail("invalid_envelope", "missing or reordered attachment frame")
            frame = envelope[offset:offset + 13]; stored_attachment, stored_chunk, length = struct.unpack(">III", frame[1:])
            if stored_attachment != attachment_index or stored_chunk != chunk_index or length > chunk_size: _fail("invalid_envelope", "invalid attachment frame")
            offset += 13; end = offset + length + 16
            if end > len(envelope): _fail("invalid_envelope", "truncated attachment frame")
            aad = MAGIC + frame + struct.pack(">I", metadata["chunks"]) + identifier
            try: plain = AESGCM(key).decrypt(prefix + struct.pack(">I", chunk_index), envelope[offset:end], aad)
            except InvalidTag: _fail("decryption_failed", "invalid secret or damaged envelope")
            chunks.append(plain); processed += len(plain); offset = end
            _progress(on_progress, "decrypting", processed, total, attachmentIndex=attachment_index, chunkIndex=chunk_index)
        data = b"".join(chunks)
        if len(data) != metadata["size"]: _fail("invalid_envelope", "attachment size does not match manifest")
        opened.append(DecryptedAttachment(metadata, data))
    if offset >= len(envelope) or envelope[offset] != 0 or offset + 1 != len(envelope): _fail("invalid_envelope", "missing end frame or trailing data")
    _progress(on_progress, "decrypting", total, total)
    return DecryptedEnvelope(manifest, tuple(opened), deletion_key, deletion_key_header(deletion_key))
