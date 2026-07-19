"""Synchronous client for the Wipe.me opaque-message HTTP API."""

from __future__ import annotations

import hashlib
import io
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Union
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from .link import MESSAGE_ID_LENGTH, normalize_base58

MAX_MESSAGE_BYTES = 3 * 1024 * 1024
MAX_EXPIRY_SECONDS = 14 * 24 * 60 * 60
MAX_SPEED_TEST_BYTES = 1024 * 1024
MAX_PERFORMANCE_REPORT_BYTES = 8 * 1024
MAX_REPORTED_BYTES = 1024 * 1024 * 1024
MAX_REPORTED_DURATION_MS = 24 * 60 * 60 * 1000
MAX_REPORTED_BPS = 2**40
_CLIENT_RE = re.compile(r"^[a-z][a-z0-9._-]{0,31}$")
_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_DELETION_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
DEFAULT_PROGRESS_CHUNK_BYTES = 100 * 1024
ProgressCallback = Callable[[Mapping[str, Union[int, str]]], None]


def _progress(callback: ProgressCallback | None, phase: str, processed: int, total: int) -> None:
    if callback is None:
        return
    event = {"phase": phase, "processedBytes": processed, "totalBytes": total,
             "percent": 100 if total == 0 else min(100, processed * 100 // total)}
    try:
        callback(event)
    except Exception:
        pass


class APIError(Exception):
    """A structured API or transport failure.

    ``code`` is stable for program logic while ``message`` is intended for people.
    Older servers that omit a code are mapped to ``http_<status>``.
    """

    def __init__(
        self,
        status: int | None,
        code: str,
        message: str,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.retry_after = retry_after


@dataclass(frozen=True)
class CreateResult:
    id: str
    created: bool


@dataclass(frozen=True)
class RetrievedMessage:
    body: bytes
    content_hash: str
    cipher_version: int


@dataclass(frozen=True)
class SpeedTestResult:
    received_bytes: int
    elapsed_seconds: float
    bytes_per_second: int


@dataclass(frozen=True)
class DownloadTestResult(SpeedTestResult):
    data: bytes


@dataclass(frozen=True)
class PerformanceReportResult:
    accepted: bool
    id: str


class _ProgressBody(io.BytesIO):
    def __init__(self, body: bytes, callback: ProgressCallback | None, threshold: int) -> None:
        super().__init__(body)
        self._callback, self._total, self._threshold, self._last = callback, len(body), threshold, -1

    def read(self, size: int = -1) -> bytes:
        chunk = super().read(size)
        processed = self.tell()
        if chunk and (self._last < 0 or processed - self._last >= self._threshold or processed == self._total):
            _progress(self._callback, "uploading", processed, self._total)
            self._last = processed
        return chunk


class Client:
    """Wipe.me API client.

    The API only receives opaque encrypted envelope bytes. Never include a private-link
    fragment or encryption secret in ``base_url`` or any operation argument.
    """

    def __init__(
        self,
        base_url: str = "https://wipe.me",
        *,
        client_id: str = "sdk-python",
        timeout: float = 30.0,
    ) -> None:
        parsed_url = urlsplit(base_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
            raise ValueError("base_url must be HTTP(S) without credentials, query, or fragment")
        if not _CLIENT_RE.fullmatch(client_id):
            raise ValueError("client_id must match ^[a-z][a-z0-9._-]{0,31}$")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.timeout = timeout

    def create(
        self,
        message_id: str,
        body: bytes,
        *,
        deletion_key: str,
        expires_at: int,
        content_hash: str | None = None,
        cipher_version: int = 1,
        on_progress: ProgressCallback | None = None,
        progress_chunk_bytes: int = DEFAULT_PROGRESS_CHUNK_BYTES,
    ) -> CreateResult:
        """Store one opaque encrypted envelope.

        ``expires_at`` is Unix epoch milliseconds and may be at most 14 days away for
        anonymous/free API use.
        """
        canonical_id = _message_id(message_id)
        if not isinstance(body, bytes):
            raise TypeError("body must be bytes")
        if not body:
            raise ValueError("body must not be empty")
        if len(body) > MAX_MESSAGE_BYTES:
            raise ValueError(f"body exceeds the {MAX_MESSAGE_BYTES}-byte free-tier limit")
        if not _DELETION_KEY_RE.fullmatch(deletion_key):
            raise ValueError("deletion_key must be 43-character unpadded base64url")
        now_ms = int(time.time() * 1000)
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise TypeError("expires_at must be Unix epoch milliseconds as an integer")
        if expires_at <= now_ms or expires_at > now_ms + MAX_EXPIRY_SECONDS * 1000:
            raise ValueError("expires_at must be in the future and no more than 14 days away")
        digest = content_hash or hashlib.sha256(body).hexdigest()
        if not _HASH_RE.fullmatch(digest):
            raise ValueError("content_hash must be a lowercase hexadecimal SHA-256 digest")
        if digest != hashlib.sha256(body).hexdigest():
            raise ValueError("content_hash does not match body")
        if cipher_version != 1:
            raise ValueError("only cipher_version 1 is supported")
        if not isinstance(progress_chunk_bytes, int) or progress_chunk_bytes < 1:
            raise ValueError("progress_chunk_bytes must be positive")

        payload, _ = self._request(
            "PUT",
            f"/api/messages/{quote(canonical_id)}",
            body=_ProgressBody(body, on_progress, progress_chunk_bytes),
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(body)),
                "X-Wipe-Content-Hash": digest,
                "X-Wipe-Deletion-Key": deletion_key,
                "X-Wipe-Cipher-Version": "1",
                "X-Wipe-Expires-At": str(expires_at),
            },
        )
        result = _json_object(payload)
        returned_id = str(result["id"])
        if returned_id != canonical_id:
            raise APIError(None, "invalid_response", "API returned an unexpected message ID")
        return CreateResult(id=returned_id, created=bool(result["created"]))

    def retrieve(self, message_id: str, *, on_headers: Callable[[Mapping[str, Any]], None] | None = None,
                 on_progress: ProgressCallback | None = None,
                 progress_chunk_bytes: int = DEFAULT_PROGRESS_CHUNK_BYTES) -> RetrievedMessage:
        """Atomically claim and return an opaque encrypted envelope."""
        if not isinstance(progress_chunk_bytes, int) or progress_chunk_bytes < 1:
            raise ValueError("progress_chunk_bytes must be positive")
        def inspect_headers(headers: Any) -> None:
            content_hash = headers.get("X-Wipe-Content-Hash")
            version = headers.get("X-Wipe-Cipher-Version")
            if not _HASH_RE.fullmatch(content_hash or "") or version != "1":
                raise APIError(None, "invalid_response", "API returned invalid encrypted-message metadata")
            if on_headers is not None:
                length = headers.get("Content-Length")
                metadata = {"totalBytes": int(length) if length and length.isdigit() else None,
                            "contentHash": content_hash, "cipherVersion": 1}
                try:
                    on_headers(metadata)
                except Exception:
                    pass
        payload, headers = self._request("GET", f"/api/messages/{quote(_message_id(message_id))}",
                                         on_headers=inspect_headers, on_progress=on_progress,
                                         progress_chunk_bytes=progress_chunk_bytes)
        content_hash = headers.get("X-Wipe-Content-Hash")
        version = headers.get("X-Wipe-Cipher-Version")
        if not payload or not _HASH_RE.fullmatch(content_hash or "") or version != "1":
            raise APIError(None, "invalid_response", "API returned invalid encrypted-message metadata")
        if hashlib.sha256(payload).hexdigest() != content_hash:
            raise APIError(None, "content_hash_mismatch", "Encrypted message failed its integrity check")
        return RetrievedMessage(
            body=payload,
            content_hash=content_hash,
            cipher_version=1,
        )

    def delete(self, message_id: str, *, deletion_key: str) -> bool:
        """Delete a message using its derived deletion capability."""
        if not _DELETION_KEY_RE.fullmatch(deletion_key):
            raise ValueError("deletion_key must be 43-character unpadded base64url")
        payload, _ = self._request(
            "DELETE",
            f"/api/messages/{quote(_message_id(message_id))}",
            headers={"X-Wipe-Deletion-Key": deletion_key},
        )
        return bool(_json_object(payload)["deleted"])

    def health(self) -> Mapping[str, Any]:
        """Return the service health document."""
        payload, _ = self._request("GET", "/health", include_client=False)
        return _json_object(payload)

    def limits(self) -> Mapping[str, Any]:
        """Return the server-authoritative effective limits for this caller."""
        payload, _ = self._request("GET", "/api/limits", include_client=False)
        result = _json_object(payload)
        names = {"messageBytes", "maxExpirySeconds", "devices", "apiKeys", "messagesPerMinute",
                 "uploadBytesPerHour", "speedTestBytesPerRequest", "speedTestBytesPerHour"}
        limits = result.get("limits")
        if (set(result) != {"authenticated", "plan", "limits", "usage"}
                or not isinstance(result["authenticated"], bool) or not isinstance(result["plan"], str)
                or not isinstance(limits, dict) or set(limits) != names
                or any(not _integer(limits[name], 0, 2**63 - 1) for name in names)):
            raise APIError(None, "invalid_response", "API returned an invalid limits response")
        return result

    def test_upload_speed(self, sample: bytes, *, on_progress: ProgressCallback | None = None,
                          progress_chunk_bytes: int = DEFAULT_PROGRESS_CHUNK_BYTES) -> SpeedTestResult:
        """Upload and discard a bounded sample, returning a locally measured rate."""
        if not isinstance(sample, bytes):
            raise TypeError("sample must be bytes")
        _speed_test_size(len(sample))
        started = time.perf_counter()
        payload, _ = self._request("POST", "/api/network-test/upload",
            body=_ProgressBody(sample, on_progress, progress_chunk_bytes), include_client=False,
            headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(sample))})
        elapsed = max(time.perf_counter() - started, 1e-9)
        result = _json_object(payload)
        if result.get("receivedBytes") != len(sample):
            raise APIError(None, "invalid_response", "API returned an invalid upload-test response")
        return SpeedTestResult(len(sample), elapsed, round(len(sample) / elapsed))

    def test_download_speed(self, size: int, *, on_progress: ProgressCallback | None = None,
                            progress_chunk_bytes: int = DEFAULT_PROGRESS_CHUNK_BYTES) -> DownloadTestResult:
        """Download a bounded generated sample, returning a locally measured rate."""
        _speed_test_size(size)
        started = time.perf_counter()
        payload, headers = self._request("GET", f"/api/network-test/download?bytes={size}",
            include_client=False, on_progress=on_progress, progress_chunk_bytes=progress_chunk_bytes)
        elapsed = max(time.perf_counter() - started, 1e-9)
        if headers.get("Content-Length") != str(size) or headers.get("Cache-Control") != "no-store" or len(payload) != size:
            raise APIError(None, "invalid_response", "API returned invalid download-test metadata")
        return DownloadTestResult(len(payload), elapsed, round(len(payload) / elapsed), payload)

    def submit_performance_report(self, report: Mapping[str, Any]) -> PerformanceReportResult:
        """Submit one strictly bounded privacy-safe estimate-versus-actual report."""
        _validate_performance_report(report)
        body = json.dumps(report, separators=(",", ":"), ensure_ascii=True).encode()
        if len(body) > MAX_PERFORMANCE_REPORT_BYTES:
            raise ValueError("performance report exceeds 8 KiB")
        payload, _ = self._request("POST", "/api/performance-reports", body=body, include_client=False,
                                   headers={"Content-Type": "application/json", "Content-Length": str(len(body))})
        result = _json_object(payload)
        if result.get("accepted") is not True or not _UUID_RE.fullmatch(str(result.get("id", ""))):
            raise APIError(None, "invalid_response", "API returned an invalid performance-report response")
        return PerformanceReportResult(True, str(result["id"]))

    # Names matching the OpenAPI operation IDs, alongside the concise idiomatic API.
    create_message = create
    retrieve_message = retrieve
    delete_message = delete
    get_health = health
    get_limits = limits
    create_performance_report = submit_performance_report

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        headers: Mapping[str, str] | None = None,
        include_client: bool = True,
        on_progress: ProgressCallback | None = None,
        on_headers: Callable[[Any], None] | None = None,
        progress_chunk_bytes: int = DEFAULT_PROGRESS_CHUNK_BYTES,
    ) -> tuple[bytes, Any]:
        request_headers = dict(headers or {})
        request_headers["Accept"] = "application/octet-stream, application/json"
        if include_client:
            request_headers["X-Wipe-Client"] = self.client_id
        request = Request(self.base_url + path, data=body, headers=request_headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                if on_headers is not None:
                    on_headers(response.headers)
                total_header = response.headers.get("Content-Length")
                total = int(total_header) if total_header and total_header.isdigit() else None
                chunks, processed, last = [], 0, -1
                while True:
                    chunk = response.read(progress_chunk_bytes)
                    if not chunk:
                        break
                    chunks.append(chunk); processed += len(chunk)
                    if total is not None and (last < 0 or processed - last >= progress_chunk_bytes or processed == total):
                        _progress(on_progress, "downloading", processed, total); last = processed
                if total is not None and processed != total:
                    raise APIError(None, "invalid_response", "Encrypted-message length did not match Content-Length")
                if on_progress is not None and total is None:
                    _progress(on_progress, "downloading", processed, processed)
                return b"".join(chunks), response.headers
        except HTTPError as error:
            payload = error.read()
            raise _api_error(error.code, payload, error.headers) from None
        except URLError as error:
            raise APIError(None, "transport_error", str(error.reason)) from error


def _message_id(value: str) -> str:
    return normalize_base58(value, MESSAGE_ID_LENGTH)


def _speed_test_size(value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > MAX_SPEED_TEST_BYTES:
        raise ValueError(f"speed-test size must be between 1 and {MAX_SPEED_TEST_BYTES} bytes")


def _integer(value: Any, minimum: int, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def _object_keys(value: Any, allowed: set[str]) -> bool:
    return isinstance(value, Mapping) and set(value).issubset(allowed)


def _validate_performance_report(value: Mapping[str, Any]) -> None:
    root = {"schemaVersion", "flow", "result", "encryptedBytes", "plaintextBytes", "estimated", "actual",
            "completedBytes", "networkEstimate", "cryptoEstimate", "estimateModel", "client"}
    if not _object_keys(value, root) or value.get("schemaVersion") != 1 or value.get("flow") not in {"create", "open"}:
        raise ValueError("invalid performance report")
    create = value["flow"] == "create"
    results = {"success", "cancelled", "transport_error"} | (set() if create else {"integrity_error", "decryption_error"})
    if value.get("result") not in results or not _integer(value.get("encryptedBytes"), 1, MAX_REPORTED_BYTES):
        raise ValueError("invalid performance report")
    if "plaintextBytes" in value and not _integer(value["plaintextBytes"], 0, MAX_REPORTED_BYTES):
        raise ValueError("invalid performance report")
    _validate_timings(value.get("estimated"), create, True)
    _validate_timings(value.get("actual"), create, value["result"] == "success")
    _validate_estimate(value.get("networkEstimate"), "uploadBytesPerSecond" if create else "downloadBytesPerSecond")
    _validate_estimate(value.get("cryptoEstimate"), "encryptBytesPerSecond" if create else "decryptBytesPerSecond")
    completed_key = "upload" if create else "download"
    completed = value.get("completedBytes")
    if completed is not None and (not _object_keys(completed, {completed_key}) or completed_key not in completed
                                  or not _integer(completed[completed_key], 0, value["encryptedBytes"])):
        raise ValueError("invalid performance report")
    client = value.get("client")
    if (not _MODEL_RE.fullmatch(str(value.get("estimateModel", "")))
            or not _object_keys(client, {"kind", "version", "platform", "browserFamily"})
            or not _CLIENT_RE.fullmatch(str(client.get("kind", "")))
            or not _VERSION_RE.fullmatch(str(client.get("version", "")))
            or client.get("platform") not in {"mobile", "desktop", "server", "unknown"}
            or ("browserFamily" in client and client["browserFamily"] not in {"chrome", "firefox", "safari", "edge", "other", "unknown"})):
        raise ValueError("invalid performance report")


def _validate_timings(value: Any, create: bool, required: bool) -> None:
    phases = {"encryptMs", "uploadMs"} if create else {"downloadMs", "decryptMs"}
    if not _object_keys(value, phases | {"totalMs"}) or not _integer(value.get("totalMs"), 0, MAX_REPORTED_DURATION_MS):
        raise ValueError("invalid performance report")
    for key in phases:
        if required and key not in value:
            raise ValueError("invalid performance report")
        if key in value and not _integer(value[key], 0, MAX_REPORTED_DURATION_MS):
            raise ValueError("invalid performance report")


def _validate_estimate(value: Any, rate_key: str) -> None:
    if value is None:
        return
    if (not _object_keys(value, {rate_key, "sampleAgeMs"}) or rate_key not in value or "sampleAgeMs" not in value
            or not _integer(value[rate_key], 1, MAX_REPORTED_BPS)
            or not _integer(value["sampleAgeMs"], 0, 365 * 24 * 60 * 60 * 1000)):
        raise ValueError("invalid performance report")


def _json_object(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise APIError(None, "invalid_response", "API returned invalid JSON") from error
    if not isinstance(value, dict):
        raise APIError(None, "invalid_response", "API returned a non-object JSON response")
    return value


def _api_error(status: int, payload: bytes, headers: Any) -> APIError:
    try:
        value = _json_object(payload)
    except APIError:
        value = {}
    message = str(value.get("error") or value.get("message") or f"HTTP {status}")
    code = str(value.get("code") or f"http_{status}")
    retry_value = value.get("retryAfter")
    if retry_value is None and headers is not None:
        retry_value = headers.get("Retry-After")
    try:
        retry_after = float(retry_value) if retry_value is not None else None
    except (TypeError, ValueError):
        retry_after = None
    return APIError(status, code, message, retry_after)
