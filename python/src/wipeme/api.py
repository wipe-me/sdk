"""Synchronous client for the Wipe.me opaque-message HTTP API."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from .link import MESSAGE_ID_LENGTH, normalize_base58

MAX_MESSAGE_BYTES = 3 * 1024 * 1024
MAX_EXPIRY_SECONDS = 14 * 24 * 60 * 60
_CLIENT_RE = re.compile(r"^[a-z][a-z0-9._-]{0,31}$")
_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_DELETION_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


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
        if cipher_version != 1:
            raise ValueError("only cipher_version 1 is supported")

        payload, _ = self._request(
            "PUT",
            f"/api/messages/{quote(canonical_id)}",
            body=body,
            headers={
                "Content-Type": "application/octet-stream",
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

    def retrieve(self, message_id: str) -> RetrievedMessage:
        """Atomically claim and return an opaque encrypted envelope."""
        payload, headers = self._request("GET", f"/api/messages/{quote(_message_id(message_id))}")
        content_hash = headers.get("X-Wipe-Content-Hash")
        version = headers.get("X-Wipe-Cipher-Version")
        if not payload or not _HASH_RE.fullmatch(content_hash or "") or version != "1":
            raise APIError(None, "invalid_response", "API returned invalid encrypted-message metadata")
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

    # Names matching the OpenAPI operation IDs, alongside the concise idiomatic API.
    create_message = create
    retrieve_message = retrieve
    delete_message = delete
    get_health = health

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        include_client: bool = True,
    ) -> tuple[bytes, Any]:
        request_headers = dict(headers or {})
        request_headers["Accept"] = "application/octet-stream, application/json"
        if include_client:
            request_headers["X-Wipe-Client"] = self.client_id
        request = Request(self.base_url + path, data=body, headers=request_headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return response.read(), response.headers
        except HTTPError as error:
            payload = error.read()
            raise _api_error(error.code, payload, error.headers) from None
        except URLError as error:
            raise APIError(None, "transport_error", str(error.reason)) from error


def _message_id(value: str) -> str:
    return normalize_base58(value, MESSAGE_ID_LENGTH)


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
