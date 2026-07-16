"""Canonical Wipe.me Base58BTC values and private links."""

from urllib.parse import urlsplit, urlunsplit

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MESSAGE_ID_LENGTH = 12
SECRET_LENGTH = 16


def normalize_base58(value: str, expected_length: int) -> str:
    canonical = value.replace("-", "").replace(" ", "")
    if len(canonical) != expected_length:
        raise ValueError(f"expected {expected_length} Base58 characters, got {len(canonical)}")
    invalid = next((character for character in canonical if character not in BASE58BTC_ALPHABET), None)
    if invalid is not None:
        raise ValueError(f"invalid Base58 character {invalid!r}")
    return canonical


def group_base58(value: str, size: int = 4) -> str:
    if size < 1:
        raise ValueError("group size must be positive")
    return "-".join(value[index:index + size] for index in range(0, len(value), size))


def parse_private_link(value: str) -> tuple[str, str]:
    parsed = urlsplit(value)
    segment = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    return normalize_base58(segment, MESSAGE_ID_LENGTH), normalize_base58(parsed.fragment, SECRET_LENGTH)


def format_private_link(site: str, message_id: str, secret: str) -> str:
    parsed = urlsplit(site)
    path = f"{parsed.path.rstrip('/')}/{group_base58(normalize_base58(message_id, MESSAGE_ID_LENGTH))}"
    fragment = group_base58(normalize_base58(secret, SECRET_LENGTH))
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, fragment))
