"""Wipe.me protocol and API SDK."""

from .api import APIError, Client, CreateResult, RetrievedMessage
from .crypto import (
    AttachmentInput,
    DecryptedAttachment,
    DecryptedEnvelope,
    EncryptedEnvelope,
    ProtocolError,
    decrypt,
    deletion_key_header,
    derive_deletion_key,
    encrypt,
    generate_message_id,
    generate_secret,
    validate_crypto_chunk_bytes,
)
from .link import format_private_link, group_base58, normalize_base58, parse_private_link

__all__ = [
    "APIError",
    "Client",
    "CreateResult",
    "RetrievedMessage",
    "AttachmentInput",
    "DecryptedAttachment",
    "DecryptedEnvelope",
    "EncryptedEnvelope",
    "ProtocolError",
    "decrypt",
    "deletion_key_header",
    "derive_deletion_key",
    "encrypt",
    "generate_message_id",
    "generate_secret",
    "validate_crypto_chunk_bytes",
    "format_private_link",
    "group_base58",
    "normalize_base58",
    "parse_private_link",
]
__version__ = "0.3.0a1"
