import secrets
from dataclasses import dataclass, field
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings

ENCRYPTION_VERSION = 1
MAX_CONTENT_BYTES = 65536
AAD_PREFIX = b"SecureVault:secret"


@dataclass(frozen=True)
class EncryptedSecret:
    ciphertext: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    key_version: int
    encryption_version: int


class SecretDecryptionError(Exception):
    """Contenu indéchiffrable, sans détail cryptographique public."""


def encode_secret_content(plaintext: str) -> bytes:
    try:
        encoded = plaintext.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Invalid secret content.") from None
    if not 1 <= len(encoded) <= MAX_CONTENT_BYTES:
        raise ValueError("Invalid secret content.")
    return encoded


def _aad(
    encryption_version: int, key_version: int, user_id: UUID, secret_id: UUID
) -> bytes:
    return (
        AAD_PREFIX
        + encryption_version.to_bytes(2, "big")
        + key_version.to_bytes(4, "big")
        + user_id.bytes
        + secret_id.bytes
    )


def encrypt_secret_content(
    plaintext: str, user_id: UUID, secret_id: UUID, settings: Settings
) -> EncryptedSecret:
    encoded = encode_secret_content(plaintext)
    key_version, key = settings.get_active_secrets_encryption_key()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(
        nonce, encoded, _aad(ENCRYPTION_VERSION, key_version, user_id, secret_id)
    )
    return EncryptedSecret(ciphertext, nonce, key_version, ENCRYPTION_VERSION)


def decrypt_secret_content(
    encrypted: EncryptedSecret, user_id: UUID, secret_id: UUID, settings: Settings
) -> str:
    if (
        encrypted.encryption_version != ENCRYPTION_VERSION
        or len(encrypted.nonce) != 12
        or not 17 <= len(encrypted.ciphertext) <= MAX_CONTENT_BYTES + 16
    ):
        raise SecretDecryptionError()
    try:
        key = settings.get_secrets_encryption_key(encrypted.key_version)
        aad = _aad(
            encrypted.encryption_version, encrypted.key_version, user_id, secret_id
        )
        return (
            AESGCM(key)
            .decrypt(encrypted.nonce, encrypted.ciphertext, aad)
            .decode("utf-8")
        )
    except (InvalidTag, KeyError, ValueError, OverflowError):
        raise SecretDecryptionError() from None
