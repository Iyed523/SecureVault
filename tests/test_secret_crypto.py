import json
from dataclasses import FrozenInstanceError, replace
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings
from app.security import secrets as crypto


def config(active: int = 1) -> Settings:
    return Settings(
        secrets_encryption_keys=json.dumps({"1": "ab" * 32, "2": "cd" * 32}),
        secrets_active_key_version=active,
    )


def test_roundtrip_and_aad_exact() -> None:
    owner, identifier = uuid4(), uuid4()
    plaintext = "  e\u0301 / é / 🔐\n\t "
    settings = config()
    first = crypto.encrypt_secret_content(plaintext, owner, identifier, settings)
    second = crypto.encrypt_secret_content(plaintext, owner, identifier, settings)
    assert len(first.nonce) == len(second.nonce) == 12
    assert first.nonce != second.nonce and first.ciphertext != second.ciphertext
    assert first.key_version == first.encryption_version == 1
    assert len(first.ciphertext) == len(plaintext.encode()) + 16
    assert (
        crypto.decrypt_secret_content(first, owner, identifier, settings) == plaintext
    )
    aad = (
        b"SecureVault:secret"
        + b"\x00\x01"
        + b"\x00\x00\x00\x01"
        + owner.bytes
        + identifier.bytes
    )
    assert (
        AESGCM(settings.get_secrets_encryption_key(1))
        .decrypt(first.nonce, first.ciphertext, aad)
        .decode()
        == plaintext
    )
    for representation in (repr(first), str(first)):
        assert plaintext not in representation
        assert repr(first.ciphertext) not in representation
        assert repr(first.nonce) not in representation
    with pytest.raises(FrozenInstanceError):
        first.key_version = 2


@pytest.mark.parametrize(
    "alteration",
    [
        "user",
        "id",
        "key_version",
        "missing_key",
        "key",
        "version",
        "nonce",
        "ciphertext",
        "nonce_length",
        "ciphertext_length",
    ],
)
def test_tampering_rejected(alteration: str) -> None:
    owner, identifier = uuid4(), uuid4()
    settings = config()
    encrypted = crypto.encrypt_secret_content(
        "SENSITIVE-CONTENT", owner, identifier, settings
    )
    if alteration == "user":
        owner = uuid4()
    elif alteration == "id":
        identifier = uuid4()
    elif alteration == "key":
        settings = Settings(secrets_encryption_keys=json.dumps({"1": "ef" * 32}))
    elif alteration in ("key_version", "missing_key"):
        encrypted = replace(
            encrypted, key_version=2 if alteration == "key_version" else 3
        )
    elif alteration == "version":
        encrypted = replace(encrypted, encryption_version=2)
    elif alteration == "nonce":
        encrypted = replace(
            encrypted, nonce=bytes([encrypted.nonce[0] ^ 1]) + encrypted.nonce[1:]
        )
    elif alteration == "ciphertext":
        encrypted = replace(
            encrypted,
            ciphertext=bytes([encrypted.ciphertext[0] ^ 1]) + encrypted.ciphertext[1:],
        )
    elif alteration == "nonce_length":
        encrypted = replace(encrypted, nonce=b"short")
    else:
        encrypted = replace(encrypted, ciphertext=b"short")
    with pytest.raises(crypto.SecretDecryptionError):
        crypto.decrypt_secret_content(encrypted, owner, identifier, settings)


def test_key_rotation_ready() -> None:
    owner, identifier = uuid4(), uuid4()
    assert config().get_secrets_encryption_key(
        1
    ) != config().get_secrets_encryption_key(2)
    old = crypto.encrypt_secret_content("old value", owner, identifier, config(1))
    assert (
        crypto.decrypt_secret_content(old, owner, identifier, config(2)) == "old value"
    )
    new = crypto.encrypt_secret_content("new value", owner, identifier, config(2))
    assert new.key_version == 2
    assert (
        crypto.decrypt_secret_content(new, owner, identifier, config(2)) == "new value"
    )


def test_key_version_is_authenticated_even_with_same_key_material() -> None:
    settings = config()
    owner, identifier = uuid4(), uuid4()
    value = crypto.encrypt_secret_content("value", owner, identifier, settings)
    altered_aad = (
        b"SecureVault:secret"
        + b"\x00\x01"
        + b"\x00\x00\x00\x02"
        + owner.bytes
        + identifier.bytes
    )
    # Isoler la liaison AAD sans construire un keyring aux clés dupliquées.
    with pytest.raises(InvalidTag):
        AESGCM(settings.get_secrets_encryption_key(1)).decrypt(
            value.nonce, value.ciphertext, altered_aad
        )


def test_surrogate_rejected_before_encrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object) -> None:
        pytest.fail("AESGCM must not receive an invalid plaintext")

    monkeypatch.setattr(crypto, "AESGCM", fail)
    with pytest.raises(ValueError, match="Invalid secret content"):
        crypto.encrypt_secret_content("\ud800", uuid4(), uuid4(), config())


def test_authenticated_non_utf8_plaintext_is_rejected() -> None:
    settings = config()
    owner, identifier = uuid4(), uuid4()
    encrypted = crypto.encrypt_secret_content("x", owner, identifier, settings)
    aad = (
        b"SecureVault:secret"
        + b"\x00\x01"
        + b"\x00\x00\x00\x01"
        + owner.bytes
        + identifier.bytes
    )
    # Nouveau nonce pour ce cas artificiel, aucune réutilisation de nonce/clé.
    nonce = crypto.secrets.token_bytes(12)
    ciphertext = AESGCM(settings.get_secrets_encryption_key(1)).encrypt(
        nonce, b"\xff", aad
    )
    with pytest.raises(crypto.SecretDecryptionError):
        crypto.decrypt_secret_content(
            replace(encrypted, nonce=nonce, ciphertext=ciphertext),
            owner,
            identifier,
            settings,
        )
