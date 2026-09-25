import pytest
from argon2 import Type, extract_parameters
from pwdlib.hashers.argon2 import Argon2Hasher

from app.security import passwords


def test_argon2_hashes_and_verification() -> None:
    password = "  Une phrase secrète 🔐 avec espaces  "
    first = passwords.hash_password(password)
    second = passwords.hash_password(password)
    assert first != second
    assert first.split("$")[4] != second.split("$")[4]
    for encoded in (first, second):
        assert password not in encoded
        params = extract_parameters(encoded)
        assert params.type is Type.ID
        assert (params.memory_cost, params.time_cost, params.parallelism) == (
            65536,
            3,
            1,
        )
        assert passwords.verify_password(password, encoded)
        assert not passwords.verify_password("Un autre mot de passe", encoded)
        assert not passwords.verify_password(password.strip(), encoded)
        assert not passwords.password_needs_rehash(encoded)


def test_password_is_not_truncated_or_unicode_normalized() -> None:
    password = "é" + "x" * 126 + "!"
    encoded = passwords.hash_password(password)
    assert passwords.verify_password(password, encoded)
    assert not passwords.verify_password(password[:-1], encoded)
    assert not passwords.verify_password(password[:-1] + "?", encoded)
    composed = "une phrase avec é accent"
    encoded = passwords.hash_password(composed)
    assert not passwords.verify_password(composed.replace("é", "e\u0301"), encoded)


def test_rehash_detection() -> None:
    old = Argon2Hasher(memory_cost=65536, time_cost=2, parallelism=1).hash("x" * 15)
    assert passwords.password_needs_rehash(old)


@pytest.mark.parametrize("password", ["x" * 14, "x" * 129, "x" * 14 + "\ud800"])
def test_invalid_password_rejected_before_hashing(
    monkeypatch: pytest.MonkeyPatch, password: str
) -> None:
    def forbidden(*args: object, **kwargs: object) -> str:
        pytest.fail("Le hashing ne doit pas recevoir un mot de passe invalide")

    monkeypatch.setattr(passwords._password_hash, "hash", forbidden)
    with pytest.raises(ValueError):
        passwords.hash_password(password)


def test_unknown_hash_is_not_verified() -> None:
    assert not passwords.verify_password("x" * 15, "not-a-password-hash")
