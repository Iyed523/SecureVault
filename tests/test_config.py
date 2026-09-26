import json
from pathlib import Path

import pytest
from dotenv import dotenv_values
from pydantic import ValidationError

from app.core.config import Settings


@pytest.fixture
def infrastructure_config(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    for name in ("DATABASE_URL", "REDIS_URL", "database_url", "redis_url"):
        monkeypatch.delenv(name, raising=False)
    example = dotenv_values(Path(__file__).resolve().parents[1] / ".env.example")
    return {name.lower(): str(example[name]) for name in ("DATABASE_URL", "REDIS_URL")}


@pytest.mark.parametrize("missing", ["database_url", "redis_url"])
def test_infrastructure_url_is_required(
    infrastructure_config: dict[str, str], missing: str
) -> None:
    values = infrastructure_config.copy()
    values.pop(missing)
    with pytest.raises(ValidationError) as caught:
        Settings(_env_file=None, **values)
    message = str(caught.value)
    assert missing in message
    assert "Field required" in message
    for value in infrastructure_config.values():
        assert value not in message
    assert "local_dev_only" not in message


def test_complete_configuration_is_valid(infrastructure_config: dict[str, str]) -> None:
    settings = Settings(_env_file=None, **infrastructure_config)
    assert str(settings.database_url) == infrastructure_config["database_url"]
    assert str(settings.redis_url) == infrastructure_config["redis_url"]
    for value in infrastructure_config.values():
        assert value not in repr(settings)


def test_jwt_secret_required(
    monkeypatch: pytest.MonkeyPatch, infrastructure_config: dict[str, str]
) -> None:
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("jwt_secret", raising=False)
    with pytest.raises(ValidationError, match="Field required"):
        Settings(_env_file=None, **infrastructure_config)


@pytest.mark.parametrize("secret", ["", "g" * 64, "a" * 63, "a" * 65, "ab " * 21 + "a"])
def test_jwt_secret_format(infrastructure_config: dict[str, str], secret: str) -> None:
    with pytest.raises(ValidationError) as caught:
        Settings(_env_file=None, jwt_secret=secret, **infrastructure_config)
    if secret:
        assert secret not in str(caught.value)


def test_jwt_secret_hidden_and_decoded(infrastructure_config: dict[str, str]) -> None:
    secret = "A1" * 32
    settings = Settings(_env_file=None, jwt_secret=secret, **infrastructure_config)
    assert settings.jwt_signing_key() == bytes.fromhex(secret)
    assert secret not in repr(settings)
    assert secret not in settings.model_dump_json()
    assert settings.access_token_ttl_minutes == 15
    assert settings.session_ttl_days == 30


def test_keyring_required(
    monkeypatch: pytest.MonkeyPatch, infrastructure_config: dict[str, str]
) -> None:
    monkeypatch.delenv("SECRETS_ENCRYPTION_KEYS", raising=False)
    with pytest.raises(ValidationError, match="Field required"):
        Settings(_env_file=None, **infrastructure_config)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "invalid-json",
        "{}",
        "[]",
        "null",
        json.dumps({"0": "ab" * 32}),
        json.dumps({"-1": "ab" * 32}),
        json.dumps({"1.5": "ab" * 32}),
        json.dumps({"x": "ab" * 32}),
        json.dumps({"2147483648": "ab" * 32}),
        json.dumps({"1": "ab" * 31}),
        json.dumps({"1": "ab" * 33}),
        json.dumps({"1": "zz" * 32}),
        json.dumps({"1": "ab " * 21 + "a"}),
        json.dumps({"1": 123}),
        json.dumps({"1": {"nested": "KEY-SENTINEL"}}),
        json.dumps({"1": "ab" * 32, "01": "cd" * 32}),
        '{"1":"' + "ab" * 32 + '","1":"' + "cd" * 32 + '"}',
    ],
)
def test_keyring_rejects_invalid_and_hides_input(
    infrastructure_config: dict[str, str], raw: str
) -> None:
    with pytest.raises(ValidationError) as caught:
        Settings(_env_file=None, secrets_encryption_keys=raw, **infrastructure_config)
    message = str(caught.value)
    assert "Invalid secrets encryption keyring." in message
    assert "ab" * 31 not in message and "cd" * 32 not in message
    assert "KEY-SENTINEL" not in message
    assert "input_value" not in message


@pytest.mark.parametrize("active", [0, -1, 2, 2147483648, True, "x", 1.5])
def test_active_key_must_be_valid_and_present(
    infrastructure_config: dict[str, str], active: object
) -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None, secrets_active_key_version=active, **infrastructure_config
        )


def test_keyring_valid_hidden_and_versioned(
    infrastructure_config: dict[str, str],
) -> None:
    raw = json.dumps({"1": "ab" * 32, "2": "cd" * 32})
    settings = Settings(
        _env_file=None,
        secrets_encryption_keys=raw,
        secrets_active_key_version=2,
        **infrastructure_config,
    )
    assert settings.get_secrets_encryption_key(1) == bytes.fromhex("ab" * 32)
    assert settings.get_active_secrets_encryption_key() == (2, bytes.fromhex("cd" * 32))
    for representation in (repr(settings), str(settings), settings.model_dump_json()):
        assert raw not in representation
        assert "ab" * 32 not in representation and "cd" * 32 not in representation
    with pytest.raises(KeyError):
        settings.get_secrets_encryption_key(3)


@pytest.mark.parametrize("mixed_case", [False, True], ids=["identical", "hex-case"])
def test_duplicate_key_material_rejected_without_leaking(
    infrastructure_config: dict[str, str], mixed_case: bool
) -> None:
    first = "a1" * 32
    second = first.upper() if mixed_case else first
    assert bytes.fromhex(first) == bytes.fromhex(second)
    if mixed_case:
        assert first != second
    raw = json.dumps({"1": first, "2": second})
    with pytest.raises(ValidationError) as caught:
        Settings(_env_file=None, secrets_encryption_keys=raw, **infrastructure_config)
    for representation in (str(caught.value), repr(caught.value)):
        assert "Invalid secrets encryption keyring." in representation
        for sensitive in (first, second, raw, repr(bytes.fromhex(first))):
            assert sensitive not in representation


def test_max_key_version(infrastructure_config: dict[str, str]) -> None:
    settings = Settings(
        _env_file=None,
        secrets_encryption_keys=json.dumps({"2147483647": "ab" * 32}),
        secrets_active_key_version=2147483647,
        **infrastructure_config,
    )
    assert settings.get_active_secrets_encryption_key() == (
        2147483647,
        bytes.fromhex("ab" * 32),
    )
