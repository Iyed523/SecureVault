import json
import re
from typing import Annotated, Literal, Self

from pydantic import (
    Field,
    PostgresDsn,
    RedisDsn,
    SecretStr,
    UrlConstraints,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

MAX_KEY_VERSION = 2**31 - 1


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate key version.")
        result[name] = value
    return result


def _parse_keyring(value: SecretStr) -> dict[int, bytes]:
    raw = json.loads(value.get_secret_value(), object_pairs_hook=_unique_object)
    if not isinstance(raw, dict) or not raw:
        raise ValueError("Invalid keyring.")
    keys: dict[int, bytes] = {}
    for version, key in raw.items():
        if re.fullmatch(r"[0-9]+", version) is None:
            raise ValueError("Invalid key version.")
        number = int(version)
        if not 1 <= number <= MAX_KEY_VERSION or number in keys:
            raise ValueError("Invalid key version.")
        if not isinstance(key, str) or re.fullmatch(r"[0-9a-fA-F]{64}", key) is None:
            raise ValueError("Invalid encryption key.")
        decoded = bytes.fromhex(key)
        if decoded in keys.values():
            raise ValueError("Encryption key material must be unique across versions.")
        keys[number] = decoded
    return keys


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", hide_input_in_errors=True
    )

    app_name: str = "SecureVault"
    app_env: str = "development"
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    database_url: Annotated[
        PostgresDsn, UrlConstraints(allowed_schemes=["postgresql+asyncpg"])
    ] = Field(repr=False)
    redis_url: RedisDsn = Field(repr=False)
    jwt_secret: SecretStr = Field(repr=False)
    secrets_encryption_keys: SecretStr = Field(repr=False)
    secrets_active_key_version: int = Field(default=1, ge=1, le=MAX_KEY_VERSION)
    access_token_ttl_minutes: int = Field(default=15, gt=0)
    session_ttl_days: int = Field(default=30, gt=0)
    jwt_issuer: str = Field(default="securevault", min_length=1)
    jwt_audience: str = Field(default="securevault-api", min_length=1)

    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, value: SecretStr) -> SecretStr:
        if re.fullmatch(r"[0-9a-fA-F]{64}", value.get_secret_value()) is None:
            raise ValueError(
                "JWT_SECRET must contain exactly 64 hexadecimal characters."
            )
        return value

    def jwt_signing_key(self) -> bytes:
        return bytes.fromhex(self.jwt_secret.get_secret_value())

    @field_validator("secrets_encryption_keys")
    @classmethod
    def validate_encryption_keys(cls, value: SecretStr) -> SecretStr:
        try:
            _parse_keyring(value)
        except (ValueError, TypeError):
            raise ValueError("Invalid secrets encryption keyring.") from None
        return value

    @field_validator("secrets_active_key_version", mode="before")
    @classmethod
    def reject_boolean_key_version(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("Invalid active key version.")
        return value

    @model_validator(mode="after")
    def validate_active_key(self) -> Self:
        if self.secrets_active_key_version not in _parse_keyring(
            self.secrets_encryption_keys
        ):
            raise ValueError("Active secrets encryption key is unavailable.")
        return self

    def get_secrets_encryption_key(self, version: int) -> bytes:
        return _parse_keyring(self.secrets_encryption_keys)[version]

    def get_active_secrets_encryption_key(self) -> tuple[int, bytes]:
        version = self.secrets_active_key_version
        return version, self.get_secrets_encryption_key(version)
