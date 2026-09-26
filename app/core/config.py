import re
from typing import Annotated, Literal

from pydantic import (
    Field,
    PostgresDsn,
    RedisDsn,
    SecretStr,
    UrlConstraints,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


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
