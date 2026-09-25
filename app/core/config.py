from typing import Annotated, Literal

from pydantic import Field, PostgresDsn, RedisDsn, UrlConstraints
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
