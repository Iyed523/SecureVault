from typing import Annotated, Literal

from email_validator import EmailNotValidError, validate_email
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.security.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    validate_password,
)


def canonicalize_email(email: str) -> str:
    try:
        canonical = validate_email(
            email, check_deliverability=False
        ).normalized.casefold()
    except EmailNotValidError:
        raise ValueError("Invalid email address.") from None
    if len(canonical) > 254:
        raise ValueError("Invalid email address.")
    return canonical


class RegistrationRequest(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True, frozen=True)

    email: Annotated[str, Field(strict=True)]
    password: Annotated[
        SecretStr,
        Field(
            strict=True,
            min_length=MIN_PASSWORD_LENGTH,
            max_length=MAX_PASSWORD_LENGTH,
        ),
    ]

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return canonicalize_email(value)

    @field_validator("password")
    @classmethod
    def check_password(cls, value: SecretStr) -> SecretStr:
        validate_password(value.get_secret_value())
        return value


class LoginRequest(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True, frozen=True)

    email: Annotated[str, Field(strict=True)]
    password: Annotated[SecretStr, Field(strict=True, max_length=MAX_PASSWORD_LENGTH)]

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return canonicalize_email(value)


class RefreshTokenRequest(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True, frozen=True)

    refresh_token: Annotated[SecretStr, Field(strict=True, max_length=256)]


class TokenPairResponse(BaseModel):
    access_token: str = Field(repr=False)
    refresh_token: str = Field(repr=False)
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
