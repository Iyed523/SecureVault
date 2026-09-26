from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.security.secrets import encode_secret_content


class SecretCreateRequest(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True, frozen=True, extra="forbid")

    title: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    content: Annotated[SecretStr, Field(strict=True)]

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str) -> str:
        if value.isspace() or "\x00" in value:
            raise ValueError("Invalid secret title.")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("Invalid secret title.") from None
        return value

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: SecretStr) -> SecretStr:
        encode_secret_content(value.get_secret_value())
        return value


class SecretResponse(BaseModel):
    id: UUID
    title: str
    content: str = Field(repr=False)
    created_at: datetime
    updated_at: datetime
