from datetime import datetime
from typing import Annotated, Self
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from app.security.secrets import encode_secret_content


def validate_title(value: str) -> str:
    if value.isspace() or "\x00" in value:
        raise ValueError("Invalid secret title.")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Invalid secret title.") from None
    return value


def validate_content(value: SecretStr) -> SecretStr:
    encode_secret_content(value.get_secret_value())
    return value


SecretTitle = Annotated[
    str,
    Field(strict=True, min_length=1, max_length=200),
    AfterValidator(validate_title),
]
SecretContent = Annotated[
    SecretStr, Field(strict=True), AfterValidator(validate_content)
]


class SecretCreateRequest(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True, frozen=True, extra="forbid")

    title: SecretTitle
    content: SecretContent


class SecretUpdateRequest(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True, frozen=True, extra="forbid")

    title: SecretTitle | None = None
    content: SecretContent | None = None

    @field_validator("title", "content", mode="before")
    @classmethod
    def reject_null(cls, value: object) -> object:
        if value is None:
            raise ValueError("Null is not allowed.")
        return value

    @model_validator(mode="after")
    def require_change(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("At least one field is required.")
        return self


class SecretListQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    limit: int = Field(default=20, ge=1, le=100)
    # OFFSET PostgreSQL est un bigint, pas un entier Python arbitraire.
    offset: int = Field(default=0, ge=0, le=2**63 - 1)
    q: SecretTitle | None = None


class SecretSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    created_at: datetime
    updated_at: datetime


class SecretListResponse(BaseModel):
    items: list[SecretSummary]
    limit: int
    offset: int
    has_more: bool


class SecretResponse(BaseModel):
    id: UUID
    title: str
    content: str = Field(repr=False)
    created_at: datetime
    updated_at: datetime
