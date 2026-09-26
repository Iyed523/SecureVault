from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.secret import SecretCreateRequest, SecretResponse


@pytest.mark.parametrize(
    "content",
    ["x", "x" * 65536, "é" * 32768, "🔐" * 16384, "  e\u0301 \n"],
    ids=["one-byte", "max-ascii", "max-two-byte", "max-four-byte", "preserved"],
)
def test_content_preserved_and_utf8_size(content: str) -> None:
    request = SecretCreateRequest(title="  Titre é  ", content=content)
    assert request.title == "  Titre é  "
    assert request.content.get_secret_value() == content


@pytest.mark.parametrize(
    "content",
    ["", "x" * 65537, "é" * 32769, "🔐" * 16385, "\ud800", 123],
    ids=[
        "empty",
        "oversize-ascii",
        "oversize-two-byte",
        "oversize-four-byte",
        "surrogate",
        "integer",
    ],
)
def test_invalid_content(content: object) -> None:
    with pytest.raises(ValidationError):
        SecretCreateRequest(title="title", content=content)


@pytest.mark.parametrize("title", ["x", "x" * 200, "  e\u0301  "])
def test_title_preserved(title: str) -> None:
    assert SecretCreateRequest(title=title, content="content").title == title


@pytest.mark.parametrize("title", ["", "x" * 201, " \t\n", "\u2003", "\ud800", 123])
def test_invalid_title(title: object) -> None:
    with pytest.raises(ValidationError):
        SecretCreateRequest(title=title, content="content")


@pytest.mark.parametrize("title", ["\x00title", "a\x00b", "title\x00"])
def test_nul_in_title_rejected(title: str) -> None:
    with pytest.raises(ValidationError, match="Invalid secret title"):
        SecretCreateRequest(title=title, content="content")


def test_representations_and_response_fields() -> None:
    content = "CONTENT-SENTINEL-🔐"
    request = SecretCreateRequest(title="public", content=content)
    now = datetime.now(UTC)
    response = SecretResponse(
        id=uuid4(), title="public", content=content, created_at=now, updated_at=now
    )
    for value in (request, response):
        assert content not in repr(value) and content not in str(value)
    assert response.model_dump()["content"] == content
    assert set(response.model_dump()) == {
        "id",
        "title",
        "content",
        "created_at",
        "updated_at",
    }
    with pytest.raises(ValidationError):
        SecretCreateRequest(title="public", content=content, user_id=uuid4())
