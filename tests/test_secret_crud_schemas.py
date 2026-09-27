import pytest
from pydantic import ValidationError

from app.repositories.secrets import escape_like
from app.schemas.secret import SecretListQuery, SecretUpdateRequest


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"title": None},
        {"content": None},
        {"title": ""},
        {"title": " "},
        {"title": "x" * 201},
        {"title": "a\x00b"},
        {"title": "\ud800"},
        {"title": 12},
        {"content": ""},
        {"content": 12},
        {"content": "\ud800"},
        {"title": "ok", "user_id": "forbidden"},
    ],
)
def test_invalid_patch(body: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SecretUpdateRequest(**body)


def test_patch_exact_values_presence_and_confidentiality() -> None:
    value = "PRIVATE-CONTENT-\u0301"
    request = SecretUpdateRequest(title="  e\u0301  ", content=value)
    assert request.title == "  e\u0301  "
    assert request.content is not None and request.content.get_secret_value() == value
    assert request.model_fields_set == {"title", "content"}
    assert value not in repr(request) and value not in str(request)
    with pytest.raises(ValidationError):
        request.title = "changed"
    assert SecretUpdateRequest(title="x").model_fields_set == {"title"}
    assert SecretUpdateRequest(content="x").model_fields_set == {"content"}


@pytest.mark.parametrize("size", [1, 65536, 65537])
def test_patch_utf8_byte_boundary(size: int) -> None:
    content = "é" * (size // 2) + "x" * (size % 2)
    if size <= 65536:
        request = SecretUpdateRequest(content=content)
        assert request.content is not None
        assert request.content.get_secret_value() == content
    else:
        with pytest.raises(ValidationError):
            SecretUpdateRequest(content=content)


@pytest.mark.parametrize(
    "query",
    [
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"offset": 2**63},
        {"q": ""},
        {"q": " "},
        {"q": "x" * 201},
        {"q": "\x00"},
        {"q": "\ud800"},
        {"user_id": "forbidden"},
    ],
)
def test_invalid_list_query(query: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SecretListQuery(**query)


def test_list_query_defaults_and_preserved_search() -> None:
    assert SecretListQuery().model_dump() == {"limit": 20, "offset": 0, "q": None}
    assert SecretListQuery(q=" e\u0301 ", offset=2**63 - 1).q == " e\u0301 "


@pytest.mark.parametrize(
    ("query", "escaped"),
    [
        ("%", "\\%"),
        ("_", "\\_"),
        ("\\", "\\\\"),
        ("a\\%_b", "a\\\\\\%\\_b"),
        ("title", "title"),
    ],
)
def test_like_literal_escape(query: str, escaped: str) -> None:
    assert escape_like(query) == escaped
