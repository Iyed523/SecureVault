import asyncio
import json

import pytest
from fastapi import Request
from fastapi.exceptions import RequestValidationError

from app.api.errors import validation_error_handler


@pytest.mark.parametrize("field", ["password", "refresh_token", "content"])
@pytest.mark.parametrize(
    "location",
    [
        ("body", "password"),
        ("body", "users", 0, "password"),
        ("body", "password", "nested"),
    ],
)
def test_password_validation_message_is_redacted(
    location: tuple[str | int, ...],
    field: str,
) -> None:
    location = tuple(field if part == "password" else part for part in location)
    sentinel = "SENSITIVE-SENTINEL-é-🔐"
    error = RequestValidationError(
        [
            {
                "type": "value_error",
                "loc": location,
                "msg": f"Rejected secret: {sentinel}",
                "input": sentinel,
                "ctx": {"secret": sentinel},
                "body": {field: sentinel},
            }
        ],
        body={field: sentinel},
    )
    response = asyncio.run(validation_error_handler(Request({"type": "http"}), error))
    payload = json.loads(response.body)
    assert response.status_code == 422
    assert payload == {
        "detail": [
            {
                "type": "value_error",
                "loc": list(location),
                "msg": "Invalid secret content."
                if field == "content"
                else f"Invalid {field.replace('_', ' ')}.",
            }
        ]
    }
    assert sentinel not in json.dumps(payload, ensure_ascii=False)
    assert {"input", "ctx", "body"}.isdisjoint(payload)
    assert {"input", "ctx", "body"}.isdisjoint(payload["detail"][0])


def test_non_sensitive_validation_message_is_preserved() -> None:
    message = "Invalid email address."
    error = RequestValidationError(
        [{"type": "value_error", "loc": ("body", "email"), "msg": message}]
    )
    response = asyncio.run(validation_error_handler(Request({"type": "http"}), error))
    assert response.status_code == 422
    assert json.loads(response.body) == {
        "detail": [{"type": "value_error", "loc": ["body", "email"], "msg": message}]
    }
