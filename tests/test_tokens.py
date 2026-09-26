from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest

from app.core.config import Settings
from app.security.tokens import (
    InvalidAccessToken,
    create_access_token,
    decode_access_token,
)


@pytest.fixture
def token_settings() -> Settings:
    return Settings()


def payload(settings: Settings) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "sub": str(uuid4()),
        "sid": str(uuid4()),
        "jti": str(uuid4()),
        "type": "access",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=15),
    }


def test_access_token_roundtrip(token_settings: Settings) -> None:
    user_id, session_id = uuid4(), uuid4()
    first = create_access_token(user_id, session_id, token_settings)
    second = create_access_token(user_id, session_id, token_settings)
    claims = decode_access_token(first, token_settings)
    assert claims.user_id == user_id and claims.session_id == session_id
    assert claims.jti.version == 4
    assert claims.jti != decode_access_token(second, token_settings).jti
    decoded = jwt.decode(
        first,
        token_settings.jwt_signing_key(),
        algorithms=["HS256"],
        audience="securevault-api",
        issuer="securevault",
    )
    assert set(decoded) == {
        "sub",
        "sid",
        "jti",
        "type",
        "iss",
        "aud",
        "iat",
        "nbf",
        "exp",
    }
    assert decoded["exp"] - decoded["iat"] == 900
    assert decoded["nbf"] == decoded["iat"]
    assert decoded["type"] == "access"
    assert jwt.get_unverified_header(first)["alg"] == "HS256"
    assert all(isinstance(UUID(decoded[name]), UUID) for name in ("sub", "sid", "jti"))


@pytest.mark.parametrize(
    "claim", ["sub", "sid", "jti", "type", "iss", "aud", "iat", "nbf", "exp"]
)
def test_missing_claim(token_settings: Settings, claim: str) -> None:
    data = payload(token_settings)
    del data[claim]
    token = jwt.encode(data, token_settings.jwt_signing_key(), algorithm="HS256")
    with pytest.raises(InvalidAccessToken):
        decode_access_token(token, token_settings)


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("iss", "other"),
        ("aud", "other"),
        ("aud", ["securevault-api"]),
        ("type", "refresh"),
        ("sub", "invalid"),
        ("sid", "invalid"),
        ("jti", "invalid"),
        ("sid", 123),
        ("iat", True),
        ("nbf", "0"),
        ("exp", []),
        ("iat", "abc"),
        ("nbf", "abc"),
        ("exp", "abc"),
        ("sub", 123),
        ("sid", []),
        ("jti", None),
        ("type", 42),
    ],
)
def test_invalid_claim(token_settings: Settings, claim: str, value: object) -> None:
    data = payload(token_settings)
    data[claim] = value
    token = jwt.encode(data, token_settings.jwt_signing_key(), algorithm="HS256")
    with pytest.raises(InvalidAccessToken):
        decode_access_token(token, token_settings)


@pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
def test_invalid_time(token_settings: Settings, claim: str) -> None:
    data = payload(token_settings)
    data[claim] = datetime.now(UTC) + timedelta(hours=-1 if claim == "exp" else 1)
    with pytest.raises(InvalidAccessToken):
        decode_access_token(
            jwt.encode(data, token_settings.jwt_signing_key(), algorithm="HS256"),
            token_settings,
        )


@pytest.mark.parametrize("algorithm", ["HS384", "none"])
def test_wrong_algorithm(token_settings: Settings, algorithm: str) -> None:
    token = jwt.encode(
        payload(token_settings),
        b"x" * 48 if algorithm != "none" else None,
        algorithm=algorithm,
    )
    with pytest.raises(InvalidAccessToken):
        decode_access_token(token, token_settings)


def test_wrong_signature_and_malformed(token_settings: Settings) -> None:
    wrong = jwt.encode(payload(token_settings), b"x" * 32, algorithm="HS256")
    for token in (wrong, "invalid.token", "", "a.b.c"):
        with pytest.raises(InvalidAccessToken):
            decode_access_token(token, token_settings)
