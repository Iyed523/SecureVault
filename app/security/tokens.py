from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt

from app.core.config import Settings

ALGORITHM = "HS256"
REQUIRED_CLAIMS = ("sub", "sid", "jti", "type", "iss", "aud", "iat", "nbf", "exp")


class InvalidAccessToken(Exception):
    """Access token refusé, sans détail public."""


@dataclass(frozen=True)
class AccessTokenClaims:
    user_id: UUID
    session_id: UUID
    jti: UUID


def create_access_token(user_id: UUID, session_id: UUID, settings: Settings) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": str(user_id),
            "sid": str(session_id),
            "jti": str(uuid4()),
            "type": "access",
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=settings.access_token_ttl_minutes),
        },
        settings.jwt_signing_key(),
        algorithm=ALGORITHM,
    )


def decode_access_token(token: str, settings: Settings) -> AccessTokenClaims:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_signing_key(),
            algorithms=[ALGORITHM],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": list(REQUIRED_CLAIMS), "strict_aud": True},
        )
        if payload["type"] != "access":
            raise InvalidAccessToken()
        if any(type(payload[name]) is not int for name in ("iat", "nbf", "exp")):
            raise InvalidAccessToken()
        if any(not isinstance(payload[name], str) for name in ("sub", "sid", "jti")):
            raise InvalidAccessToken()
        return AccessTokenClaims(
            user_id=UUID(payload["sub"]),
            session_id=UUID(payload["sid"]),
            jti=UUID(payload["jti"]),
        )
    except (jwt.InvalidTokenError, ValueError, TypeError, OverflowError):
        raise InvalidAccessToken() from None
