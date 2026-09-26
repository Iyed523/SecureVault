import hashlib
import re

import pytest

from app.schemas.auth import RefreshTokenRequest, TokenPairResponse
from app.security.refresh_tokens import generate_refresh_token, hash_refresh_token


def test_generation_and_hashing() -> None:
    tokens = [generate_refresh_token() for _ in range(3)]
    assert len(set(tokens)) == 3
    digests = []
    for token in tokens:
        assert len(token) == 64
        assert re.fullmatch(r"[0-9a-f]{64}", token)
        digest = hash_refresh_token(token)
        assert digest == hash_refresh_token(token)
        assert digest == hashlib.sha256(token.encode("utf-8")).digest()
        assert isinstance(digest, bytes) and len(digest) == 32
        digests.append(digest)
    assert len(set(digests)) == 3


@pytest.mark.parametrize("raw", ["ABC", " abc ", "", "é", "not-a-token"])
def test_no_normalization(raw: str) -> None:
    request = RefreshTokenRequest(refresh_token=raw)
    assert request.refresh_token.get_secret_value() == raw
    assert hash_refresh_token(raw) == hashlib.sha256(raw.encode("utf-8")).digest()
    assert hash_refresh_token("abc") != hash_refresh_token("ABC")
    assert hash_refresh_token("abc") != hash_refresh_token(" abc ")


def test_token_pair_repr_and_str_are_private() -> None:
    response = TokenPairResponse(
        access_token="ACCESS-SENTINEL", refresh_token="REFRESH-SENTINEL", expires_in=900
    )
    assert response.access_token not in repr(response)
    assert response.refresh_token not in repr(response)
    assert response.access_token not in str(response)
    assert response.refresh_token not in str(response)
    assert response.model_dump() == {
        "access_token": "ACCESS-SENTINEL",
        "refresh_token": "REFRESH-SENTINEL",
        "token_type": "bearer",
        "expires_in": 900,
    }
    assert "REFRESH-SENTINEL" not in repr(
        RefreshTokenRequest(refresh_token="REFRESH-SENTINEL")
    )
    assert "REFRESH-SENTINEL" not in str(
        RefreshTokenRequest(refresh_token="REFRESH-SENTINEL")
    )
