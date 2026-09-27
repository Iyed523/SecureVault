import hashlib
import hmac

import pytest
from fastapi import Request

from app.api.rate_limit import client_identifier
from app.security.rate_limit import SLIDING_WINDOW_SCRIPT, bucket_key


def test_hmac_keys_are_stable_private_and_domain_separated() -> None:
    secret = bytes.fromhex("cd" * 32)
    identifier = "sentinel@example.com"
    key = bucket_key(secret, "login-account", identifier)
    expected = hmac.new(
        secret, b"login-account\0" + identifier.encode(), hashlib.sha256
    ).hexdigest()
    assert key == f"securevault:ratelimit:v1:login-account:{expected}"
    assert key == bucket_key(secret, "login-account", identifier)
    assert key != bucket_key(secret, "login-account", "other@example.com")
    assert key != bucket_key(secret, "login-ip", identifier)
    assert key != bucket_key(bytes.fromhex("ef" * 32), "login-account", identifier)
    assert identifier not in key


@pytest.mark.parametrize("client", [None, ("192.0.2.18", 4567)])
def test_client_identifier_ignores_forwarded_headers(
    client: tuple[str, int] | None,
) -> None:
    request = Request(
        {
            "type": "http",
            "client": client,
            "headers": [
                (b"x-forwarded-for", b"198.51.100.2"),
                (b"x-real-ip", b"198.51.100.3"),
                (b"forwarded", b"for=198.51.100.4"),
            ],
        }
    )
    assert client_identifier(request) == ("unknown" if client is None else client[0])


def test_script_uses_redis_time_and_constant_arguments() -> None:
    assert 'redis.call("TIME")' in SLIDING_WINDOW_SCRIPT
    assert "KEYS[1]" in SLIDING_WINDOW_SCRIPT
    assert all(f"ARGV[{i}]" in SLIDING_WINDOW_SCRIPT for i in (1, 2, 3))
