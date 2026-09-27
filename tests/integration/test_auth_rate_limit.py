import logging
import re
import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx2 import ASGITransport, AsyncClient, Response
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.session import get_session
from app.infrastructure.redis import get_redis
from app.main import create_app
from app.models import RefreshToken, Session, User
from app.schemas.auth import LoginRequest
from app.security.rate_limit import Bucket, bucket_key
from app.services import login, registration
from tests.integration.test_login import PASSWORD, seed

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@dataclass
class Environment:
    app: FastAPI
    settings: Settings
    redis: Redis
    keys: set[str] = field(default_factory=set)

    def key(self, bucket: Bucket, identifier: str) -> str:
        key = bucket_key(self.settings.rate_limit_hmac_key(), bucket, identifier)
        self.keys.add(key)
        return key

    async def post(
        self,
        path: str,
        email: str = "",
        *,
        ip: str | None = "192.0.2.18",
        password: str = PASSWORD,
        headers: dict[str, str] | None = None,
        body: dict[str, str] | None = None,
    ) -> Response:
        if path == "/auth/login":
            self.key("login-ip", ip or "unknown")
            if "@" in email:
                self.key(
                    "login-account", LoginRequest(email=email, password=password).email
                )
        elif path == "/auth/register":
            self.key("register-ip", ip or "unknown")
        async with AsyncClient(
            transport=ASGITransport(app=self.app, client=(ip, 4321) if ip else None),
            base_url="http://test",
        ) as client:
            return await client.post(
                path,
                json=body or {"email": email, "password": password},
                headers=headers,
            )


@pytest.fixture
async def env(db_session: AsyncSession) -> AsyncIterator[Environment]:
    settings = Settings(
        rate_limit_secret=secrets.token_hex(32),
        login_rate_limit_per_ip=2,
        login_rate_limit_per_account=2,
        register_rate_limit_per_ip=2,
        rate_limit_window_seconds=60,
    )
    app = create_app(settings)

    async def override() -> AsyncIterator[AsyncSession]:
        yield db_session

    app.dependency_overrides[get_session] = override
    async with app.router.lifespan_context(app):
        environment = Environment(app, settings, app.state.redis)
        try:
            yield environment
        finally:
            if environment.keys:
                await environment.redis.delete(*environment.keys)


async def counts(db: AsyncSession) -> tuple[int, int, int]:
    async with db.begin():
        return tuple(
            [
                await db.scalar(select(func.count()).select_from(model))
                for model in (User, Session, RefreshToken)
            ]
        )


def forbidden(*args: object, **kwargs: object) -> None:
    pytest.fail("A refused request must not perform password work")


def assert_limited(response: Response) -> None:
    assert response.status_code == 429
    assert response.json() == {"detail": "Too many requests."}
    assert response.headers["retry-after"].isdigit()
    assert 1 <= int(response.headers["retry-after"]) <= 60


@pytest.mark.parametrize("outcome", ["success", "wrong", "missing", "inactive"])
async def test_login_ip_counts_all_attempts_and_stops_before_password_and_db(
    env: Environment,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    env.settings.login_rate_limit_per_account = 100
    user = await seed(db_session)
    email = f"{uuid4()}@example.com" if outcome == "missing" else user.email
    if outcome == "inactive":
        async with db_session.begin():
            await db_session.execute(
                update(User).where(User.id == user.id).values(is_active=False)
            )
    password = "wrong" if outcome == "wrong" else PASSWORD
    for _ in range(2):
        response = await env.post("/auth/login", email, password=password)
        assert response.status_code == (200 if outcome == "success" else 401)
    before = await counts(db_session)
    monkeypatch.setattr(login, "verify_password", forbidden)
    # IP refusal must not even create a bucket for this new account.
    other = f"{uuid4()}@example.com"
    assert_limited(await env.post("/auth/login", other))
    assert await env.redis.exists(env.key("login-account", other)) == 0
    assert await counts(db_session) == before


@pytest.mark.parametrize("exists", [False, True])
async def test_login_account_canonicalization_and_no_existence_oracle(
    env: Environment,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    exists: bool,
) -> None:
    env.settings.login_rate_limit_per_ip = 100
    email = (await seed(db_session)).email if exists else f"{uuid4()}@example.com"
    for ip, spelling in [("192.0.2.1", email.upper()), ("192.0.2.2", email)]:
        response = await env.post("/auth/login", spelling, ip=ip)
        assert response.status_code == (200 if exists else 401)
    before = await counts(db_session)
    monkeypatch.setattr(login, "verify_password", forbidden)
    assert_limited(await env.post("/auth/login", email.upper(), ip="192.0.2.3"))
    assert await counts(db_session) == before
    assert await env.redis.zcard(env.key("login-account", email)) == 2
    # IP acceptance remains consumed even when account is denied.
    assert await env.redis.zcard(env.key("login-ip", "192.0.2.3")) == 1


@pytest.mark.parametrize("duplicate", [False, True])
async def test_register_counts_success_and_duplicate_then_stops_before_hash_and_db(
    env: Environment,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    duplicate: bool,
) -> None:
    email = f"{uuid4()}@example.com"
    assert (await env.post("/auth/register", email)).status_code == 201
    second = email if duplicate else f"{uuid4()}@example.com"
    assert (await env.post("/auth/register", second)).status_code == (
        409 if duplicate else 201
    )
    before = await counts(db_session)
    monkeypatch.setattr(registration, "hash_password", forbidden)
    assert_limited(await env.post("/auth/register", f"{uuid4()}@example.com"))
    assert await counts(db_session) == before


@pytest.mark.parametrize("path", ["/auth/login", "/auth/register"])
@pytest.mark.parametrize("error", [RedisConnectionError, RedisTimeoutError])
async def test_redis_unavailable_is_private_fail_closed(
    env: Environment,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    path: str,
    error: type[Exception],
) -> None:
    class Unavailable:
        async def eval(self, *args: object) -> None:
            raise error("PRIVATE-REDIS-ERROR")

    env.app.dependency_overrides[get_redis] = lambda: Unavailable()
    monkeypatch.setattr(login, "verify_password", forbidden)
    monkeypatch.setattr(registration, "hash_password", forbidden)
    before = await counts(db_session)
    response = await env.post(path, f"{uuid4()}@example.com")
    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}
    assert "PRIVATE-REDIS-ERROR" not in response.text + caplog.text
    assert await counts(db_session) == before


async def test_programming_errors_are_not_swallowed(env: Environment) -> None:
    class Broken:
        async def eval(self, *args: object) -> None:
            raise TypeError("Programming error")

    env.app.dependency_overrides[get_redis] = lambda: Broken()
    with pytest.raises(TypeError, match="Programming error"):
        await env.post("/auth/login", f"{uuid4()}@example.com")


async def test_account_outage_preserves_real_ip_admission(
    env: Environment,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    user = await seed(db_session)
    # Existing real tokens make the confidentiality checks non-vacuous.
    tokens = await login.login_user(
        LoginRequest(email=user.email, password=PASSWORD), db_session, env.settings
    )
    before = await counts(db_session)
    ip = "198.51.100.79"
    ip_key = env.key("login-ip", ip)
    account_key = env.key("login-account", user.email)
    private_message = "PRIVATE-ACCOUNT-REDIS-ERROR"
    calls: list[str] = []
    admitted_members: list[str] = []

    class FailSecondBucket:
        async def eval(
            self, script: str, numkeys: int, key: str, *args: str | int
        ) -> list[int]:
            calls.append(key)
            assert numkeys == 1
            if len(calls) == 1:
                assert key == ip_key
                result = await env.redis.eval(script, numkeys, key, *args)
                assert result == [1, 0]
                admitted_members.extend(await env.redis.zrange(ip_key, 0, -1))
                assert len(admitted_members) == 1
                return result
            assert calls == [ip_key, account_key]
            assert await env.redis.zcard(ip_key) == 1
            raise RedisConnectionError(private_message)

    env.app.dependency_overrides[get_redis] = lambda: FailSecondBucket()
    monkeypatch.setattr(login, "verify_password", forbidden)
    monkeypatch.setattr(login, "create_access_token", forbidden)
    caplog.clear()
    caplog.set_level(logging.INFO)
    response = await env.post("/auth/login", user.email, ip=ip)
    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}
    assert calls == [ip_key, account_key]
    assert await env.redis.exists(ip_key) == 1
    assert await env.redis.zcard(ip_key) == 1
    assert await env.redis.zrange(ip_key, 0, -1) == admitted_members
    assert 0 < await env.redis.pttl(ip_key) <= 60000
    assert await env.redis.exists(account_key) == 0
    assert await counts(db_session) == before
    exposed = response.text + str(response.headers) + caplog.text
    for sensitive in (
        user.email,
        ip,
        ip_key,
        account_key,
        private_message,
        PASSWORD,
        tokens.access_token,
        tokens.refresh_token,
        env.settings.rate_limit_secret.get_secret_value(),
    ):
        assert sensitive not in exposed


async def test_real_redis_keys_and_members_do_not_contain_identifiers(
    env: Environment,
    caplog: pytest.LogCaptureFixture,
) -> None:
    email = f"sentinel-{uuid4()}@example.com"
    ip = "198.51.100.98"
    assert (await env.post("/auth/login", email, ip=ip)).status_code == 401
    for bucket, identifier in [("login-ip", ip), ("login-account", email)]:
        key = env.key(bucket, identifier)
        # Inspect only the exact keys belonging to this test; never scan all Redis.
        assert [item async for item in env.redis.scan_iter(match=key)] == [key]
        assert re.fullmatch(r"securevault:ratelimit:v1:[a-z-]+:[0-9a-f]{64}", key)
        members = await env.redis.zrange(key, 0, -1)
        assert len(members) == 1
        assert re.fullmatch(r"[0-9a-f]{32}", members[0])
        for value in [key, *members]:
            assert email not in value and ip not in value
    assert email not in caplog.text and ip not in caplog.text


@pytest.mark.parametrize("ip", ["192.0.2.18", None])
async def test_forwarded_headers_cannot_change_bucket(
    env: Environment,
    ip: str | None,
) -> None:
    env.settings.login_rate_limit_per_account = 100
    for index in range(3):
        response = await env.post(
            "/auth/login",
            f"{uuid4()}@example.com",
            ip=ip,
            headers={
                "X-Forwarded-For": f"198.51.100.{index}",
                "X-Real-IP": f"198.51.100.{index}",
                "Forwarded": f"for=198.51.100.{index}",
            },
        )
        if index < 2:
            assert response.status_code == 401
        else:
            assert_limited(response)


@pytest.mark.parametrize("path", ["/auth/login", "/auth/register"])
async def test_invalid_body_does_not_consume_quota(env: Environment, path: str) -> None:
    response = await env.post(path, "invalid-email")
    assert response.status_code == 422
    assert await env.redis.exists(*env.keys) == 0


async def test_refresh_replay_and_logout_remain_available_without_rate_limiter(
    env: Environment,
    db_session: AsyncSession,
) -> None:
    user = await seed(db_session)
    result = await env.post("/auth/login", user.email)
    assert result.status_code == 200
    token = result.json()["refresh_token"]

    def no_redis() -> None:
        pytest.fail("Refresh/logout must not request the rate limiter Redis dependency")

    env.app.dependency_overrides[get_redis] = no_redis
    refreshed = await env.post("/auth/refresh", body={"refresh_token": token})
    assert refreshed.status_code == 200
    replay = await env.post("/auth/refresh", body={"refresh_token": token})
    assert replay.status_code == 401
    assert replay.json() == {"detail": "Invalid refresh token."}
    replacement = refreshed.json()["refresh_token"]
    assert (
        await env.post("/auth/refresh", body={"refresh_token": replacement})
    ).status_code == 401
    for _ in range(2):
        assert (
            await env.post("/auth/logout", body={"refresh_token": token})
        ).status_code == 204
