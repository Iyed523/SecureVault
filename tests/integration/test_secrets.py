import base64
import json
import logging
from collections.abc import AsyncIterator
from uuid import UUID, uuid4

import pytest
from httpx2 import ASGITransport, AsyncClient
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.session import get_session
from app.main import create_app
from app.models import Secret, User
from app.repositories.secrets import SecretRepository
from app.schemas.auth import LoginRequest, TokenPairResponse
from app.schemas.secret import SecretCreateRequest
from app.schemas.user import PublicUser
from app.security import secrets as crypto
from app.services import secrets as service
from app.services.login import login_user
from tests.integration.test_login import PASSWORD, seed

pytestmark = [pytest.mark.integration, pytest.mark.anyio]
CONTENT = "  SECRET-CONTENT-é-e\u0301-🔐\n "
TITLE = "  Public metadata é  "


@pytest.fixture
def settings() -> Settings:
    return Settings(
        secrets_encryption_keys=json.dumps({"1": "ab" * 32, "2": "cd" * 32}),
        secrets_active_key_version=2,
    )


@pytest.fixture
async def client(
    db_session: AsyncSession, settings: Settings
) -> AsyncIterator[AsyncClient]:
    async def override() -> AsyncIterator[AsyncSession]:
        try:
            yield db_session
        finally:
            await db_session.rollback()

    app = create_app(settings)
    app.dependency_overrides[get_session] = override
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield client


@pytest.fixture
async def accounts(
    db_session: AsyncSession, settings: Settings
) -> tuple[tuple[PublicUser, TokenPairResponse], tuple[PublicUser, TokenPairResponse]]:
    first = await seed(db_session)
    pair1 = await login_user(
        LoginRequest(email=first.email, password=PASSWORD), db_session, settings
    )
    second = await seed(db_session)
    pair2 = await login_user(
        LoginRequest(email=second.email, password=PASSWORD), db_session, settings
    )
    return (first, pair1), (second, pair2)


def bearer(pair: TokenPairResponse) -> dict[str, str]:
    return {"Authorization": f"Bearer {pair.access_token}"}


async def create(
    client: AsyncClient, pair: TokenPairResponse, content: str = CONTENT
) -> dict[str, object]:
    response = await client.post(
        "/secrets", json={"title": TITLE, "content": content}, headers=bearer(pair)
    )
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"id", "title", "content", "created_at", "updated_at"}
    assert body["content"] == content and body["title"] == TITLE
    return body


def encrypted(row: Secret) -> crypto.EncryptedSecret:
    return crypto.EncryptedSecret(
        row.ciphertext, row.nonce, row.key_version, row.encryption_version
    )


def assert_private_logs(
    caplog: pytest.LogCaptureFixture,
    row: Secret,
    pair: TokenPairResponse,
    settings: Settings,
    password_hash: str,
) -> None:
    messages = "\n".join(
        record.getMessage()
        for phase in ("setup", "call", "teardown")
        for record in caplog.get_records(phase)
    )
    for value in (
        CONTENT,
        row.ciphertext.hex(),
        base64.b64encode(row.ciphertext).decode(),
        row.nonce.hex(),
        settings.secrets_encryption_keys.get_secret_value(),
        "ab" * 32,
        "cd" * 32,
        pair.access_token,
        pair.refresh_token,
        PASSWORD,
        password_hash,
    ):
        assert value not in messages


async def test_create_read_persistence_and_crypto_outside_transaction(
    client: AsyncClient,
    db_session: AsyncSession,
    settings: Settings,
    accounts: tuple,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caplog.set_level(logging.INFO)
    user, pair = accounts[0]
    real_encrypt, real_decrypt = (
        service.encrypt_secret_content,
        service.decrypt_secret_content,
    )
    operations = []

    def encrypt(
        plaintext: str, user_id: UUID, secret_id: UUID, settings: Settings
    ) -> crypto.EncryptedSecret:
        assert db_session.in_transaction() is False
        assert isinstance(secret_id, UUID) and secret_id.version == 4
        operations.append("encrypt")
        return real_encrypt(plaintext, user_id, secret_id, settings)

    def decrypt(
        value: crypto.EncryptedSecret,
        user_id: UUID,
        secret_id: UUID,
        settings: Settings,
    ) -> str:
        assert db_session.in_transaction() is False
        operations.append("decrypt")
        return real_decrypt(value, user_id, secret_id, settings)

    monkeypatch.setattr(service, "encrypt_secret_content", encrypt)
    monkeypatch.setattr(service, "decrypt_secret_content", decrypt)
    body = await create(client, pair)
    response = await client.get(f"/secrets/{body['id']}", headers=bearer(pair))
    assert response.status_code == 200 and response.json() == body
    assert operations == ["encrypt", "decrypt"]
    async with db_session.begin():
        row = await SecretRepository(db_session).get_owned_by_id(
            UUID(body["id"]), user.id
        )
        assert row is not None
        assert row.user_id == user.id and row.title == TITLE
        assert (
            len(row.nonce) == 12
            and row.key_version == 2
            and row.encryption_version == 1
        )
        assert isinstance(row.ciphertext, bytes) and row.ciphertext != CONTENT.encode()
        assert (
            crypto.decrypt_secret_content(encrypted(row), user.id, row.id, settings)
            == CONTENT
        )
        assert "content" not in Secret.__table__.columns and not hasattr(row, "content")
        for column in Secret.__table__.columns:
            assert getattr(row, column.name) not in (CONTENT, CONTENT.encode())
        stored_user = await db_session.get(User, user.id)
        assert stored_user is not None
        assert_private_logs(caplog, row, pair, settings, stored_user.password_hash)


async def test_idor_unknown_and_no_decrypt(
    client: AsyncClient,
    db_session: AsyncSession,
    accounts: tuple,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = await create(client, accounts[0][1])
    absent = uuid4()
    async with db_session.begin():
        assert (
            await db_session.scalar(select(Secret.id).where(Secret.id == absent))
            is None
        )

    def fail(*args: object) -> str:
        pytest.fail("Foreign or absent secret must not be decrypted")

    monkeypatch.setattr(service, "decrypt_secret_content", fail)
    for identifier in (body["id"], absent):
        result = await client.get(
            f"/secrets/{identifier}", headers=bearer(accounts[1][1])
        )
        assert result.status_code == 404 and result.json() == {
            "detail": "Secret not found."
        }


async def test_repository_owner_filter_is_in_sql(
    client: AsyncClient, db_session: AsyncSession, accounts: tuple
) -> None:
    body = await create(client, accounts[0][1])
    identifier = UUID(body["id"])
    statements = []

    def capture(
        conn: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        statements.append(statement.lower())

    async with db_session.begin():
        connection = await db_session.connection()
        event.listen(connection.sync_connection, "before_cursor_execute", capture)
        try:
            repository = SecretRepository(db_session)
            assert (
                await repository.get_owned_by_id(identifier, accounts[0][0].id)
                is not None
            )
            assert (
                await repository.get_owned_by_id(identifier, accounts[1][0].id) is None
            )
        finally:
            event.remove(connection.sync_connection, "before_cursor_execute", capture)
    assert len(statements) == 2
    for sql in statements:
        predicate = sql.split("where", 1)[1]
        assert (
            "secrets.id =" in predicate
            and "secrets.user_id =" in predicate
            and " and " in predicate
        )


@pytest.mark.parametrize(
    "case", ["ciphertext", "nonce", "key_version", "encryption_version"]
)
async def test_owner_corruption_is_private_500(
    client: AsyncClient,
    db_session: AsyncSession,
    settings: Settings,
    accounts: tuple,
    case: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    user, pair = accounts[0]
    body = await create(client, pair)
    async with db_session.begin():
        row = await SecretRepository(db_session).get_owned_by_id(
            UUID(body["id"]), user.id
        )
        assert row is not None
        if case in ("ciphertext", "nonce"):
            value = getattr(row, case)
            setattr(row, case, bytes([value[0] ^ 1]) + value[1:])
        else:
            setattr(row, case, 99)
    result = await client.get(f"/secrets/{body['id']}", headers=bearer(pair))
    assert result.status_code == 500
    assert result.json() == {"detail": "Secret content unavailable."}
    async with db_session.begin():
        row = await SecretRepository(db_session).get_owned_by_id(
            UUID(body["id"]), user.id
        )
        stored_user = await db_session.get(User, user.id)
        assert row is not None and stored_user is not None
        assert_private_logs(caplog, row, pair, settings, stored_user.password_hash)


async def test_aad_prevents_blob_substitution(
    client: AsyncClient, db_session: AsyncSession, settings: Settings, accounts: tuple
) -> None:
    first = await create(client, accounts[0][1])
    second = await create(client, accounts[0][1], "second private value")
    async with db_session.begin():
        row = await SecretRepository(db_session).get_owned_by_id(
            UUID(first["id"]), accounts[0][0].id
        )
        assert row is not None
        for owner, identifier in (
            (accounts[0][0].id, UUID(second["id"])),
            (accounts[1][0].id, row.id),
        ):
            with pytest.raises(crypto.SecretDecryptionError):
                crypto.decrypt_secret_content(
                    encrypted(row), owner, identifier, settings
                )


@pytest.mark.parametrize(
    "content",
    ["x", "x" * 65536, "é" * 32768],
    ids=["one-byte", "max-ascii", "max-unicode"],
)
async def test_http_content_sizes(
    client: AsyncClient, accounts: tuple, content: str
) -> None:
    body = await create(client, accounts[0][1], content)
    result = await client.get(f"/secrets/{body['id']}", headers=bearer(accounts[0][1]))
    assert result.status_code == 200 and result.json()["content"] == content


@pytest.mark.parametrize(
    "content",
    ["", "SENSITIVE" * 8193, "é" * 32769, "\ud800"],
    ids=["empty", "oversize", "utf8-oversize", "surrogate"],
)
async def test_http_content_validation_private(
    client: AsyncClient, accounts: tuple, content: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    result = await client.post(
        "/secrets",
        content=json.dumps({"title": TITLE, "content": content}),
        headers={**bearer(accounts[0][1]), "Content-Type": "application/json"},
    )
    assert result.status_code == 422
    error = result.json()["detail"][0]
    assert set(error) == {"type", "loc", "msg"}
    assert error["msg"] == "Invalid secret content."
    if content:
        assert content not in result.text and content not in caplog.text
    assert "SENSITIVE" not in result.text


async def test_client_cannot_set_owner(client: AsyncClient, accounts: tuple) -> None:
    result = await client.post(
        "/secrets",
        json={"title": TITLE, "content": CONTENT, "user_id": str(accounts[1][0].id)},
        headers=bearer(accounts[0][1]),
    )
    assert result.status_code == 422


@pytest.mark.parametrize("header", [None, "Bearer invalid"])
async def test_secrets_require_authentication(
    client: AsyncClient, header: str | None
) -> None:
    headers = {} if header is None else {"Authorization": header}
    for method, path, body in (
        ("POST", "/secrets", {"title": TITLE, "content": CONTENT}),
        ("GET", f"/secrets/{uuid4()}", None),
    ):
        result = await client.request(method, path, json=body, headers=headers)
        assert (
            result.status_code == 401 and result.headers["www-authenticate"] == "Bearer"
        )


async def test_revoked_session_cannot_access_secret(
    client: AsyncClient, db_session: AsyncSession, accounts: tuple
) -> None:
    user, pair = accounts[0]
    body = await create(client, pair)
    result = await client.post(
        "/auth/logout", json={"refresh_token": pair.refresh_token}
    )
    assert result.status_code == 204
    assert (
        await client.get(f"/secrets/{body['id']}", headers=bearer(pair))
    ).status_code == 401
    assert (
        await client.post(
            "/secrets", json={"title": TITLE, "content": CONTENT}, headers=bearer(pair)
        )
    ).status_code == 401


@pytest.mark.parametrize("failure", ["encryption", "before_commit"])
async def test_creation_failure_returns_no_success(
    db_session: AsyncSession,
    settings: Settings,
    accounts: tuple,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    def fail(*args: object) -> None:
        assert db_session.in_transaction() is (failure == "before_commit")
        raise RuntimeError("controlled failure")

    if failure == "encryption":
        monkeypatch.setattr(service, "encrypt_secret_content", fail)
    else:
        event.listen(db_session.sync_session, "before_commit", fail)
    try:
        with pytest.raises(RuntimeError, match="controlled failure"):
            await service.create_secret(
                SecretCreateRequest(title=TITLE, content=CONTENT),
                accounts[0][0].id,
                db_session,
                settings,
            )
    finally:
        if failure == "before_commit":
            event.remove(db_session.sync_session, "before_commit", fail)
    assert db_session.in_transaction() is False
    async with db_session.begin():
        assert (
            await db_session.scalar(
                select(Secret.id).where(Secret.user_id == accounts[0][0].id)
            )
            is None
        )


async def test_duplicate_nonce_insert_is_not_bypassed(
    client: AsyncClient,
    db_session: AsyncSession,
    settings: Settings,
    accounts: tuple,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    request = SecretCreateRequest(title=TITLE, content=CONTENT)
    original = await service.create_secret(
        request, accounts[0][0].id, db_session, settings
    )
    async with db_session.begin():
        row = await SecretRepository(db_session).get_owned_by_id(
            original.id, accounts[0][0].id
        )
        assert row is not None
        prepared = encrypted(row)
    # Simuler une réponse crypto déjà préparée, sans refaire AES avec le même nonce.
    monkeypatch.setattr(service, "encrypt_secret_content", lambda *args: prepared)
    result = await client.post(
        "/secrets",
        json={"title": TITLE, "content": CONTENT},
        headers=bearer(accounts[0][1]),
    )
    assert result.status_code == 500
    assert result.json() == {"detail": "Secret could not be stored."}
    assert not db_session.in_transaction()
    async with db_session.begin():
        rows = (
            await db_session.scalars(
                select(Secret).where(Secret.user_id == accounts[0][0].id)
            )
        ).all()
        assert len(rows) == 1 and rows[0].id == original.id
        user = await db_session.get(User, accounts[0][0].id)
        assert user is not None
        assert_private_logs(
            caplog, rows[0], accounts[0][1], settings, user.password_hash
        )
        for value in (
            prepared.nonce.hex(),
            repr(prepared.nonce),
            prepared.ciphertext.hex(),
            base64.b64encode(prepared.ciphertext).decode(),
            settings.secrets_encryption_keys.get_secret_value(),
            "ab" * 32,
            "cd" * 32,
            CONTENT,
            accounts[0][1].access_token,
            accounts[0][1].refresh_token,
            PASSWORD,
            user.password_hash,
            "uq_secrets_key_version",
        ):
            assert value not in caplog.text and value not in result.text
        assert not any(record.exc_info for record in caplog.records)


async def test_other_integrity_error_is_not_translated(
    db_session: AsyncSession,
    settings: Settings,
) -> None:
    # Un propriétaire absent déclenche la FK réelle, sans simulation SQL.
    with pytest.raises(IntegrityError) as caught:
        await service.create_secret(
            SecretCreateRequest(title=TITLE, content=CONTENT),
            uuid4(),
            db_session,
            settings,
        )
    assert caught.value.orig.__cause__.constraint_name == "fk_secrets_user_id_users"
    assert not db_session.in_transaction()
    async with db_session.begin():
        assert await db_session.scalar(select(1)) == 1


async def test_nul_title_http_rejected_before_insert(
    client: AsyncClient,
    accounts: tuple,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)

    async def fail(*args: object) -> Secret:
        pytest.fail("Invalid title must not reach Secret INSERT")

    monkeypatch.setattr(SecretRepository, "add", fail)
    response = await client.post(
        "/secrets",
        json={"title": "a\u0000b", "content": CONTENT},
        headers=bearer(accounts[0][1]),
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["msg"] == "Value error, Invalid secret title."
    assert CONTENT not in response.text and CONTENT not in caplog.text
