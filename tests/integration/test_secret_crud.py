import base64
import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from httpx2 import AsyncClient
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import Secret, User
from app.schemas.auth import TokenPairResponse
from app.schemas.secret import SecretUpdateRequest
from app.schemas.user import PublicUser
from app.services import secrets as service
from tests.integration.test_secrets import (
    CONTENT,
    PASSWORD,
    bearer,
    encrypted,
)
from tests.integration.test_secrets import (
    accounts as accounts,
)
from tests.integration.test_secrets import (
    client as client,
)
from tests.integration.test_secrets import (
    settings as settings,
)

pytestmark = [pytest.mark.integration, pytest.mark.anyio]
Accounts = tuple[
    tuple[PublicUser, TokenPairResponse], tuple[PublicUser, TokenPairResponse]
]
SUMMARY_FIELDS = {"id", "title", "created_at", "updated_at"}


async def create(
    client: AsyncClient,
    pair: TokenPairResponse,
    title: str = "original",
    content: str = CONTENT,
) -> UUID:
    result = await client.post(
        "/secrets", headers=bearer(pair), json={"title": title, "content": content}
    )
    assert result.status_code == 201
    return UUID(result.json()["id"])


async def snapshot(db: AsyncSession, identifier: UUID) -> dict[str, object]:
    async with db.begin():
        row = await db.get(Secret, identifier, populate_existing=True)
        assert row is not None
        return {
            column.name: getattr(row, column.name)
            for column in Secret.__table__.columns
        }


def no_crypto(*args: object) -> str:
    pytest.fail("This operation must not invoke crypto")


async def test_collection_search_isolation_and_no_decrypt(
    client: AsyncClient,
    db_session: AsyncSession,
    accounts: Accounts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    titles = [
        "Alpha Vault",
        "100% literal",
        "under_score",
        "back\\slash",
        "plain title",
    ]
    identifiers = [await create(client, accounts[0][1], title) for title in titles]
    foreign = await create(client, accounts[1][1], "Alpha Vault")
    async with db_session.begin():
        row = await db_session.get(Secret, identifiers[0])
        assert row is not None
        row.ciphertext = bytes([row.ciphertext[0] ^ 1]) + row.ciphertext[1:]
    with monkeypatch.context() as patch:
        patch.setattr(service, "decrypt_secret_content", no_crypto)
        patch.setattr(service, "encrypt_secret_content", no_crypto)
        cases = [
            (None, identifiers),
            ("VAuLT", [identifiers[0]]),
            ("pha", [identifiers[0]]),
            ("no-match", []),
            ("SECRET-CONTENT", []),
            ("%", [identifiers[1]]),
            ("_", [identifiers[2]]),
            ("\\", [identifiers[3]]),
        ]
        for query, expected in cases:
            result = await client.get(
                "/secrets",
                headers=bearer(accounts[0][1]),
                params={} if query is None else {"q": query},
            )
            assert result.status_code == 200
            body = result.json()
            assert set(body) == {"items", "limit", "offset", "has_more"}
            assert {item["id"] for item in body["items"]} == {str(i) for i in expected}
            assert all(set(item) == SUMMARY_FIELDS for item in body["items"])
            assert body["limit"] == 20 and body["offset"] == 0
            assert body["has_more"] is False
        result = await client.get("/secrets", headers=bearer(accounts[1][1]))
        assert [item["id"] for item in result.json()["items"]] == [str(foreign)]
    result = await client.get(
        f"/secrets/{identifiers[0]}", headers=bearer(accounts[0][1])
    )
    assert result.status_code == 500
    assert result.json() == {"detail": "Secret content unavailable."}


async def test_pagination_order_and_has_more(
    client: AsyncClient,
    db_session: AsyncSession,
    accounts: Accounts,
) -> None:
    identifiers = [await create(client, accounts[0][1]) for _ in range(5)]
    timestamp = datetime(2020, 1, 1, tzinfo=UTC)
    dated = [
        (identifier, timestamp + timedelta(days=index // 2))
        for index, identifier in enumerate(identifiers)
    ]
    async with db_session.begin():
        for identifier, created_at in dated:
            row = await db_session.get(Secret, identifier)
            assert row is not None
            row.created_at = created_at
    expected = [
        str(identifier)
        for identifier, _ in sorted(
            dated, key=lambda pair: (pair[1], pair[0]), reverse=True
        )
    ]
    for offset, more in [(0, True), (2, True), (4, False), (5, False)]:
        result = await client.get(
            "/secrets",
            headers=bearer(accounts[0][1]),
            params={"limit": 2, "offset": offset},
        )
        assert result.status_code == 200
        body = result.json()
        assert [item["id"] for item in body["items"]] == expected[offset : offset + 2]
        assert body["has_more"] is more
        assert body["limit"] == 2 and body["offset"] == offset


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"q": " "},
        {"q": ""},
        {"q": "x" * 201},
        {"q": "a\x00b"},
        {"user_id": "foreign"},
    ],
)
async def test_http_invalid_query(
    client: AsyncClient, accounts: Accounts, params: dict
) -> None:
    result = await client.get("/secrets", headers=bearer(accounts[0][1]), params=params)
    assert result.status_code == 422


async def test_patch_title_only_preserves_crypto_and_timestamp(
    client: AsyncClient,
    db_session: AsyncSession,
    accounts: Accounts,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings.secrets_active_key_version = 1
    identifier = await create(client, accounts[0][1])
    async with db_session.begin():
        row = await db_session.get(Secret, identifier)
        assert row is not None
        row.updated_at = datetime(2000, 1, 1, tzinfo=UTC)
    before = await snapshot(db_session, identifier)
    settings.secrets_active_key_version = 2
    with monkeypatch.context() as patch:
        patch.setattr(service, "encrypt_secret_content", no_crypto)
        patch.setattr(service, "decrypt_secret_content", no_crypto)
        result = await client.patch(
            f"/secrets/{identifier}",
            headers=bearer(accounts[0][1]),
            json={"title": "  New e\u0301 title  "},
        )
        assert result.status_code == 200 and set(result.json()) == SUMMARY_FIELDS
        first_state = await snapshot(db_session, identifier)
        async with db_session.begin():
            connection = await db_session.connection()
            sync = connection.sync_connection
        statements: list[str] = []

        def capture(
            conn: object,
            cursor: object,
            statement: str,
            parameters: object,
            context: object,
            executemany: bool,
        ) -> None:
            statements.append(" ".join(statement.lower().split()))

        event.listen(sync, "before_cursor_execute", capture)
        try:
            unchanged = await client.patch(
                f"/secrets/{identifier}",
                headers=bearer(accounts[0][1]),
                json={"title": "  New e\u0301 title  "},
            )
        finally:
            event.remove(sync, "before_cursor_execute", capture)
        assert unchanged.status_code == 200
        assert any("for update" in sql for sql in statements)
        assert not any(sql.startswith("update secrets ") for sql in statements)
        assert unchanged.json() == result.json()
    after = await snapshot(db_session, identifier)
    assert after["updated_at"] == first_state["updated_at"]
    for name in (
        "ciphertext",
        "nonce",
        "key_version",
        "encryption_version",
        "id",
        "user_id",
        "created_at",
    ):
        assert after[name] == before[name]
    assert after["key_version"] == 1
    assert after["title"] == "  New e\u0301 title  "
    assert after["updated_at"] > before["updated_at"]
    assert datetime.fromisoformat(result.json()["updated_at"]) == after["updated_at"]
    detail = await client.get(f"/secrets/{identifier}", headers=bearer(accounts[0][1]))
    assert detail.json()["content"] == CONTENT


@pytest.mark.parametrize("both", [False, True])
async def test_patch_content_rotation_and_no_decrypt(
    client: AsyncClient,
    db_session: AsyncSession,
    accounts: Accounts,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    both: bool,
) -> None:
    settings.secrets_active_key_version = 1
    identifier = await create(client, accounts[0][1])
    before = await snapshot(db_session, identifier)
    settings.secrets_active_key_version = 2
    plaintext = "  new PRIVATE é e\u0301  "
    real_encrypt = service.encrypt_secret_content
    calls = []

    def encrypt(content: str, user_id: UUID, secret_id: UUID, config: Settings):
        assert not db_session.in_transaction()
        assert user_id == accounts[0][0].id and secret_id == identifier
        calls.append(secret_id)
        return real_encrypt(content, user_id, secret_id, config)

    body = {"content": plaintext}
    if both:
        body["title"] = "new title"
    with monkeypatch.context() as patch:
        patch.setattr(service, "decrypt_secret_content", no_crypto)
        patch.setattr(service, "encrypt_secret_content", encrypt)
        result = await client.patch(
            f"/secrets/{identifier}", headers=bearer(accounts[0][1]), json=body
        )
    assert calls == [identifier]
    assert result.status_code == 200 and set(result.json()) == SUMMARY_FIELDS
    assert plaintext not in result.text
    after = await snapshot(db_session, identifier)
    for name in ("id", "user_id", "created_at"):
        assert after[name] == before[name]
    assert (
        after["nonce"] != before["nonce"]
        and after["ciphertext"] != before["ciphertext"]
    )
    assert after["key_version"] == 2 and after["encryption_version"] == 1
    assert after["title"] == ("new title" if both else before["title"])
    assert datetime.fromisoformat(result.json()["updated_at"]) == after["updated_at"]
    assert all(
        value not in (CONTENT, CONTENT.encode(), plaintext, plaintext.encode())
        for value in after.values()
    )
    detail = await client.get(f"/secrets/{identifier}", headers=bearer(accounts[0][1]))
    assert detail.json()["content"] == plaintext
    # Même plaintext : nouveau nonce, sans déchiffrer pour comparer.
    with monkeypatch.context() as patch:
        patch.setattr(service, "decrypt_secret_content", no_crypto)
        again = await client.patch(
            f"/secrets/{identifier}",
            headers=bearer(accounts[0][1]),
            json={"content": plaintext},
        )
    assert again.status_code == 200
    assert (await snapshot(db_session, identifier))["nonce"] != after["nonce"]


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"title": None},
        {"content": None},
        {"title": " "},
        {"title": "a\x00b"},
        {"content": ""},
        {"content": "PRIVATE" * 10000},
        {"content": "\ud800"},
        {"title": "ok", "user_id": "foreign"},
    ],
    ids=[
        "empty",
        "null-title",
        "null-content",
        "blank-title",
        "nul-title",
        "empty-content",
        "oversize",
        "surrogate",
        "owner",
    ],
)
async def test_http_patch_validation(
    client: AsyncClient,
    accounts: Accounts,
    body: dict,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import json

    result = await client.patch(
        f"/secrets/{uuid4()}",
        headers={**bearer(accounts[0][1]), "Content-Type": "application/json"},
        content=json.dumps(body),
    )
    assert result.status_code == 422
    assert "PRIVATE" not in result.text and "PRIVATE" not in caplog.text
    assert all(
        set(error) == {"type", "loc", "msg"} for error in result.json()["detail"]
    )
    if "content" in body:
        assert result.json()["detail"][0]["msg"] == "Invalid secret content."


async def test_patch_and_delete_idor_and_delete_contract(
    client: AsyncClient,
    db_session: AsyncSession,
    accounts: Accounts,
) -> None:
    identifier = await create(client, accounts[0][1])
    before = await snapshot(db_session, identifier)
    for method, body in [
        ("PATCH", {"title": "intrusion"}),
        ("PATCH", {"content": "intrusion"}),
        ("DELETE", None),
    ]:
        for target in (identifier, uuid4()):
            result = await client.request(
                method, f"/secrets/{target}", headers=bearer(accounts[1][1]), json=body
            )
            assert result.status_code == 404 and result.json() == {
                "detail": "Secret not found."
            }
        assert await snapshot(db_session, identifier) == before
    result = await client.delete(
        f"/secrets/{identifier}", headers=bearer(accounts[0][1])
    )
    assert result.status_code == 204 and result.content == b""
    async with db_session.begin():
        assert (
            await db_session.scalar(select(Secret.id).where(Secret.id == identifier))
            is None
        )
    for method in ("GET", "DELETE"):
        result = await client.request(
            method, f"/secrets/{identifier}", headers=bearer(accounts[0][1])
        )
        assert result.status_code == 404 and result.json() == {
            "detail": "Secret not found."
        }


@pytest.mark.parametrize("operation", ["patch", "delete"])
async def test_before_commit_rollback(
    client: AsyncClient,
    db_session: AsyncSession,
    accounts: Accounts,
    settings: Settings,
    operation: str,
) -> None:
    identifier = await create(client, accounts[0][1])
    before = await snapshot(db_session, identifier)

    def fail(session: Session) -> None:
        assert db_session.in_transaction()
        persisted_title = session.scalar(
            select(Secret.title).where(Secret.id == identifier)
        )
        assert persisted_title == ("changed" if operation == "patch" else None)
        raise RuntimeError("before_commit sentinel")

    event.listen(db_session.sync_session, "before_commit", fail)
    try:
        with pytest.raises(RuntimeError, match="before_commit sentinel"):
            if operation == "patch":
                await service.update_secret(
                    identifier,
                    SecretUpdateRequest(title="changed", content="new private"),
                    accounts[0][0].id,
                    db_session,
                    settings,
                )
            else:
                await service.delete_secret(identifier, accounts[0][0].id, db_session)
    finally:
        event.remove(db_session.sync_session, "before_commit", fail)
    assert not db_session.in_transaction()
    assert await snapshot(db_session, identifier) == before


async def test_patch_nonce_collision_rollback_and_logs(
    client: AsyncClient,
    db_session: AsyncSession,
    accounts: Accounts,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    first = await create(client, accounts[0][1])
    second = await create(client, accounts[0][1], "second")
    before = await snapshot(db_session, first)
    async with db_session.begin():
        row = await db_session.get(Secret, second)
        user = await db_session.get(User, accounts[0][0].id)
        assert row is not None and user is not None
        prepared, password_hash = encrypted(row), user.password_hash
    monkeypatch.setattr(service, "encrypt_secret_content", lambda *args: prepared)
    result = await client.patch(
        f"/secrets/{first}",
        headers=bearer(accounts[0][1]),
        json={"title": "partial forbidden", "content": "new PRIVATE"},
    )
    assert result.status_code == 500 and result.json() == {
        "detail": "Secret could not be stored."
    }
    assert not db_session.in_transaction()
    assert await snapshot(db_session, first) == before
    detail = await client.get(f"/secrets/{first}", headers=bearer(accounts[0][1]))
    assert detail.json()["content"] == CONTENT
    for value in (
        CONTENT,
        "new PRIVATE",
        prepared.nonce.hex(),
        repr(prepared.nonce),
        prepared.ciphertext.hex(),
        base64.b64encode(prepared.ciphertext).decode(),
        settings.secrets_encryption_keys.get_secret_value(),
        "ab" * 32,
        "cd" * 32,
        accounts[0][1].access_token,
        PASSWORD,
        password_hash,
        "uq_secrets_key_version",
    ):
        assert value not in caplog.text and value not in result.text
    assert not any(record.exc_info for record in caplog.records)


async def test_sql_owner_predicates_lock_and_metadata_projection(
    client: AsyncClient,
    db_session: AsyncSession,
    accounts: Accounts,
) -> None:
    identifier = await create(client, accounts[0][1], "matched")
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    # La connexion externe de la fixture reste la même entre les savepoints.
    async with db_session.begin():
        connection = await db_session.connection()
        sync = connection.sync_connection
    event.listen(sync, "before_cursor_execute", capture)
    try:
        assert (
            await client.get(
                "/secrets", params={"q": "matched"}, headers=bearer(accounts[0][1])
            )
        ).status_code == 200
        assert (
            await client.patch(
                f"/secrets/{identifier}",
                json={"title": "changed"},
                headers=bearer(accounts[0][1]),
            )
        ).status_code == 200
        assert (
            await client.delete(
                f"/secrets/{identifier}", headers=bearer(accounts[0][1])
            )
        ).status_code == 204
    finally:
        event.remove(sync, "before_cursor_execute", capture)
    collection = [sql for sql in statements if "from secrets" in sql and "ilike" in sql]
    assert len(collection) == 1
    sql = collection[0]
    assert "secrets.user_id =" in sql and "escape" in sql
    assert "order by secrets.created_at desc, secrets.id desc" in sql
    assert "limit" in sql and "offset" in sql and "count(" not in sql
    assert "ciphertext" not in sql and "nonce" not in sql
    locked = [sql for sql in statements if "for update" in sql]
    assert len(locked) == 1
    assert "secrets.id =" in locked[0] and "secrets.user_id =" in locked[0]
    deleted = [sql for sql in statements if sql.startswith("delete from secrets")]
    assert len(deleted) == 1 and "returning secrets.id" in deleted[0]
    assert "secrets.id =" in deleted[0] and "secrets.user_id =" in deleted[0]


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("GET", "/secrets", None),
        ("PATCH", f"/secrets/{uuid4()}", {"title": "new"}),
        ("DELETE", f"/secrets/{uuid4()}", None),
    ],
)
async def test_new_routes_require_auth(
    client: AsyncClient, method: str, path: str, body: dict | None
) -> None:
    result = await client.request(method, path, json=body)
    assert result.status_code == 401 and result.headers["www-authenticate"] == "Bearer"


async def test_metadata_mutations_private_logs_and_large_offset(
    client: AsyncClient,
    db_session: AsyncSession,
    accounts: Accounts,
    settings: Settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    identifier = await create(client, accounts[0][1])
    before = await snapshot(db_session, identifier)
    plaintext = "PHASE8-PRIVATE-NEW-CONTENT"
    result = await client.patch(
        f"/secrets/{identifier}",
        headers=bearer(accounts[0][1]),
        json={"content": plaintext},
    )
    assert result.status_code == 200 and set(result.json()) == SUMMARY_FIELDS
    after = await snapshot(db_session, identifier)
    responses = [result.text]
    for params in ({}, {"q": "original"}, {"offset": 2**63 - 1}):
        result = await client.get(
            "/secrets", headers=bearer(accounts[0][1]), params=params
        )
        assert result.status_code == 200
        if "offset" in params:
            assert result.json()["items"] == [] and result.json()["has_more"] is False
        else:
            assert all(set(item) == SUMMARY_FIELDS for item in result.json()["items"])
        responses.append(result.text)
    async with db_session.begin():
        user = await db_session.get(User, accounts[0][0].id)
        assert user is not None
        password_hash = user.password_hash
    result = await client.delete(
        f"/secrets/{identifier}", headers=bearer(accounts[0][1])
    )
    assert result.status_code == 204 and result.content == b""
    sensitive = [
        CONTENT,
        plaintext,
        settings.secrets_encryption_keys.get_secret_value(),
        "ab" * 32,
        "cd" * 32,
        accounts[0][1].access_token,
        accounts[0][1].refresh_token,
        PASSWORD,
        password_hash,
    ]
    for data in (before, after):
        for name in ("nonce", "ciphertext"):
            value = data[name]
            assert isinstance(value, bytes)
            sensitive.extend(
                [value.hex(), repr(value), base64.b64encode(value).decode()]
            )
    for value in sensitive:
        assert value not in caplog.text and all(value not in text for text in responses)
    assert not any(record.exc_info for record in caplog.records)
