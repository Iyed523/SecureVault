import asyncio
from uuid import UUID

import pytest
from httpx2 import ASGITransport, AsyncClient
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.session import create_engine
from app.main import create_app
from app.models import Secret, User
from app.repositories.secrets import SecretRepository
from app.schemas.auth import LoginRequest
from app.schemas.secret import SecretCreateRequest, SecretUpdateRequest
from app.services.login import login_user
from app.services.secrets import create_secret, update_secret
from tests.integration.test_login import PASSWORD, seed

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def test_concurrent_title_and_content_patch_preserves_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings()
    engine = create_engine(settings)
    user_id: UUID | None = None
    new_title = "title committed by T1"
    new_content = "private content committed by T2"
    try:
        # De vrais commits rendent la ligne visible aux deux connexions.
        async with AsyncSession(engine, expire_on_commit=False) as setup:
            user = await seed(setup)
            user_id = user.id
            pair = await login_user(
                LoginRequest(email=user.email, password=PASSWORD), setup, settings
            )
            original = await create_secret(
                SecretCreateRequest(title="old title", content="old private content"),
                user.id,
                setup,
                settings,
            )

        async with (
            engine.connect() as connection1,
            engine.connect() as connection2,
            engine.connect() as observer,
        ):
            pid1 = await connection1.scalar(text("SELECT pg_backend_pid()"))
            pid2 = await connection2.scalar(text("SELECT pg_backend_pid()"))
            observer_pid = await observer.scalar(text("SELECT pg_backend_pid()"))
            assert len({pid1, pid2, observer_pid}) == 3
            for connection in (connection1, connection2):
                assert (
                    await connection.scalar(text("SHOW transaction_isolation"))
                    == "read committed"
                )
                await connection.rollback()

            async with (
                AsyncSession(connection1, expire_on_commit=False) as t1,
                AsyncSession(connection2, expire_on_commit=False) as t2,
            ):
                # Conserver volontairement un ancien objet dans l'identity map T2.
                async with t2.begin():
                    cached = await t2.get(Secret, original.id)
                    assert cached is not None and cached.title == "old title"
                    old_nonce, old_ciphertext = cached.nonce, cached.ciphertext
                assert not t1.in_transaction() and not t2.in_transaction()
                t1_locked = asyncio.Event()
                allow_t1_continue = asyncio.Event()
                t2_entered = asyncio.Event()
                t2_acquired = asyncio.Event()
                real_get = SecretRepository.get_owned_by_id_for_update

                async def controlled_get(
                    repository: SecretRepository,
                    secret_id: UUID,
                    owner_id: UUID,
                ) -> Secret | None:
                    if repository.session is t2:
                        t2_entered.set()
                    row = await real_get(repository, secret_id, owner_id)
                    if repository.session is t1:
                        assert row is not None
                        t1_locked.set()
                        await allow_t1_continue.wait()
                    elif repository.session is t2:
                        assert row is cached
                        assert row.title == new_title
                        t2_acquired.set()
                    return row

                monkeypatch.setattr(
                    SecretRepository, "get_owned_by_id_for_update", controlled_get
                )
                tasks = []
                try:
                    # Timeout de garde seulement ; synchronisation par événements
                    # et constat du verrou dans PostgreSQL, sans sleep.
                    async with asyncio.timeout(10):
                        tasks.append(
                            asyncio.create_task(
                                update_secret(
                                    original.id,
                                    SecretUpdateRequest(title=new_title),
                                    user.id,
                                    t1,
                                    settings,
                                )
                            )
                        )
                        await t1_locked.wait()
                        tasks.append(
                            asyncio.create_task(
                                update_secret(
                                    original.id,
                                    SecretUpdateRequest(content=new_content),
                                    user.id,
                                    t2,
                                    settings,
                                )
                            )
                        )
                        await t2_entered.wait()
                        while True:
                            blockers = await observer.scalar(
                                text("SELECT pg_blocking_pids(:pid)"), {"pid": pid2}
                            )
                            if pid1 in blockers:
                                break
                            assert not tasks[1].done()
                        assert not t2_acquired.is_set()
                        assert not tasks[0].done() and not tasks[1].done()
                        assert t1.in_transaction()
                        allow_t1_continue.set()
                        first, second = await asyncio.gather(*tasks)
                        assert t2_acquired.is_set()
                        assert first.title == second.title == new_title
                        assert not t1.in_transaction() and not t2.in_transaction()
                finally:
                    allow_t1_continue.set()
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)

        # Lecture fraîche après les deux commits, hors identity maps T1/T2.
        async with AsyncSession(engine) as verification, verification.begin():
            row = await verification.get(Secret, original.id)
            assert row is not None
            assert row.id == original.id and row.user_id == user.id
            assert row.title == new_title
            assert row.nonce != old_nonce and len(row.nonce) == 12
            assert row.ciphertext != old_ciphertext
            assert row.key_version == settings.secrets_active_key_version
            assert row.encryption_version == 1

        # GET propriétaire avec la dépendance et une session HTTP fraîches.
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as http:
                response = await http.get(
                    f"/secrets/{original.id}",
                    headers={"Authorization": f"Bearer {pair.access_token}"},
                )
                assert response.status_code == 200
                assert response.json()["title"] == new_title
                assert response.json()["content"] == new_content
                assert response.json()["id"] == str(original.id)
    finally:
        try:
            if user_id is not None:
                async with AsyncSession(engine) as cleanup, cleanup.begin():
                    await cleanup.execute(delete(User).where(User.id == user_id))
        finally:
            await engine.dispose()
