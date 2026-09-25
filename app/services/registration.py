from asyncpg import UniqueViolationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.models import User
from app.repositories.users import UserRepository
from app.schemas.auth import RegistrationRequest
from app.schemas.user import PublicUser
from app.security.passwords import hash_password


class EmailAlreadyRegistered(Exception):
    """Inscription indisponible pour cet email."""


async def register_user(
    request: RegistrationRequest, session: AsyncSession
) -> PublicUser:
    """Attend une session sans transaction active ; contrôle commit et rollback."""
    try:
        async with session.begin():
            password_hash = await run_in_threadpool(
                hash_password, request.password.get_secret_value()
            )
            user = await UserRepository(session).add(
                User(email=request.email, password_hash=password_hash)
            )
            public_user = PublicUser.model_validate(user)
    except IntegrityError as exc:
        cause = exc.orig.__cause__
        if (
            isinstance(cause, UniqueViolationError)
            and cause.constraint_name == "uq_users_email"
        ):
            raise EmailAlreadyRegistered() from None
        raise
    return public_user
