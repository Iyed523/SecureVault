from argon2 import Type
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError
from pwdlib.hashers.argon2 import Argon2Hasher

MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128

_argon2 = Argon2Hasher(memory_cost=65536, time_cost=3, parallelism=1, type=Type.ID)
_password_hash = PasswordHash((_argon2,))


def validate_password(password: str) -> str:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise ValueError("Password must contain between 15 and 128 characters.")
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Password must contain valid Unicode characters.") from None
    return password


def hash_password(password: str) -> str:
    return _password_hash.hash(validate_password(password))


def verify_password(password: str, password_hash: str) -> bool:
    try:
        validate_password(password)
    except ValueError:
        return False
    try:
        return _password_hash.verify(password, password_hash)
    except UnknownHashError:
        return False


def password_needs_rehash(password_hash: str) -> bool:
    """Inspecte un hash Argon2 stocké valide, sans le modifier."""
    return _argon2.check_needs_rehash(password_hash)
