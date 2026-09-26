import hashlib
import secrets


def generate_refresh_token() -> str:
    return secrets.token_hex(32)


def hash_refresh_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()
