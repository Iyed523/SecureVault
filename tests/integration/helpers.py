from secrets import token_bytes


def make_token_hash() -> bytes:
    """Empreinte factice aléatoire de 32 octets, réservée aux tests."""
    return token_bytes(32)
