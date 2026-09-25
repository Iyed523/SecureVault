import pytest
from email_validator import deliverability
from pydantic import ValidationError

from app.schemas.auth import RegistrationRequest, canonicalize_email


@pytest.mark.parametrize(
    "password",
    ["x" * 15, "x" * 128, " " * 15, "  Une phrase avec é 🔐 !  ", "e\u0301" * 15],
)
def test_password_policy_preserves_value(password: str) -> None:
    request = RegistrationRequest(email="user@example.com", password=password)
    assert request.password.get_secret_value() == password
    assert password not in repr(request)
    assert password not in str(request)
    assert password not in request.model_dump_json()


@pytest.mark.parametrize("password", ["x" * 14, "x" * 129])
def test_password_policy_rejects_invalid_lengths(password: str) -> None:
    with pytest.raises(ValidationError) as caught:
        RegistrationRequest(email="user@example.com", password=password)
    assert password not in str(caught.value)


@pytest.mark.parametrize(
    ("email", "expected"),
    [
        ("User@Example.COM", "user@example.com"),
        ("First.Last+Tag@Gmail.com", "first.last+tag@gmail.com"),
        ("Straße@Example.com", "strasse@example.com"),
        ("e\u0301@Example.com", "é@example.com"),
    ],
)
def test_email_canonicalization_without_dns(
    monkeypatch: pytest.MonkeyPatch, email: str, expected: str
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Aucune vérification de délivrabilité ne doit être appelée")

    monkeypatch.setattr(deliverability, "validate_email_deliverability", forbidden)
    assert canonicalize_email(email) == expected


def test_email_length_limit() -> None:
    email = "a" * 64 + "@" + "b" * 63 + "." + "c" * 63 + "." + "d" * 57 + ".com"
    assert len(canonicalize_email(email)) == 254
    with pytest.raises(ValueError, match="Invalid email address"):
        canonicalize_email(email.replace(".com", ".comx"))


@pytest.mark.parametrize("email", ["invalid", "user@@example.com", "@example.com"])
def test_invalid_email_has_generic_error(email: str) -> None:
    with pytest.raises(ValidationError) as caught:
        RegistrationRequest(email=email, password="x" * 15)
    assert caught.value.errors()[0]["msg"] == "Value error, Invalid email address."
