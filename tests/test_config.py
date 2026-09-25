from pathlib import Path

import pytest
from dotenv import dotenv_values
from pydantic import ValidationError

from app.core.config import Settings


@pytest.fixture
def infrastructure_config(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    for name in ("DATABASE_URL", "REDIS_URL", "database_url", "redis_url"):
        monkeypatch.delenv(name, raising=False)
    example = dotenv_values(Path(__file__).resolve().parents[1] / ".env.example")
    return {name.lower(): str(example[name]) for name in ("DATABASE_URL", "REDIS_URL")}


@pytest.mark.parametrize("missing", ["database_url", "redis_url"])
def test_infrastructure_url_is_required(
    infrastructure_config: dict[str, str], missing: str
) -> None:
    values = infrastructure_config.copy()
    values.pop(missing)
    with pytest.raises(ValidationError) as caught:
        Settings(_env_file=None, **values)
    message = str(caught.value)
    assert missing in message
    assert "Field required" in message
    for value in infrastructure_config.values():
        assert value not in message
    assert "local_dev_only" not in message


def test_complete_configuration_is_valid(infrastructure_config: dict[str, str]) -> None:
    settings = Settings(_env_file=None, **infrastructure_config)
    assert str(settings.database_url) == infrastructure_config["database_url"]
    assert str(settings.redis_url) == infrastructure_config["redis_url"]
    for value in infrastructure_config.values():
        assert value not in repr(settings)
