import json
import logging
from datetime import UTC, datetime

from app.core.request_context import request_id

HTTP_LOGGER = "app.http"


class HTTPJSONFormatter(logging.Formatter):
    """Only explicitly allowed operational fields, never message or traceback."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "event": "http.request.completed",
                "request_id": request_id.get(),
                "method": getattr(record, "method", None),
                "route": getattr(record, "route", None),
                "status_code": getattr(record, "status_code", None),
                "duration_ms": getattr(record, "duration_ms", None),
            },
            ensure_ascii=True,
        )


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("app").setLevel(level)
    http_logger = logging.getLogger(HTTP_LOGGER)
    http_logger.setLevel(level)
    http_logger.propagate = False
    # Repeated lifespan startup must not multiply handlers.
    if not any(
        isinstance(h.formatter, HTTPJSONFormatter) for h in http_logger.handlers
    ):
        handler = logging.StreamHandler()
        handler.setFormatter(HTTPJSONFormatter())
        http_logger.addHandler(handler)
