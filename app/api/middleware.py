import logging
from time import perf_counter
from uuid import uuid4

from starlette.datastructures import MutableHeaders
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import HTTP_LOGGER
from app.core.request_context import request_id

logger = logging.getLogger(HTTP_LOGGER)
METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
)


class HTTPObservabilityMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        identifier = uuid4().hex
        token = request_id.set(identifier)
        started = perf_counter()
        status_code = 500

        async def send_response(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = identifier
                headers["Cache-Control"] = "no-store"
                headers["X-Content-Type-Options"] = "nosniff"
            await send(message)

        try:
            await self.app(scope, receive, send_response)
        finally:
            try:
                route = scope.get("route")
                method = scope.get("method")
                logger.info(
                    "http.request.completed",
                    extra={
                        "method": method if method in METHODS else "<other>",
                        "route": route.path
                        if isinstance(route, Route)
                        else "<unmatched>",
                        "status_code": status_code,
                        "duration_ms": round((perf_counter() - started) * 1000, 3),
                    },
                )
            finally:
                request_id.reset(token)
