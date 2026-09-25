from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

SENSITIVE_VALIDATION_FIELDS = frozenset({"password"})


async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Conserve les diagnostics 422, sans entrée brute ni contexte de validation."""
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {
                    "type": error["type"],
                    "loc": error["loc"],
                    "msg": (
                        "Invalid password."
                        if any(
                            part in SENSITIVE_VALIDATION_FIELDS for part in error["loc"]
                        )
                        else error["msg"]
                    ),
                }
                for error in exc.errors()
            ]
        },
    )
