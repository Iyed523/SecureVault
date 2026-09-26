from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

SENSITIVE_VALIDATION_MESSAGES = {
    "password": "Invalid password.",
    "refresh_token": "Invalid refresh token.",
}


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
                    "msg": next(
                        (
                            SENSITIVE_VALIDATION_MESSAGES[part]
                            for part in error["loc"]
                            if part in SENSITIVE_VALIDATION_MESSAGES
                        ),
                        error["msg"],
                    ),
                }
                for error in exc.errors()
            ]
        },
    )
