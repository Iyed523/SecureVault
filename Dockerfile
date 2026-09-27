FROM python:3.13.14-slim-bookworm@sha256:67a1e1f215ccda113cfc024e8639049257e88f273898f595b61476d128d387e8

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

RUN groupadd --gid 10001 securevault \
    && useradd --uid 10001 --gid securevault --no-create-home securevault

COPY pyproject.toml README.md constraints-runtime.txt ./
COPY app ./app
RUN python -m pip install --no-cache-dir -c constraints-runtime.txt .
COPY alembic.ini ./
COPY migrations ./migrations

USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-proxy-headers"]
