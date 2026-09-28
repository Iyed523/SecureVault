FROM python:3.14.6-slim-trixie@sha256:7bec7ddcddeff7975d6ba9b4be7dd6f6b2f55e7491539145e2978f7f97ce9144

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

RUN groupadd --gid 10001 securevault \
    && useradd --uid 10001 --gid securevault --no-create-home securevault

COPY pyproject.toml README.md constraints-runtime.txt ./
COPY app ./app
RUN python -m pip install --no-cache-dir -c constraints-runtime.txt . \
    && python -m pip uninstall --yes pip
COPY alembic.ini ./
COPY migrations ./migrations

USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-proxy-headers"]
