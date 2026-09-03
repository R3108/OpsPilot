# syntax=docker/dockerfile:1.7
#
# Two stages: a builder that compiles wheels, and a slim runtime that gets only
# the installed site-packages. The runtime image has no compiler and runs as a
# non-root user — an agent that can restart your production pods should not
# itself be running as root.

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml ./
# Installing into a venv keeps the copy into the runtime stage a single directory.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# Floors for transitive deps with known CVEs (see Trivy gate in CI).
RUN pip install --upgrade pip "setuptools>=78.1.1" "msgpack>=1.2.1" wheel && pip install .


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1001 opspilot \
    && useradd --system --uid 1001 --gid opspilot --create-home opspilot

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=opspilot:opspilot alembic.ini ./
COPY --chown=opspilot:opspilot alembic ./alembic
COPY --chown=opspilot:opspilot app ./app

USER opspilot

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health/live || exit 1

# tini reaps the zombie processes uvicorn's reloader and boto3's threads leave.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
