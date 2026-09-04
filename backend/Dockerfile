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
# Floors for transitive deps with known CVEs (see Trivy gate in CI). Applied
# *after* `pip install .` so no dependency resolution can downgrade them again.
RUN pip install --upgrade pip wheel && pip install . \
    && pip install --upgrade "setuptools>=78.1.1" \
    # pip>=26.2 vendors a CycloneDX SBOM (pip/_vendor/bom.cdx.json) listing its
    # vendored deps at stale versions (msgpack 1.1.2, setuptools 70.3.0). Trivy
    # scans embedded SBOMs and flagged those phantom versions, failing the CVE
    # gate. The vendored deps are not installed packages — strip the SBOM.
    && find /opt/venv -name "bom.cdx.json" -delete


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 curl tini \
    && rm -rf /var/lib/apt/lists/* \
    # The base image ships its own setuptools outside the venv; Trivy scans it
    # too, so upgrade it rather than leaving the stale copy in the image.
    && pip install --no-cache-dir --upgrade "setuptools>=78.1.1" \
    # Same vendored-SBOM strip as the builder, for the system pip the base
    # image ships (the strip above only covers /opt/venv). In python:slim
    # images all site-packages live under /usr/local/lib.
    && find /usr/local/lib -name "bom.cdx.json" -delete \
    && rm -rf /root/.cache \
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
