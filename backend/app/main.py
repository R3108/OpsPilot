"""FastAPI application."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api.v1.router import api_router
from app.core import metrics
from app.core.config import settings
from app.core.db import check_database, dispose_engine
from app.core.errors import OpsPilotError
from app.core.logging import (
    configure_logging,
    get_logger,
    incident_id_ctx,
    request_id_ctx,
    tenant_id_ctx,
    user_id_ctx,
)
from app.core.redis_client import check_redis, close_redis
from app.schemas.common import HealthStatus

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    settings.validate_production()

    # Importing the catalog at boot means a malformed action fails the process
    # rather than surfacing mid-incident.
    from app.services.actions import ACTION_REGISTRY, registry_fingerprint

    log.info(
        "api.starting",
        version=__version__,
        environment=settings.environment,
        llm_provider=settings.llm_provider,
        actions=len(ACTION_REGISTRY),
        catalog_fingerprint=registry_fingerprint(),
        remediation_disabled=settings.remediation_disabled,
    )

    if settings.langchain_tracing_v2 and settings.langchain_api_key:
        import os

        os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")
        os.environ.setdefault("LANGCHAIN_API_KEY", settings.langchain_api_key)
        os.environ.setdefault("LANGCHAIN_PROJECT", settings.langchain_project)
        os.environ.setdefault("LANGCHAIN_ENDPOINT", settings.langchain_endpoint)
        log.info("api.langsmith_enabled", project=settings.langchain_project)

    yield

    from app.workers.queue import close_pool

    await close_pool()
    await close_redis()
    await dispose_engine()
    log.info("api.stopped")


app = FastAPI(
    title=settings.project_name,
    description=(
        "Autonomous AI SRE. Ingests alerts, investigates with a LangGraph agent "
        "swarm, proposes remediation from a fixed action catalog, gates every "
        "risky change behind deterministic policy plus human approval, verifies "
        "recovery, and writes the postmortem."
    ),
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    openapi_url="/openapi.json" if not settings.is_production else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)
app.add_middleware(GZipMiddleware, minimum_size=1024)


@app.middleware("http")
async def request_context(request: Request, call_next):  # noqa: ANN001, ANN201
    """Attach a request id, time the request, and clear the logging context."""
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
    request_id_ctx.set(request_id)
    tenant_id_ctx.set(None)
    user_id_ctx.set(None)
    incident_id_ctx.set(None)

    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        log.exception(
            "request.unhandled",
            method=request.method,
            path=request.url.path,
            ms=int((time.perf_counter() - started) * 1000),
        )
        raise

    duration_ms = int((time.perf_counter() - started) * 1000)
    response.headers["X-Request-ID"] = request_id
    # SSE responses are long-lived; logging their duration is meaningless noise.
    if not request.url.path.startswith(f"{settings.api_v1_prefix}/stream"):
        log.info(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            ms=duration_ms,
        )
        route = request.scope.get("route")
        route_path = getattr(route, "path", request.url.path) if route else request.url.path
        metrics.inc(
            "opspilot_http_requests_total",
            labels={
                "route": route_path,
                "method": request.method,
                "status": str(response.status_code),
            },
        )
        metrics.observe_latency("opspilot_http_request_seconds", (time.perf_counter() - started))
    return response


# --------------------------------------------------------------------------
# error handling
# --------------------------------------------------------------------------
@app.exception_handler(OpsPilotError)
async def opspilot_error_handler(_request: Request, exc: OpsPilotError) -> JSONResponse:
    if exc.status_code >= 500:
        log.error("error.server", code=exc.code, message=exc.message, details=exc.details)
    else:
        log.info("error.client", code=exc.code, message=exc.message)
    return JSONResponse(status_code=exc.status_code, content=_jsonable(exc.to_payload()))


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "Request validation failed",
                # Pydantic puts the original exception object in `ctx` for custom
                # validators, which is not JSON-serialisable — stringify it rather
                # than turning a 422 into a 500.
                "details": {"errors": _jsonable(exc.errors())},
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": "http_error", "message": str(exc.detail)}},
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    log.exception("error.unhandled", error_type=type(exc).__name__)
    # Never leak an internal message to a client in production.
    message = (
        "An unexpected error occurred" if settings.is_production else f"{type(exc).__name__}: {exc}"
    )
    return JSONResponse(
        status_code=500, content={"error": {"code": "internal_error", "message": message}}
    )


def _jsonable(value: object) -> object:
    """Coerce anything into something the JSON encoder will accept."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


# --------------------------------------------------------------------------
# health
# --------------------------------------------------------------------------
@app.get("/health", response_model=HealthStatus, tags=["health"])
async def health() -> HealthStatus:
    database_ok = await check_database()
    redis_ok = await check_redis()
    return HealthStatus(
        status="ok" if (database_ok and redis_ok) else "degraded",
        version=__version__,
        environment=settings.environment,
        database=database_ok,
        redis=redis_ok,
        checked_at=datetime.now(UTC),
    )


@app.get("/health/live", tags=["health"])
async def liveness() -> dict[str, str]:
    """Process is up. Deliberately does not touch dependencies."""
    return {"status": "alive"}


@app.get("/health/ready", tags=["health"])
async def readiness() -> JSONResponse:
    """Ready to serve: database and Redis both reachable."""
    database_ok = await check_database()
    redis_ok = await check_redis()
    ready = database_ok and redis_ok
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"ready": ready, "database": database_ok, "redis": redis_ok},
    )


@app.get("/metrics", tags=["observability"])
async def prometheus_metrics() -> Response:
    """Prometheus text exposition: request rates, latencies, domain counters."""
    from fastapi.responses import PlainTextResponse

    metrics.set_gauge("opspilot_uptime_seconds", metrics.uptime_seconds())
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")


app.include_router(api_router, prefix=settings.api_v1_prefix)
