"""Structured logging with request/tenant correlation and secret redaction."""

from __future__ import annotations

import logging
import re
import sys
from contextvars import ContextVar
from typing import Any

import structlog

from app.core.config import settings

request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
tenant_id_ctx: ContextVar[str | None] = ContextVar("tenant_id", default=None)
user_id_ctx: ContextVar[str | None] = ContextVar("user_id", default=None)
incident_id_ctx: ContextVar[str | None] = ContextVar("incident_id", default=None)

_SENSITIVE_KEYS = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|authorization|credential|private[_-]?key|"
    r"encryption[_-]?key|signing[_-]?secret|webhook[_-]?secret|bearer)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]+", re.IGNORECASE)
_LONG_TOKEN = re.compile(r"\b(sk-|xoxb-|xoxp-|ghp_|github_pat_|AKIA)[A-Za-z0-9_\-]{8,}\b")

REDACTED = "***redacted***"


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        value = _BEARER.sub(r"\1" + REDACTED, value)
        return _LONG_TOKEN.sub(REDACTED, value)
    if isinstance(value, dict):
        return _redact_mapping(value)
    if isinstance(value, (list, tuple)):
        return type(value)(_redact_value(v) for v in value)
    return value


def _redact_mapping(data: dict[Any, Any]) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    for key, value in data.items():
        if isinstance(key, str) and _SENSITIVE_KEYS.search(key):
            out[key] = REDACTED
        else:
            out[key] = _redact_value(value)
    return out


def redact(data: Any) -> Any:
    """Public helper: scrub secrets out of anything before it is logged or traced."""
    return _redact_value(data)


def _redaction_processor(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    return _redact_mapping(event_dict)


def _context_processor(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for name, var in (
        ("request_id", request_id_ctx),
        ("tenant_id", tenant_id_ctx),
        ("user_id", user_id_ctx),
        ("incident_id", incident_id_ctx),
    ):
        value = var.get()
        if value is not None:
            event_dict.setdefault(name, value)
    return event_dict


def configure_logging() -> None:
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio", "kubernetes_asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if settings.is_production
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            _context_processor,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            _redaction_processor,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
