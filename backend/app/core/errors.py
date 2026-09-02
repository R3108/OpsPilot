"""Typed application errors mapped to HTTP responses by a single handler."""

from __future__ import annotations

from typing import Any


class OpsPilotError(Exception):
    """Base class for every error OpsPilot raises deliberately."""

    status_code: int = 500
    code: str = "internal_error"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"error": {"code": self.code, "message": self.message}}
        if self.details:
            payload["error"]["details"] = self.details
        return payload


class NotFoundError(OpsPilotError):
    status_code = 404
    code = "not_found"


class ConflictError(OpsPilotError):
    status_code = 409
    code = "conflict"


class ValidationError(OpsPilotError):
    status_code = 422
    code = "validation_error"


class AuthenticationError(OpsPilotError):
    status_code = 401
    code = "unauthenticated"


class PermissionDeniedError(OpsPilotError):
    status_code = 403
    code = "permission_denied"


class RateLimitedError(OpsPilotError):
    status_code = 429
    code = "rate_limited"


class IntegrationError(OpsPilotError):
    """An upstream provider (K8s, Prometheus, GitHub, ...) failed."""

    status_code = 502
    code = "integration_error"


class IntegrationTimeoutError(IntegrationError):
    status_code = 504
    code = "integration_timeout"


class PolicyViolationError(OpsPilotError):
    """A proposed action was rejected by the deterministic policy engine."""

    status_code = 403
    code = "policy_violation"


class ApprovalRequiredError(OpsPilotError):
    status_code = 428
    code = "approval_required"


class UnknownActionError(OpsPilotError):
    """The model proposed an action key that is not in the signed catalog."""

    status_code = 400
    code = "unknown_action"
