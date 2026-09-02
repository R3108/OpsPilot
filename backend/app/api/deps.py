"""Request dependencies: authentication, tenant scoping and RBAC.

Every authenticated route resolves to a :class:`Principal`, which carries the
tenant id. Handlers filter by ``principal.tenant_id`` — there is no code path
that queries a tenant-scoped table without it.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.errors import AuthenticationError, PermissionDeniedError, RateLimitedError
from app.core.logging import tenant_id_ctx, user_id_ctx
from app.core.redis_client import rate_limit_ok
from app.core.security import decode_token, hash_api_key, parse_api_key_prefix
from app.models.enums import UserRole, role_satisfies
from app.models.tenant import ApiKey, Tenant, User

bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")

DbSession = Annotated[AsyncSession, Depends(get_db)]


@dataclass(slots=True)
class Principal:
    """Who is making this request."""

    tenant_id: uuid.UUID
    role: UserRole
    kind: str  # "user" | "api_key"
    user: User | None = None
    api_key: ApiKey | None = None

    @property
    def id(self) -> uuid.UUID:
        if self.user is not None:
            return self.user.id
        assert self.api_key is not None
        return self.api_key.id

    @property
    def label(self) -> str:
        if self.user is not None:
            return self.user.full_name or self.user.email
        assert self.api_key is not None
        return f"api-key:{self.api_key.name}"

    @property
    def audit_actor_type(self) -> str:
        return "user" if self.user is not None else "api_key"

    def require_user(self) -> User:
        """Some actions (approvals) must be attributable to a human."""
        if self.user is None:
            raise PermissionDeniedError("This action requires a signed-in user, not an API key")
        return self.user


async def get_principal(
    request: Request,
    session: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Principal:
    principal = (
        await _principal_from_api_key(session, x_api_key)
        if x_api_key
        else await _principal_from_jwt(session, credentials)
    )

    tenant_id_ctx.set(str(principal.tenant_id))
    user_id_ctx.set(str(principal.id))
    request.state.principal = principal
    return principal


async def _principal_from_jwt(
    session: AsyncSession, credentials: HTTPAuthorizationCredentials | None
) -> Principal:
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("Missing bearer token")

    payload = decode_token(credentials.credentials, expected_type="access")
    user = await session.get(User, uuid.UUID(payload["sub"]))
    if user is None or not user.is_active:
        raise AuthenticationError("User not found or deactivated")
    if str(user.tenant_id) != payload["tid"]:
        raise AuthenticationError("Token does not match the user's organisation")

    tenant = await session.get(Tenant, user.tenant_id)
    if tenant is None or not tenant.is_active:
        raise AuthenticationError("Organisation is inactive")

    # The token's role is a snapshot; the database is authoritative, so a
    # demotion takes effect immediately rather than at token expiry.
    return Principal(tenant_id=user.tenant_id, role=user.role, kind="user", user=user)


async def _principal_from_api_key(session: AsyncSession, raw_key: str) -> Principal:
    prefix = parse_api_key_prefix(raw_key)
    if prefix is None:
        raise AuthenticationError("Malformed API key")

    api_key = (
        await session.execute(select(ApiKey).where(ApiKey.prefix == prefix))
    ).scalar_one_or_none()
    if api_key is None or not api_key.is_active:
        raise AuthenticationError("Invalid API key")
    if api_key.key_hash != hash_api_key(raw_key):
        raise AuthenticationError("Invalid API key")
    if api_key.expires_at is not None and api_key.expires_at < datetime.now(UTC):
        raise AuthenticationError("API key has expired")

    tenant = await session.get(Tenant, api_key.tenant_id)
    if tenant is None or not tenant.is_active:
        raise AuthenticationError("Organisation is inactive")

    api_key.last_used_at = datetime.now(UTC)
    return Principal(
        tenant_id=api_key.tenant_id, role=api_key.role, kind="api_key", api_key=api_key
    )


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def require_role(minimum: UserRole) -> Callable[[Principal], Principal]:
    """Dependency factory enforcing a minimum role."""

    async def _dependency(principal: CurrentPrincipal) -> Principal:
        if not role_satisfies(principal.role, minimum):
            raise PermissionDeniedError(
                f"This endpoint requires the '{minimum}' role or above",
                details={"required_role": str(minimum), "your_role": str(principal.role)},
            )
        return principal

    return _dependency


RequireViewer = Annotated[Principal, Depends(require_role(UserRole.VIEWER))]
RequireResponder = Annotated[Principal, Depends(require_role(UserRole.RESPONDER))]
RequireApprover = Annotated[Principal, Depends(require_role(UserRole.APPROVER))]
RequireAdmin = Annotated[Principal, Depends(require_role(UserRole.ADMIN))]
RequireOwner = Annotated[Principal, Depends(require_role(UserRole.OWNER))]


def rate_limit(*, limit: int, window_seconds: int = 60, scope: str = "default"):
    """Per-principal fixed-window rate limit."""

    async def _dependency(principal: CurrentPrincipal) -> None:
        ok, count = await rate_limit_ok(
            f"{scope}:{principal.tenant_id}:{principal.id}",
            limit=limit,
            window_seconds=window_seconds,
        )
        if not ok:
            raise RateLimitedError(
                f"Rate limit exceeded: {limit} requests per {window_seconds}s",
                details={"scope": scope, "observed": count},
            )

    return Depends(_dependency)


def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
