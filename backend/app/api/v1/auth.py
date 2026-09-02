"""Signup, login, token refresh, user and API-key management."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request, status
from sqlalchemy import func, select

from app.api.deps import (
    CurrentPrincipal,
    DbSession,
    RequireAdmin,
    client_ip,
    rate_limit,
)
from app.core.config import settings
from app.core.errors import AuthenticationError, ConflictError, NotFoundError
from app.core.security import (
    create_token,
    decode_token,
    generate_api_key,
    hash_password,
    verify_password,
)
from app.models.enums import AuditAction, TenantPlan, UserRole
from app.models.tenant import ApiKey, Tenant, User
from app.schemas.auth import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    LoginRequest,
    RefreshRequest,
    SessionOut,
    SignupRequest,
    TenantOut,
    TokenPair,
    UserCreate,
    UserOut,
    UserUpdate,
)
from app.schemas.common import Acknowledgement, Page
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return (slug or "org")[:60]


def _tokens(user: User) -> TokenPair:
    common = {"subject": str(user.id), "tenant_id": str(user.tenant_id), "role": str(user.role)}
    return TokenPair(
        access_token=create_token(**common, token_type="access"),
        refresh_token=create_token(**common, token_type="refresh"),
        expires_in=settings.access_token_ttl_minutes * 60,
    )


@router.post("/signup", response_model=TokenPair, status_code=status.HTTP_201_CREATED)
async def signup(payload: SignupRequest, request: Request, session: DbSession) -> TokenPair:
    """Create an organisation and its first OWNER."""
    base_slug = _slugify(payload.organization_name)
    slug = base_slug
    for suffix in range(1, 100):
        exists = (
            await session.execute(select(Tenant.id).where(Tenant.slug == slug))
        ).scalar_one_or_none()
        if exists is None:
            break
        slug = f"{base_slug}-{suffix}"
    else:  # pragma: no cover
        raise ConflictError("Could not allocate an organisation slug")

    tenant = Tenant(name=payload.organization_name[:200], slug=slug, plan=TenantPlan.FREE)
    session.add(tenant)
    await session.flush()

    user = User(
        tenant_id=tenant.id,
        email=payload.email.lower(),
        full_name=payload.full_name or payload.email.split("@")[0],
        password_hash=hash_password(payload.password),
        role=UserRole.OWNER,
        last_login_at=datetime.now(UTC),
    )
    session.add(user)
    await session.flush()

    await audit.record(
        session,
        tenant_id=tenant.id,
        action=AuditAction.USER_CREATED,
        resource_type="user",
        resource_id=user.id,
        actor_type="user",
        actor_id=user.id,
        actor_label=user.email,
        summary=f"Organisation '{tenant.name}' created with owner {user.email}",
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return _tokens(user)


@router.post("/login", response_model=TokenPair, dependencies=[])
async def login(payload: LoginRequest, request: Request, session: DbSession) -> TokenPair:
    stmt = select(User).where(User.email == payload.email.lower())
    if payload.tenant_slug:
        stmt = stmt.join(Tenant).where(Tenant.slug == payload.tenant_slug)
    users = list((await session.execute(stmt)).scalars().all())

    # Verify against a real hash even when the user does not exist, so response
    # timing does not disclose which emails are registered.
    candidate = users[0] if users else None
    password_ok = verify_password(
        payload.password,
        candidate.password_hash if candidate else hash_password("timing-equalizer-value"),
    )

    if candidate is None or not password_ok or not candidate.is_active:
        if candidate is not None:
            await audit.record(
                session,
                tenant_id=candidate.tenant_id,
                action=AuditAction.USER_LOGIN_FAILED,
                resource_type="user",
                resource_id=candidate.id,
                actor_type="user",
                actor_id=candidate.id,
                actor_label=candidate.email,
                summary="Failed login attempt",
                ip_address=client_ip(request),
                user_agent=request.headers.get("user-agent"),
            )
        raise AuthenticationError("Incorrect email or password")

    if len(users) > 1:
        raise AuthenticationError("This email belongs to several organisations; supply tenant_slug")

    candidate.last_login_at = datetime.now(UTC)
    await audit.record(
        session,
        tenant_id=candidate.tenant_id,
        action=AuditAction.USER_LOGIN,
        resource_type="user",
        resource_id=candidate.id,
        actor_type="user",
        actor_id=candidate.id,
        actor_label=candidate.email,
        summary="Signed in",
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return _tokens(candidate)


@router.post("/refresh", response_model=TokenPair)
async def refresh(payload: RefreshRequest, session: DbSession) -> TokenPair:
    claims = decode_token(payload.refresh_token, expected_type="refresh")
    user = await session.get(User, uuid.UUID(claims["sub"]))
    if user is None or not user.is_active:
        raise AuthenticationError("User not found or deactivated")
    return _tokens(user)


@router.get("/session", response_model=SessionOut)
async def current_session(principal: CurrentPrincipal, session: DbSession) -> SessionOut:
    user = principal.require_user()
    tenant = await session.get(Tenant, principal.tenant_id)
    if tenant is None:  # pragma: no cover
        raise NotFoundError("Organisation not found")
    return SessionOut(user=UserOut.model_validate(user), tenant=TenantOut.model_validate(tenant))


# --------------------------------------------------------------------------
# users
# --------------------------------------------------------------------------
@router.get("/users", response_model=Page[UserOut])
async def list_users(
    principal: CurrentPrincipal, session: DbSession, limit: int = 50, offset: int = 0
) -> Page[UserOut]:
    base = select(User).where(User.tenant_id == principal.tenant_id)
    total = int(
        (await session.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    )
    rows = list(
        (await session.execute(base.order_by(User.created_at).limit(limit).offset(offset)))
        .scalars()
        .all()
    )
    return Page(
        items=[UserOut.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserCreate, principal: RequireAdmin, session: DbSession) -> UserOut:
    existing = (
        await session.execute(
            select(User).where(
                User.tenant_id == principal.tenant_id, User.email == payload.email.lower()
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError("A user with this email already exists in your organisation")

    # Only an owner may mint another owner.
    if payload.role is UserRole.OWNER and principal.role is not UserRole.OWNER:
        raise ConflictError("Only an owner can create another owner")

    user = User(
        tenant_id=principal.tenant_id,
        email=payload.email.lower(),
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    session.add(user)
    await session.flush()

    await audit.record(
        session,
        tenant_id=principal.tenant_id,
        action=AuditAction.USER_CREATED,
        resource_type="user",
        resource_id=user.id,
        actor_type=principal.audit_actor_type,
        actor_id=principal.id,
        actor_label=principal.label,
        summary=f"Created user {user.email} with role {user.role}",
        after={"email": user.email, "role": str(user.role)},
    )
    return UserOut.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID, payload: UserUpdate, principal: RequireAdmin, session: DbSession
) -> UserOut:
    user = await session.get(User, user_id)
    if user is None or user.tenant_id != principal.tenant_id:
        raise NotFoundError("User not found")

    before = {"role": str(user.role), "is_active": user.is_active}

    if payload.role is not None and payload.role != user.role:
        if UserRole.OWNER in (payload.role, user.role) and principal.role is not UserRole.OWNER:
            raise ConflictError("Only an owner can grant or revoke the owner role")
        if user.id == principal.id:
            raise ConflictError("You cannot change your own role")
        user.role = payload.role
    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.external_ids is not None:
        user.external_ids = payload.external_ids
    if payload.is_active is not None:
        if user.id == principal.id and not payload.is_active:
            raise ConflictError("You cannot deactivate your own account")
        user.is_active = payload.is_active

    after = {"role": str(user.role), "is_active": user.is_active}
    if before != after:
        await audit.record(
            session,
            tenant_id=principal.tenant_id,
            action=(
                AuditAction.USER_DISABLED
                if before["is_active"] and not after["is_active"]
                else AuditAction.USER_ROLE_CHANGED
            ),
            resource_type="user",
            resource_id=user.id,
            actor_type=principal.audit_actor_type,
            actor_id=principal.id,
            actor_label=principal.label,
            summary=f"Updated {user.email}: {before} -> {after}",
            before=before,
            after=after,
        )
    return UserOut.model_validate(user)


# --------------------------------------------------------------------------
# api keys
# --------------------------------------------------------------------------
@router.get("/api-keys", response_model=list[ApiKeyOut])
async def list_api_keys(principal: RequireAdmin, session: DbSession) -> list[ApiKeyOut]:
    rows = list(
        (
            await session.execute(
                select(ApiKey)
                .where(ApiKey.tenant_id == principal.tenant_id)
                .order_by(ApiKey.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [ApiKeyOut.model_validate(r) for r in rows]


@router.post(
    "/api-keys",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[rate_limit(limit=10, window_seconds=3600, scope="api_key_create")],
)
async def create_api_key(
    payload: ApiKeyCreate, principal: RequireAdmin, session: DbSession
) -> ApiKeyCreated:
    """The plaintext key is returned exactly once and never stored."""
    if payload.role is UserRole.OWNER:
        raise ConflictError("API keys cannot hold the owner role")

    full_key, prefix, key_hash = generate_api_key()
    api_key = ApiKey(
        tenant_id=principal.tenant_id,
        name=payload.name,
        prefix=prefix,
        key_hash=key_hash,
        role=payload.role,
        expires_at=(
            datetime.now(UTC) + timedelta(days=payload.expires_in_days)
            if payload.expires_in_days
            else None
        ),
    )
    session.add(api_key)
    await session.flush()

    await audit.record(
        session,
        tenant_id=principal.tenant_id,
        action=AuditAction.USER_CREATED,
        resource_type="api_key",
        resource_id=api_key.id,
        actor_type=principal.audit_actor_type,
        actor_id=principal.id,
        actor_label=principal.label,
        summary=f"Created API key '{api_key.name}' with role {api_key.role}",
        after={"name": api_key.name, "prefix": prefix, "role": str(api_key.role)},
    )
    return ApiKeyCreated(**ApiKeyOut.model_validate(api_key).model_dump(), key=full_key)


@router.delete("/api-keys/{key_id}", response_model=Acknowledgement)
async def revoke_api_key(
    key_id: uuid.UUID, principal: RequireAdmin, session: DbSession
) -> Acknowledgement:
    api_key = await session.get(ApiKey, key_id)
    if api_key is None or api_key.tenant_id != principal.tenant_id:
        raise NotFoundError("API key not found")
    api_key.is_active = False
    await audit.record(
        session,
        tenant_id=principal.tenant_id,
        action=AuditAction.USER_DISABLED,
        resource_type="api_key",
        resource_id=api_key.id,
        actor_type=principal.audit_actor_type,
        actor_id=principal.id,
        actor_label=principal.label,
        summary=f"Revoked API key '{api_key.name}'",
    )
    return Acknowledgement(message=f"API key '{api_key.name}' revoked")
