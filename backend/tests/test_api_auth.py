"""Authentication, RBAC and — most importantly — tenant isolation."""

from __future__ import annotations

import uuid

from conftest import auth_headers_for
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import UserRole
from app.models.tenant import User


async def test_signup_creates_tenant_and_owner(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/signup",
        json={
            "organization_name": "Acme Corp",
            "email": "founder@acme.dev",
            "password": "a-good-password-1",
            "full_name": "Ada",
        },
    )
    assert response.status_code == 201
    tokens = response.json()
    assert tokens["access_token"] and tokens["refresh_token"]

    session_response = await client.get(
        "/api/v1/auth/session",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert session_response.status_code == 200
    body = session_response.json()
    assert body["user"]["role"] == "owner"
    assert body["tenant"]["slug"] == "acme-corp"


async def test_weak_password_is_refused(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/signup",
        json={
            "organization_name": "Weak",
            "email": "weak@test.dev",
            "password": "alllettersonly",
        },
    )
    assert response.status_code == 422


async def test_login_and_refresh(client: AsyncClient) -> None:
    await client.post(
        "/api/v1/auth/signup",
        json={
            "organization_name": "Login Co",
            "email": "user@login.dev",
            "password": "a-good-password-1",
        },
    )
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@login.dev", "password": "a-good-password-1"},
    )
    assert login.status_code == 200

    refreshed = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login.json()["refresh_token"]},
    )
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"]


async def test_refresh_rotates_and_burns_the_old_token(client: AsyncClient) -> None:
    """A refresh token is single-use: reuse after rotation is rejected."""
    await client.post(
        "/api/v1/auth/signup",
        json={
            "organization_name": "Rotate Co",
            "email": "user@rotate.dev",
            "password": "a-good-password-1",
        },
    )
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@rotate.dev", "password": "a-good-password-1"},
    )
    first_refresh = login.json()["refresh_token"]

    rotated = await client.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh})
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != first_refresh

    replay = await client.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh})
    assert replay.status_code == 401


async def test_logout_revokes_the_refresh_token(client: AsyncClient) -> None:
    await client.post(
        "/api/v1/auth/signup",
        json={
            "organization_name": "Logout Co",
            "email": "user@logout.dev",
            "password": "a-good-password-1",
        },
    )
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@logout.dev", "password": "a-good-password-1"},
    )
    refresh_token = login.json()["refresh_token"]

    logged_out = await client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token})
    assert logged_out.status_code == 200

    reuse = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert reuse.status_code == 401


async def test_unknown_refresh_token_is_rejected(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "not-a-real-token"},
    )
    assert response.status_code in (401, 422)


async def test_wrong_password_is_rejected(client: AsyncClient) -> None:
    await client.post(
        "/api/v1/auth/signup",
        json={
            "organization_name": "Secure Co",
            "email": "user@secure.dev",
            "password": "a-good-password-1",
        },
    )
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@secure.dev", "password": "wrong-password-9"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


async def test_unknown_email_is_rejected_without_disclosure(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@nowhere.dev", "password": "a-good-password-1"},
    )
    assert response.status_code == 401
    # Same message as a wrong password: no account enumeration.
    assert response.json()["error"]["message"] == "Incorrect email or password"


async def test_missing_token_is_rejected(client: AsyncClient) -> None:
    response = await client.get("/api/v1/incidents")
    assert response.status_code == 401


# --------------------------------------------------------------------- RBAC
async def test_viewer_cannot_create_incidents(client: AsyncClient, users: dict[str, User]) -> None:
    response = await client.post(
        "/api/v1/incidents",
        json={"title": "Something is broken"},
        headers=auth_headers_for(users["viewer"]),
    )
    assert response.status_code == 403
    assert response.json()["error"]["details"]["required_role"] == "responder"


async def test_responder_can_create_incidents(client: AsyncClient, users: dict[str, User]) -> None:
    response = await client.post(
        "/api/v1/incidents",
        json={"title": "Something is broken", "auto_investigate": False},
        headers=auth_headers_for(users["responder"]),
    )
    assert response.status_code == 201


async def test_responder_cannot_manage_users(client: AsyncClient, users: dict[str, User]) -> None:
    response = await client.post(
        "/api/v1/auth/users",
        json={"email": "new@test.dev", "password": "a-good-password-1"},
        headers=auth_headers_for(users["responder"]),
    )
    assert response.status_code == 403


async def test_admin_can_create_users_but_not_owners(
    client: AsyncClient, users: dict[str, User]
) -> None:
    ok = await client.post(
        "/api/v1/auth/users",
        json={
            "email": "responder2@test.dev",
            "password": "a-good-password-1",
            "role": "responder",
        },
        headers=auth_headers_for(users["admin"]),
    )
    assert ok.status_code == 201

    refused = await client.post(
        "/api/v1/auth/users",
        json={"email": "owner2@test.dev", "password": "a-good-password-1", "role": "owner"},
        headers=auth_headers_for(users["admin"]),
    )
    assert refused.status_code == 409


async def test_user_cannot_change_their_own_role(
    client: AsyncClient, users: dict[str, User]
) -> None:
    admin = users["admin"]
    response = await client.patch(
        f"/api/v1/auth/users/{admin.id}",
        json={"role": "owner"},
        headers=auth_headers_for(admin),
    )
    assert response.status_code == 409


async def test_role_change_takes_effect_immediately(
    client: AsyncClient, session: AsyncSession, users: dict[str, User]
) -> None:
    """A demotion must not wait for the old token to expire."""
    responder = users["responder"]
    headers = auth_headers_for(responder)

    assert (
        await client.post(
            "/api/v1/incidents",
            json={"title": "before demotion", "auto_investigate": False},
            headers=headers,
        )
    ).status_code == 201

    responder.role = UserRole.VIEWER
    await session.commit()

    after = await client.post(
        "/api/v1/incidents",
        json={"title": "after demotion", "auto_investigate": False},
        headers=headers,
    )
    assert after.status_code == 403


async def test_deactivated_user_is_locked_out(
    client: AsyncClient, session: AsyncSession, users: dict[str, User]
) -> None:
    admin = users["admin"]
    headers = auth_headers_for(admin)
    admin.is_active = False
    await session.commit()

    response = await client.get("/api/v1/incidents", headers=headers)
    assert response.status_code == 401


# ----------------------------------------------------------- tenant isolation
async def test_tenants_cannot_see_each_others_incidents(client: AsyncClient) -> None:
    async def make_org(name: str, email: str) -> str:
        response = await client.post(
            "/api/v1/auth/signup",
            json={
                "organization_name": name,
                "email": email,
                "password": "a-good-password-1",
            },
        )
        return response.json()["access_token"]

    token_a = await make_org("Org A", "a@a.dev")
    token_b = await make_org("Org B", "b@b.dev")

    created = await client.post(
        "/api/v1/incidents",
        json={"title": "Org A secret incident", "auto_investigate": False},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    incident_id = created.json()["id"]

    listed_b = await client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token_b}"})
    assert listed_b.json()["total"] == 0

    fetched_b = await client.get(
        f"/api/v1/incidents/{incident_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert fetched_b.status_code == 404, "cross-tenant read must 404, not 403"


async def test_token_from_another_tenant_is_rejected(
    client: AsyncClient, session: AsyncSession, users: dict[str, User]
) -> None:
    """A token whose tenant claim does not match the user's is invalid."""
    from app.core.security import create_token

    user = users["admin"]
    forged = create_token(subject=str(user.id), tenant_id=str(uuid.uuid4()), role="admin")
    response = await client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


# --------------------------------------------------------------------- api keys
async def test_api_key_lifecycle(auth_client: AsyncClient) -> None:
    created = await auth_client.post(
        "/api/v1/auth/api-keys", json={"name": "alertmanager", "role": "responder"}
    )
    assert created.status_code == 201
    body = created.json()
    plaintext = body["key"]
    assert plaintext.startswith("opk_")

    # The plaintext must never appear again in a listing.
    listed = await auth_client.get("/api/v1/auth/api-keys")
    assert all(plaintext not in str(item) for item in listed.json())

    # The key authenticates.
    ingested = await auth_client.post(
        "/api/v1/incidents",
        json={"title": "from an api key", "auto_investigate": False},
        headers={"X-API-Key": plaintext, "Authorization": ""},
    )
    assert ingested.status_code == 201

    revoked = await auth_client.delete(f"/api/v1/auth/api-keys/{body['id']}")
    assert revoked.status_code == 200

    after = await auth_client.post(
        "/api/v1/incidents",
        json={"title": "after revocation", "auto_investigate": False},
        headers={"X-API-Key": plaintext, "Authorization": ""},
    )
    assert after.status_code == 401


async def test_api_keys_cannot_hold_owner_role(auth_client: AsyncClient) -> None:
    response = await auth_client.post(
        "/api/v1/auth/api-keys", json={"name": "too-powerful", "role": "owner"}
    )
    assert response.status_code == 409


async def test_api_key_cannot_approve(client: AsyncClient, auth_client: AsyncClient) -> None:
    """Approvals require an attributable human, never a machine credential."""
    created = await auth_client.post("/api/v1/auth/api-keys", json={"name": "bot", "role": "admin"})
    key = created.json()["key"]

    response = await auth_client.post(
        f"/api/v1/approvals/{uuid.uuid4()}/decision",
        json={"decision": "approve"},
        headers={"X-API-Key": key, "Authorization": ""},
    )
    assert response.status_code in (403, 404)
    if response.status_code == 403:
        assert "signed-in user" in response.json()["error"]["message"]
