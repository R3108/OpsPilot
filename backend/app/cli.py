"""Operational CLI: ``python -m app.cli <command>``.

Commands
--------
``keys``        generate a SECRET_KEY / ENCRYPTION_KEY pair for .env
``init-db``     create tables directly (dev only; production uses Alembic)
``seed``        create the demo tenant, user, integrations and incidents
``catalog``     print the action catalog as the agent sees it
``investigate`` run an investigation for one incident, inline
``health``      check database and Redis connectivity
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.config import settings
from app.core.crypto import generate_kek
from app.core.db import (
    dispose_engine,
    get_engine,
    session_scope,
    use_compatible_event_loop,
)
from app.core.logging import configure_logging, get_logger
from app.core.security import hash_password
from app.models import Base
from app.models.enums import (
    IncidentSeverity,
    IncidentStatus,
    TenantPlan,
    UserRole,
)
from app.models.incident import Incident
from app.models.knowledge import Runbook
from app.models.remediation import PolicyRule
from app.models.tenant import Tenant, User

log = get_logger(__name__)

DEMO_SLUG = "acme"
DEMO_EMAIL = "admin@opspilot.dev"
DEMO_PASSWORD = "opspilot"  # noqa: S105 - documented demo credential


def cmd_keys() -> int:
    print("# Add these to your .env")  # noqa: T201
    print(f"SECRET_KEY={secrets.token_urlsafe(48)}")  # noqa: T201
    print(f"ENCRYPTION_KEY={generate_kek()}")  # noqa: T201
    return 0


async def cmd_init_db() -> int:
    if settings.is_production:
        print("Refusing to create tables directly in production; use alembic.")  # noqa: T201
        return 1
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print(f"Created {len(Base.metadata.tables)} tables on {_safe_url()}")  # noqa: T201
    return 0


async def cmd_health() -> int:
    from app.core.db import check_database
    from app.core.redis_client import check_redis

    database_ok = await check_database()
    redis_ok = await check_redis()
    print(f"database: {'ok' if database_ok else 'UNREACHABLE'}  ({_safe_url()})")  # noqa: T201
    print(f"redis:    {'ok' if redis_ok else 'UNREACHABLE'}")  # noqa: T201
    return 0 if (database_ok and redis_ok) else 1


def cmd_catalog() -> int:
    from app.services.actions import catalog_for_prompt, list_actions, registry_fingerprint

    print(catalog_for_prompt())  # noqa: T201
    print()  # noqa: T201
    print(  # noqa: T201
        f"{len(list_actions())} actions, catalog fingerprint {registry_fingerprint()}"
    )
    return 0


async def cmd_seed(*, reset: bool = False) -> int:
    """Create a demo organisation with simulated integrations and incidents."""
    from app.evals.dataset import (
        create_scenario_incident,
        load_scenarios,
        provision_scenario,
    )

    async with session_scope() as session:
        tenant = (
            await session.execute(select(Tenant).where(Tenant.slug == DEMO_SLUG))
        ).scalar_one_or_none()

        if tenant is not None and reset:
            await session.delete(tenant)
            await session.flush()
            tenant = None

        if tenant is None:
            tenant = Tenant(
                name="Acme Corp",
                slug=DEMO_SLUG,
                plan=TenantPlan.ENTERPRISE,
                settings_json={
                    "policy": {
                        "auto_approve_low_risk": True,
                        "always_approve_at_or_above": "medium",
                        "protected_namespaces": ["kube-system", "istio-system"],
                        "max_actions_per_incident": 5,
                        "min_confidence_high_risk": 0.5,
                    }
                },
            )
            session.add(tenant)
            await session.flush()
            print(f"Created tenant {tenant.name} ({tenant.slug})")  # noqa: T201

        users = [
            (DEMO_EMAIL, "Ada Ops", UserRole.OWNER),
            ("approver@opspilot.dev", "Grace Approver", UserRole.APPROVER),
            ("responder@opspilot.dev", "Rae Responder", UserRole.RESPONDER),
            ("viewer@opspilot.dev", "Vic Viewer", UserRole.VIEWER),
        ]
        for email, name, role in users:
            existing = (
                await session.execute(
                    select(User).where(User.tenant_id == tenant.id, User.email == email)
                )
            ).scalar_one_or_none()
            if existing is None:
                session.add(
                    User(
                        tenant_id=tenant.id,
                        email=email,
                        full_name=name,
                        password_hash=hash_password(DEMO_PASSWORD),
                        role=role,
                    )
                )
        await session.flush()

        # A couple of guardrails so the policy page is not empty.
        if not (
            await session.execute(select(PolicyRule.id).where(PolicyRule.tenant_id == tenant.id))
        ).first():
            session.add_all(
                [
                    PolicyRule(
                        tenant_id=tenant.id,
                        name="Never touch the payments namespace automatically",
                        description=(
                            "Payments is PCI scope; every change there goes through "
                            "the change process, not the agent."
                        ),
                        priority=10,
                        match={"namespaces": ["payments"], "min_risk_tier": "high"},
                        effect="require_approval",
                        required_role="admin",
                        reason="PCI scope requires an admin approver",
                    ),
                    PolicyRule(
                        tenant_id=tenant.id,
                        name="No scaling to zero in production",
                        description="Scaling to zero is an outage, not a remediation.",
                        priority=5,
                        match={
                            "action_keys": ["k8s.scale_deployment"],
                            "environments": ["production"],
                        },
                        effect="require_approval",
                        limits={"max_replica_delta": 8},
                        reason="Replica changes in production need a human",
                    ),
                ]
            )

        if not (
            await session.execute(select(Runbook.id).where(Runbook.tenant_id == tenant.id))
        ).first():
            session.add(
                Runbook(
                    tenant_id=tenant.id,
                    title="Checkout API: connection pool exhaustion",
                    service="checkout-api",
                    tags=["database", "postgres", "pool"],
                    symptoms=(
                        "500s from checkout-api with 'too many clients already' or "
                        "connection acquisition timeouts."
                    ),
                    content_markdown=(
                        "## Connection pool exhaustion\n\n"
                        "1. Check `pg_stat_activity` for backends in "
                        "`idle in transaction`.\n"
                        "2. If the nightly reconciler is holding them, terminating "
                        "those backends is safe — it is idempotent and re-runs.\n"
                        "3. Escalate to the payments team to fix the leaked "
                        "transaction properly.\n"
                    ),
                    suggested_action_keys=["db.terminate_idle_connections"],
                )
            )

        # Simulated integrations + one incident per scenario.
        scenarios = load_scenarios()
        created = []
        for scenario in scenarios:
            await provision_scenario(session, tenant=tenant, scenario=scenario)
            existing = (
                await session.execute(
                    select(Incident).where(
                        Incident.tenant_id == tenant.id,
                        Incident.title == scenario.incident["title"],
                    )
                )
            ).scalar_one_or_none()
            if existing is None:
                incident = await create_scenario_incident(session, tenant=tenant, scenario=scenario)
                created.append(incident.reference)

        # One already-closed incident so the dashboard and the history
        # investigator have something to work with on a fresh install.
        await _seed_historical(session, tenant)

    print(f"Seeded tenant '{DEMO_SLUG}' with {len(scenarios)} scenario integrations")  # noqa: T201
    if created:
        print(f"Created incidents: {', '.join(created)}")  # noqa: T201
    print()  # noqa: T201
    print(f"Log in at the web app with {DEMO_EMAIL} / {DEMO_PASSWORD}")  # noqa: T201
    print("Then open an incident and click 'Investigate'.")  # noqa: T201
    return 0


async def _seed_historical(session, tenant: Tenant) -> None:  # noqa: ANN001
    """A resolved incident from three weeks ago.

    Gives the dashboard something to compute MTTR from, and gives the history
    investigator a real precedent to find on a fresh install.
    """
    from app.models.incident import TimelineEntry
    from app.services.incidents import next_reference

    existing = (
        await session.execute(
            select(Incident).where(
                Incident.tenant_id == tenant.id, Incident.status == IncidentStatus.CLOSED
            )
        )
    ).first()
    if existing:
        return

    detected = datetime.now(UTC) - timedelta(days=21)
    incident = Incident(
        tenant_id=tenant.id,
        # Allocated, not hardcoded: the scenario incidents above have already
        # taken the low references.
        reference=await next_reference(session, tenant.id),
        title="Checkout API 500s from exhausted database connection pool",
        description=(
            "Checkout error rate reached 28%. Root cause was a leaked transaction in "
            "the nightly reconciler holding 70+ backends idle in transaction."
        ),
        status=IncidentStatus.CLOSED,
        severity=IncidentSeverity.SEV1,
        service="checkout-api",
        namespace="payments",
        environment="production",
        labels={"database": "checkout_prod", "team": "payments"},
        detected_at=detected,
        acknowledged_at=detected + timedelta(minutes=2),
        mitigated_at=detected + timedelta(minutes=14),
        resolved_at=detected + timedelta(minutes=17),
        closed_at=detected + timedelta(minutes=40),
        root_cause_summary=(
            "Leaked transactions in the nightly reconciler exhausted the connection pool"
        ),
        root_cause_confidence=0.91,
        dedupe_key="historical:checkout-pool-exhaustion",
    )
    session.add(incident)
    await session.flush()
    session.add(
        TimelineEntry(
            tenant_id=tenant.id,
            incident_id=incident.id,
            occurred_at=detected + timedelta(minutes=14),
            actor_type="agent",
            actor_label="OpsPilot Agent",
            title="Terminated 71 idle-in-transaction backends",
            body="Connection saturation fell from 99% to 26% within 40 seconds.",
        )
    )


async def cmd_investigate(incident_ref: str) -> int:
    from app.services import investigations

    async with session_scope() as session:
        stmt = select(Incident)
        try:
            stmt = stmt.where(Incident.id == uuid.UUID(incident_ref))
        except ValueError:
            stmt = stmt.where(Incident.reference == incident_ref)
        # References are only unique per tenant, so a bare "INC-0001" can match
        # several incidents once eval tenants exist alongside the demo one.
        matches = list((await session.execute(stmt)).scalars().all())
        if not matches:
            print(f"No incident matching '{incident_ref}'")  # noqa: T201
            return 1
        if len(matches) > 1:
            print(f"'{incident_ref}' matches {len(matches)} incidents; pass the uuid:")  # noqa: T201
            for match in matches:
                print(f"  {match.id}  tenant={match.tenant_id}  {match.title[:60]}")  # noqa: T201
            return 1
        incident = matches[0]
        incident_id, tenant_id, reference = incident.id, incident.tenant_id, incident.reference

    print(f"Investigating {reference} ...")  # noqa: T201
    outcome = await investigations.start_investigation(
        incident_id=incident_id, tenant_id=tenant_id, triggered_by="cli"
    )
    print(f"status: {outcome['status']}")  # noqa: T201
    for key, value in (outcome.get("state") or {}).items():
        print(f"  {key}: {value}")  # noqa: T201
    if outcome["status"] == "awaiting_approval":
        print()  # noqa: T201
        print("Paused for human approval. Approve in the web app or via:")  # noqa: T201
        print("  POST /api/v1/approvals/{approval_id}/decision")  # noqa: T201
    return 0


def _safe_url() -> str:
    url = settings.database_url
    if "@" in url:
        scheme, _, rest = url.partition("://")
        return f"{scheme}://***@{rest.split('@', 1)[1]}"
    return url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="opspilot", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("keys", help="generate SECRET_KEY and ENCRYPTION_KEY")
    sub.add_parser("init-db", help="create tables (dev only)")
    sub.add_parser("health", help="check database and Redis")
    sub.add_parser("catalog", help="print the action catalog")

    seed = sub.add_parser("seed", help="seed the demo organisation")
    seed.add_argument("--reset", action="store_true", help="delete and recreate it")

    investigate = sub.add_parser("investigate", help="run an investigation inline")
    investigate.add_argument("incident", help="incident reference (INC-0002) or uuid")

    args = parser.parse_args(argv)
    configure_logging()
    use_compatible_event_loop()

    if args.command == "keys":
        return cmd_keys()
    if args.command == "catalog":
        return cmd_catalog()

    async def _run() -> int:
        try:
            if args.command == "init-db":
                return await cmd_init_db()
            if args.command == "health":
                return await cmd_health()
            if args.command == "seed":
                return await cmd_seed(reset=args.reset)
            if args.command == "investigate":
                return await cmd_investigate(args.incident)
        finally:
            await dispose_engine()
        return 1  # pragma: no cover

    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
