from fastapi import APIRouter

from app.api.v1 import (
    approvals,
    audit,
    auth,
    catalog,
    dashboard,
    incidents,
    integrations,
    stream,
    webhooks,
)

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(incidents.router)
api_router.include_router(approvals.router)
api_router.include_router(catalog.router)
api_router.include_router(integrations.router)
api_router.include_router(dashboard.router)
api_router.include_router(audit.router)
api_router.include_router(stream.router)
# Webhooks last: they authenticate per-integration, not per-principal.
api_router.include_router(webhooks.router)
