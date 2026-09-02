"""Action catalog.

Importing this package is what populates :data:`ACTION_REGISTRY`. Every module
listed below registers its actions at import time, so adding a new action means
adding it to a module here — there is no dynamic discovery and no way to inject
an action at runtime.
"""

from app.services.actions import database, deployment, kubernetes, notify  # noqa: F401
from app.services.actions.registry import (
    ACTION_REGISTRY,
    ActionSpec,
    BlastRadius,
    ExecutionContext,
    ExecutionResult,
    catalog_for_prompt,
    get_action,
    list_actions,
    register_action,
    registry_fingerprint,
)

__all__ = [
    "ACTION_REGISTRY",
    "ActionSpec",
    "BlastRadius",
    "ExecutionContext",
    "ExecutionResult",
    "catalog_for_prompt",
    "get_action",
    "list_actions",
    "register_action",
    "registry_fingerprint",
]
