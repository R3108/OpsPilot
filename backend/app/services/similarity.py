"""Historical incident similarity.

Two backends behind one function:

* **Vector** — when a tenant has embeddings stored (pgvector on Postgres), we
  rank by cosine distance.
* **Lexical** — otherwise, an IDF-weighted token overlap over title, description,
  labels, service and recorded root cause.

The lexical path is not a placeholder: incident text is short, highly templated
and dominated by rare technical tokens ("OOMKilled", "pg_stat_activity"), which
is exactly where IDF-weighted overlap performs well. It also means the history
investigator works on day one, before any embedding backfill has run.
"""

from __future__ import annotations

import math
import re
import uuid
from collections import Counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.enums import IncidentStatus
from app.models.incident import Incident
from app.models.knowledge import IncidentEmbedding

log = get_logger(__name__)

_TOKEN = re.compile(r"[a-z0-9_]{3,}")

# Words that appear in nearly every incident and carry no discriminating signal.
STOPWORDS = frozenset(
    [
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "are",
        "was",
        "were",
        "has",
        "have",
        "had",
        "not",
        "but",
        "you",
        "your",
        "all",
        "can",
        "will",
        "been",
        "being",
        "into",
        "out",
        "over",
        "under",
        "about",
        "after",
        "before",
        "during",
        "then",
        "than",
        "when",
        "what",
        "which",
        "who",
        "how",
        "why",
        "service",
        "error",
        "incident",
        "alert",
        "issue",
        "problem",
        "failure",
        "production",
        "prod",
        "high",
        "low",
        "new",
        "old",
        "get",
        "set",
        "use",
        "using",
        "used",
        "run",
        "running",
    ]
)


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall((text or "").lower()) if t not in STOPWORDS]


def incident_document(incident: Incident, *, root_cause: str | None = None) -> str:
    parts = [
        incident.title,
        incident.description,
        incident.service or "",
        incident.namespace or "",
        str(incident.source),
        " ".join(f"{k} {v}" for k, v in (incident.labels or {}).items()),
        root_cause or incident.root_cause_summary or "",
    ]
    return " ".join(p for p in parts if p)


async def find_similar_incidents(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident: Incident,
    limit: int = 5,
    min_score: float = 0.15,
) -> list[dict[str, Any]]:
    """Rank previously resolved incidents by similarity to ``incident``."""
    vector_hits = await _vector_search(session, tenant_id=tenant_id, incident=incident, limit=limit)
    if vector_hits:
        return vector_hits

    stmt = (
        select(Incident)
        .where(
            Incident.tenant_id == tenant_id,
            Incident.id != incident.id,
            Incident.status.in_([IncidentStatus.RESOLVED, IncidentStatus.CLOSED]),
        )
        .order_by(Incident.resolved_at.desc().nullslast())
        .limit(300)  # bounded corpus keeps this cheap during an active incident
    )
    candidates = list((await session.execute(stmt)).scalars().all())
    if not candidates:
        return []

    corpus = [tokenize(incident_document(c)) for c in candidates]
    idf = _build_idf(corpus)
    query_tokens = tokenize(incident_document(incident))
    if not query_tokens:
        return []

    scored: list[tuple[float, Incident, list[str]]] = []
    for candidate, tokens in zip(candidates, corpus, strict=True):
        score, overlap = _weighted_overlap(query_tokens, tokens, idf)
        # Same-service incidents are materially more likely to recur the same way.
        if candidate.service and candidate.service == incident.service:
            score = min(1.0, score * 1.25)
        if score >= min_score:
            scored.append((score, candidate, overlap))

    scored.sort(key=lambda row: row[0], reverse=True)
    return [
        {
            "score": round(score, 4),
            "method": "lexical",
            "reason": "shared terms: " + ", ".join(overlap[:6]),
            "incident": {
                "id": str(candidate.id),
                "reference": candidate.reference,
                "title": candidate.title,
                "severity": str(candidate.severity),
                "service": candidate.service,
                "root_cause_summary": candidate.root_cause_summary,
                "resolved_at": candidate.resolved_at.isoformat() if candidate.resolved_at else None,
                "time_to_resolve_seconds": candidate.time_to_resolve_seconds,
            },
        }
        for score, candidate, overlap in scored[:limit]
    ]


def _build_idf(corpus: list[list[str]]) -> dict[str, float]:
    document_count = len(corpus) or 1
    frequencies: Counter[str] = Counter()
    for tokens in corpus:
        frequencies.update(set(tokens))
    return {
        token: math.log((document_count + 1) / (count + 1)) + 1.0
        for token, count in frequencies.items()
    }


def _weighted_overlap(
    query: list[str], candidate: list[str], idf: dict[str, float]
) -> tuple[float, list[str]]:
    """Cosine similarity over IDF-weighted term-frequency vectors."""
    query_counts = Counter(query)
    candidate_counts = Counter(candidate)

    shared = set(query_counts) & set(candidate_counts)
    if not shared:
        return 0.0, []

    numerator = sum(query_counts[t] * candidate_counts[t] * (idf.get(t, 1.0) ** 2) for t in shared)
    query_norm = math.sqrt(sum((c * idf.get(t, 1.0)) ** 2 for t, c in query_counts.items()))
    candidate_norm = math.sqrt(sum((c * idf.get(t, 1.0)) ** 2 for t, c in candidate_counts.items()))
    if not query_norm or not candidate_norm:
        return 0.0, []

    score = numerator / (query_norm * candidate_norm)
    ranked = sorted(shared, key=lambda t: idf.get(t, 1.0), reverse=True)
    return score, ranked


async def _vector_search(
    session: AsyncSession, *, tenant_id: uuid.UUID, incident: Incident, limit: int
) -> list[dict[str, Any]]:
    """Cosine ranking over stored embeddings, when they exist."""
    embedding = await embed_incident(incident)
    if embedding is None:
        return []

    rows = list(
        (
            await session.execute(
                select(IncidentEmbedding).where(
                    IncidentEmbedding.tenant_id == tenant_id,
                    IncidentEmbedding.incident_id != incident.id,
                )
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return []

    scored = []
    for row in rows:
        stored = row.embedding or []
        if len(stored) != len(embedding):
            continue
        score = _cosine(embedding, list(stored))
        if score >= 0.5:
            scored.append((score, row))

    scored.sort(key=lambda item: item[0], reverse=True)
    return [
        {
            "score": round(score, 4),
            "method": "vector",
            "reason": f"embedding cosine similarity ({row.model})",
            "incident": row.snapshot,
        }
        for score, row in scored[:limit]
    ]


def _cosine(a: list[float], b: list[float]) -> float:
    numerator = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    return numerator / (norm_a * norm_b) if norm_a and norm_b else 0.0


async def embed_incident(incident: Incident) -> list[float] | None:
    """Hook for an embedding provider.

    Returns ``None`` today, which routes every caller down the lexical path. Wire
    a provider here (and backfill :class:`IncidentEmbedding`) to switch the
    history investigator to vector search without touching its call site.
    """
    return None


async def store_incident_embedding(
    session: AsyncSession, incident: Incident, *, root_cause: str | None = None
) -> IncidentEmbedding | None:
    """Index a resolved incident so future investigations can find it."""
    embedding = await embed_incident(incident)
    if embedding is None:
        return None

    existing = (
        await session.execute(
            select(IncidentEmbedding).where(IncidentEmbedding.incident_id == incident.id)
        )
    ).scalar_one_or_none()

    snapshot = {
        "id": str(incident.id),
        "reference": incident.reference,
        "title": incident.title,
        "severity": str(incident.severity),
        "service": incident.service,
        "root_cause_summary": root_cause or incident.root_cause_summary,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
    }
    content = incident_document(incident, root_cause=root_cause)

    if existing is not None:
        existing.embedding = embedding
        existing.content = content
        existing.snapshot = snapshot
        return existing

    row = IncidentEmbedding(
        tenant_id=incident.tenant_id,
        incident_id=incident.id,
        content=content,
        embedding=embedding,
        dimensions=len(embedding),
        snapshot=snapshot,
    )
    session.add(row)
    return row
