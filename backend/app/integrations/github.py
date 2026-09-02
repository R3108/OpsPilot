"""GitHub client: recent commits, deployments, PRs, and the revert/dispatch writes."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.core.errors import IntegrationError
from app.core.logging import get_logger
from app.integrations.base import HealthReport, HttpProviderClient
from app.models.enums import IntegrationProvider

log = get_logger(__name__)


class GitHubClient(HttpProviderClient):
    provider = IntegrationProvider.GITHUB

    @property
    def base_url(self) -> str:
        return str(self.config.get("base_url") or "https://api.github.com").rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            **super()._headers(),
            "Authorization": f"Bearer {self._credential('token')}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _check_repo_allowed(self, repo: str) -> None:
        """A repo not on the integration's list is simply not addressable."""
        allowed = self.config.get("repos") or []
        if allowed and repo not in allowed:
            raise IntegrationError(
                f"Repository '{repo}' is not configured for this integration",
                details={"allowed": allowed},
            )

    async def health_check(self) -> HealthReport:
        started = time.perf_counter()
        try:
            user = await self._get_json("/user")
        except Exception as exc:  # noqa: BLE001
            return HealthReport(healthy=False, detail=str(exc)[:400])
        return HealthReport(
            healthy=True,
            detail=f"authenticated as {user.get('login', 'unknown')}",
            latency_ms=int((time.perf_counter() - started) * 1000),
            capabilities=["commits", "deployments", "pull_requests", "workflows"],
        )

    # -- read ---------------------------------------------------------------
    async def list_recent_commits(
        self, repo: str, *, hours: int = 24, branch: str | None = None, limit: int = 30
    ) -> list[dict[str, Any]]:
        self._check_repo_allowed(repo)
        since = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
        payload = await self._get_json(
            f"/repos/{repo}/commits", since=since, sha=branch, per_page=min(limit, 100)
        )
        return [
            {
                "sha": c.get("sha"),
                "short_sha": (c.get("sha") or "")[:8],
                "message": (c.get("commit", {}).get("message") or "").strip(),
                "author": (c.get("commit", {}).get("author") or {}).get("name"),
                "author_login": (c.get("author") or {}).get("login"),
                "committed_at": (c.get("commit", {}).get("committer") or {}).get("date"),
                "url": c.get("html_url"),
            }
            for c in payload[:limit]
        ]

    async def get_commit(self, repo: str, sha: str) -> dict[str, Any] | None:
        self._check_repo_allowed(repo)
        try:
            c = await self._get_json(f"/repos/{repo}/commits/{sha}")
        except IntegrationError as exc:
            if (exc.details or {}).get("status") == 404:
                return None
            raise
        stats = c.get("stats") or {}
        return {
            "sha": c.get("sha"),
            "message": (c.get("commit", {}).get("message") or "").strip(),
            "author": (c.get("commit", {}).get("author") or {}).get("name"),
            "committed_at": (c.get("commit", {}).get("committer") or {}).get("date"),
            "additions": stats.get("additions"),
            "deletions": stats.get("deletions"),
            "files": [
                {
                    "filename": f.get("filename"),
                    "status": f.get("status"),
                    "additions": f.get("additions"),
                    "deletions": f.get("deletions"),
                }
                for f in (c.get("files") or [])[:50]
            ],
            "url": c.get("html_url"),
        }

    async def list_deployments(
        self, repo: str, *, environment: str | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        self._check_repo_allowed(repo)
        payload = await self._get_json(
            f"/repos/{repo}/deployments", environment=environment, per_page=min(limit, 100)
        )
        deployments: list[dict[str, Any]] = []
        for d in payload[:limit]:
            statuses = await self._get_json(
                f"/repos/{repo}/deployments/{d['id']}/statuses", per_page=1
            )
            latest = statuses[0] if statuses else {}
            deployments.append(
                {
                    "id": d.get("id"),
                    "sha": d.get("sha"),
                    "short_sha": (d.get("sha") or "")[:8],
                    "ref": d.get("ref"),
                    "environment": d.get("environment"),
                    "created_at": d.get("created_at"),
                    "description": d.get("description"),
                    "creator": (d.get("creator") or {}).get("login"),
                    "state": latest.get("state"),
                    "state_updated_at": latest.get("created_at"),
                }
            )
        return deployments

    async def list_recent_pull_requests(
        self, repo: str, *, hours: int = 48, limit: int = 20
    ) -> list[dict[str, Any]]:
        self._check_repo_allowed(repo)
        payload = await self._get_json(
            f"/repos/{repo}/pulls",
            state="closed",
            sort="updated",
            direction="desc",
            per_page=min(limit, 100),
        )
        cutoff = datetime.now(UTC) - timedelta(hours=hours)
        results = []
        for pr in payload:
            merged_at = pr.get("merged_at")
            if not merged_at:
                continue
            if datetime.fromisoformat(merged_at.replace("Z", "+00:00")) < cutoff:
                continue
            results.append(
                {
                    "number": pr.get("number"),
                    "title": pr.get("title"),
                    "author": (pr.get("user") or {}).get("login"),
                    "merged_at": merged_at,
                    "merge_commit_sha": pr.get("merge_commit_sha"),
                    "url": pr.get("html_url"),
                    "labels": [label.get("name") for label in pr.get("labels") or []],
                }
            )
        return results[:limit]

    async def get_workflow_runs(
        self, repo: str, *, hours: int = 24, status: str | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        self._check_repo_allowed(repo)
        created = f">={(datetime.now(UTC) - timedelta(hours=hours)).date().isoformat()}"
        payload = await self._get_json(
            f"/repos/{repo}/actions/runs",
            created=created,
            status=status,
            per_page=min(limit, 100),
        )
        return [
            {
                "id": r.get("id"),
                "name": r.get("name"),
                "status": r.get("status"),
                "conclusion": r.get("conclusion"),
                "head_sha": r.get("head_sha"),
                "created_at": r.get("created_at"),
                "updated_at": r.get("updated_at"),
                "url": r.get("html_url"),
            }
            for r in (payload.get("workflow_runs") or [])[:limit]
        ]

    # -- write --------------------------------------------------------------
    async def create_revert_pull_request(
        self, *, repo: str, commit_sha: str, base_branch: str, title: str, body: str
    ) -> dict[str, Any]:
        self._require_write()
        self._check_repo_allowed(repo)

        base_ref = await self._get_json(f"/repos/{repo}/git/ref/heads/{base_branch}")
        base_sha = base_ref["object"]["sha"]
        branch = f"opspilot/revert-{commit_sha[:8]}-{int(time.time())}"

        await self._post_json(
            f"/repos/{repo}/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": base_sha},
        )

        # Reverting means re-applying the inverse of the commit's tree. GitHub has
        # no revert API, so we recreate the parent's file contents on the branch.
        commit = await self._get_json(f"/repos/{repo}/commits/{commit_sha}")
        parents = commit.get("parents") or []
        if not parents:
            raise IntegrationError(f"Commit {commit_sha[:8]} has no parent and cannot be reverted")
        parent_sha = parents[0]["sha"]

        for changed in commit.get("files") or []:
            path = changed["filename"]
            await self._restore_file(repo, path, parent_sha, branch, commit_sha)

        pr = await self._post_json(
            f"/repos/{repo}/pulls",
            {"title": title, "body": body, "head": branch, "base": base_branch},
        )
        return {
            "number": pr.get("number"),
            "url": pr.get("html_url"),
            "branch": branch,
            "state": pr.get("state"),
        }

    async def _restore_file(
        self, repo: str, path: str, parent_sha: str, branch: str, reverted_sha: str
    ) -> None:
        """Put ``path`` back to its content at ``parent_sha`` on ``branch``."""
        current = await self._safe_get(f"/repos/{repo}/contents/{path}", ref=branch)
        original = await self._safe_get(f"/repos/{repo}/contents/{path}", ref=parent_sha)

        message = f"Revert {reverted_sha[:8]}: {path}"
        if original is None:
            # File was added by the reverted commit -> delete it.
            if current is not None:
                await self._delete_json(
                    f"/repos/{repo}/contents/{path}",
                    {"message": message, "sha": current["sha"], "branch": branch},
                )
            return

        payload: dict[str, Any] = {
            "message": message,
            "content": original["content"].replace("\n", ""),
            "branch": branch,
        }
        if current is not None:
            payload["sha"] = current["sha"]
        await self._put_json(f"/repos/{repo}/contents/{path}", payload)

    async def dispatch_workflow(
        self, *, repo: str, workflow: str, ref: str, inputs: dict[str, str]
    ) -> dict[str, Any]:
        self._require_write()
        self._check_repo_allowed(repo)
        allowed = self.config.get("workflows") or []
        if allowed and workflow not in allowed:
            raise IntegrationError(
                f"Workflow '{workflow}' is not allowlisted for this integration",
                details={"allowed": allowed},
            )
        await self._post_json(
            f"/repos/{repo}/actions/workflows/{workflow}/dispatches",
            {"ref": ref, "inputs": inputs},
        )
        return {"workflow": workflow, "ref": ref, "dispatched_at": datetime.now(UTC).isoformat()}

    # -- helpers -------------------------------------------------------------
    async def _safe_get(self, path: str, **params: Any) -> dict[str, Any] | None:
        try:
            return await self._get_json(path, **params)
        except IntegrationError as exc:
            if (exc.details or {}).get("status") == 404:
                return None
            raise

    async def _put_json(self, path: str, payload: dict[str, Any]) -> Any:
        async def _call() -> Any:
            response = await self.http.put(path, json=payload)
            response.raise_for_status()
            return response.json()

        return await self._with_retries(f"PUT {path}", _call, attempts=2)

    async def _delete_json(self, path: str, payload: dict[str, Any]) -> Any:
        async def _call() -> Any:
            response = await self.http.request("DELETE", path, json=payload)
            response.raise_for_status()
            return response.json() if response.content else {}

        return await self._with_retries(f"DELETE {path}", _call, attempts=2)

    async def _get_json(self, path: str, **params: Any) -> Any:
        """Override to surface GitHub's rate-limit headers as a typed error."""

        async def _call() -> Any:
            response = await self.http.get(
                path, params={k: v for k, v in params.items() if v is not None}
            )
            if response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0":
                reset = response.headers.get("x-ratelimit-reset", "?")
                raise IntegrationError(
                    f"GitHub rate limit exhausted; resets at {reset}",
                    details={"reset": reset},
                )
            response.raise_for_status()
            return response.json()

        try:
            return await self._with_retries(f"GET {path}", _call)
        except httpx.HTTPStatusError as exc:  # pragma: no cover - mapped in base
            raise IntegrationError(str(exc)) from exc
