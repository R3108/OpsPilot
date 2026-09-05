"""Interactive operator console: ``python -m app.console [BASE_URL]``.

A thin client for the OpsPilot API. Sign in (or sign up), then run the
incident-response scenes from one terminal: list and file incidents, kick off
an investigation and watch the agent swarm fan out live over SSE, connect
providers (GitHub, Slack, ...) whose evidence the swarm investigates, work
the approval queue, and read postmortems.

Nothing here imports a service directly — every command exercises the HTTP API
that ships, including its policy gates.

Usage::

    python -m app.console                       # http://localhost:8000
    python -m app.console https://api.example.com
    OPSPILOT_API_KEY=opk_... python -m app.console   # authenticate with a key
"""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import sys
from typing import Any

import httpx

SEVERITIES = ("sev1", "sev2", "sev3", "sev4", "sev5")
PROVIDERS = (
    "slack",
    "github",
    "kubernetes",
    "prometheus",
    "grafana",
    "cloudwatch",
    "postgres",
)

# Provider -> (credential keys, config keys) the API's create schema enforces.
PROVIDER_FIELDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "slack": (("bot_token", "signing_secret"), ()),
    "github": (("token",), ("owner", "repos")),
    "kubernetes": (("kubeconfig",), ("cluster", "default_namespace")),
    "prometheus": ((), ("base_url",)),
    "grafana": (("api_token",), ("base_url",)),
    "cloudwatch": (("access_key_id", "secret_access_key"), ("region", "log_groups")),
    "postgres": (("dsn",), ("label",)),
}

HELP = """\
incident scenes
  incidents [n]            list recent incidents (n = count)
  incident <ref|id>        show one incident; makes it current
  new                     file a new incident (interactive)
  investigate [ref]       swarm-investigate an incident, streaming live
  watch [ref]             attach to a running investigation's live feed
  runs                    agent runs for the current incident
  steps <run_id>          one run's steps, phase by phase
  evidence                collected evidence for the current incident
  actions                 remediation actions proposed so far
  postmortem              the written postmortem, once ready

approvals (human in the loop)
  approvals               pending approvals
  approve <id> [note]     approve a proposed action
  reject <id> [note]      reject it

providers (what the swarm can investigate)
  integrations            connected providers and their health
  connect <provider>      connect one (interactive; e.g. connect github)
  test <integration_id>   live connectivity check
  check_github <owner/repo>
                          full scene: ensure the GitHub provider is connected,
                          file a "what changed?" incident, and swarm it

session
  login [email] [password] [tenant_slug]
  signup                  create an organisation and its owner
  logout, whoami, status, quit / exit

  aliases: ? = help, ls = incidents, i = investigate, w = watch, exit = quit
"""


class ConsoleError(Exception):
    pass


# ---------------------------------------------------------------- rendering
def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


def _dim(text: str) -> str:
    return _c("2", str(text))


def _bold(text: str) -> str:
    return _c("1", str(text))


def _red(text: str) -> str:
    return _c("31", str(text))


def _green(text: str) -> str:
    return _c("32", str(text))


def _yellow(text: str) -> str:
    return _c("33", str(text))


def _fmt(value: Any, width: int = 0) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.2f}".rstrip("0").rstrip(".")
    text = str(value)
    return text[: width - 1] + "…" if width and len(text) > width else text


def _kv(label: str, value: Any) -> None:
    print(f"  {_dim(label):<22}{value}")


# ---------------------------------------------------------------- prompts
def prompt(text: str, *, default: str = "") -> str:
    suffix = f" {_dim(f'[{default}]')}" if default else ""
    value = input(f"{text}{suffix}: ").strip()
    return value or default


def prompt_secret(text: str) -> str:
    import getpass

    return getpass.getpass(f"{text}: ").strip()


# ---------------------------------------------------------------- client
class Client:
    """The HTTP client half of the console; knows no command logic."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.http = httpx.Client(base_url=self.base_url, timeout=30.0)
        self.token: str | None = None
        self.refresh: str | None = None
        self.api_key: str | None = None
        self.session: dict[str, Any] = {}

    # -- plumbing ---------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        if self.api_key:
            return {"X-API-Key": self.api_key}
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        auth: bool = True,
    ) -> dict[str, Any]:
        if auth and not (self.token or self.api_key):
            raise ConsoleError("Not signed in — try: login <email> <password>")
        for _attempt in range(2):  # one original try + at most one retry after refresh
            try:
                response = self.http.request(
                    method,
                    path,
                    json=body,
                    params={k: v for k, v in (params or {}).items() if v is not None},
                    headers=self._headers() if auth else {},
                )
            except httpx.ConnectError as exc:
                raise ConsoleError(
                    f"Cannot reach {self.base_url} — is the API running? ({exc})"
                ) from None
            if (
                response.status_code == 401
                and _attempt == 0
                and self.refresh
                and not self.api_key
                and self._try_refresh()
            ):
                continue
            break
        if response.status_code >= 400:
            try:
                message = response.json().get("error", {}).get("message", response.text)
            except ValueError:
                message = response.text
            raise ConsoleError(f"HTTP {response.status_code}: {message}")
        if response.status_code == 204 or not response.content:
            return {}
        return response.json()

    def _try_refresh(self) -> bool:
        try:
            response = self.http.post("/api/v1/auth/refresh", json={"refresh_token": self.refresh})
        except httpx.HTTPError:
            return False
        if response.status_code != 200:
            self.token = self.refresh = None
            return False
        pair = response.json()
        self.token = pair["access_token"]
        self.refresh = pair["refresh_token"]
        return True

    # -- auth --------------------------------------------------------------
    def login(self, email: str, password: str, tenant_slug: str | None) -> None:
        pair = self.request(
            "POST",
            "/api/v1/auth/login",
            body={"email": email, "password": password, "tenant_slug": tenant_slug},
            auth=False,
        )
        self._adopt_pair(pair)

    def signup(self, org: str, email: str, password: str, full_name: str) -> None:
        pair = self.request(
            "POST",
            "/api/v1/auth/signup",
            body={
                "organization_name": org,
                "email": email,
                "password": password,
                "full_name": full_name,
            },
            auth=False,
        )
        self._adopt_pair(pair)

    def _adopt_pair(self, pair: dict[str, Any]) -> None:
        self.api_key = None
        self.token = pair["access_token"]
        self.refresh = pair["refresh_token"]
        self.session = self.request("GET", "/api/v1/auth/session")

    def logout(self) -> None:
        if self.refresh:
            with contextlib.suppress(ConsoleError):
                self.request("POST", "/api/v1/auth/logout", body={"refresh_token": self.refresh})
        self.token = self.refresh = None
        self.session = {}

    # -- sse -----------------------------------------------------------------
    def stream_incident(self, incident_id: str) -> None:
        """Print the live agent feed for one incident until it settles.

        Prefers SSE; when the stream transport is unavailable (Redis down, as
        in a bare local demo) falls back to polling the incident's runs so the
        operator still sees the investigation progress.
        """
        try:
            ticket = self.request("POST", "/api/v1/stream/ticket")["ticket"]
        except ConsoleError as exc:
            print(_dim(f"(live stream unavailable: {exc})"))
            print(_dim("falling back to polling the investigation…"))
            self.poll_incident(incident_id)
            return
        with self.http.stream(
            "GET",
            f"/api/v1/stream/incidents/{incident_id}",
            params={"ticket": ticket},
            headers=self._headers(),
            timeout=httpx.Timeout(30.0, read=60.0),
        ) as response:
            try:
                if response.status_code == 404:
                    print(_red("Incident stream not found"))
                    return
                response.raise_for_status()
                event_type = ""
                for line in response.iter_lines():
                    if line.startswith("event:"):
                        event_type = line.split(":", 1)[1].strip()
                        continue
                    if not line.startswith("data:"):
                        continue
                    raw = line.split(":", 1)[1].strip()
                    try:
                        event = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    kind = event.get("type") or event_type
                    if kind == "heartbeat":
                        print(_dim("·"), end="", flush=True)
                        continue
                    if _render_event(event):
                        return  # graph settled
            except httpx.HTTPError as exc:
                print(_red(f"stream failed: {exc}"))
                self.poll_incident(incident_id)
                return
        print(_dim("(stream closed)"))

    def poll_incident(self, incident_id: str, *, timeout_seconds: float = 900) -> None:
        """Fallback when SSE is unavailable: watch the incident until it settles.

        The incident status — not the run rows — is the source of truth: a run
        parked on an approval stays ``awaiting_approval`` forever, so waiting for
        all runs to complete would never return after an approval pause.
        """
        import time

        deadline = time.monotonic() + timeout_seconds
        seen_steps: set[str] = set()
        while time.monotonic() < deadline:
            detail = self.request("GET", f"/api/v1/incidents/{incident_id}")
            status = str(detail.get("status"))
            # Stream new steps live, whichever run they belong to.
            for run in detail.get("runs") or []:
                self._poll_print_steps(incident_id, str(run["id"]), seen_steps)
            if status == "awaiting_approval":
                count = int(detail.get("open_approval_count") or 0)
                if count == 0:
                    # The status flips a beat before the approval row lands.
                    time.sleep(2)
                    continue
                print(_yellow(f"— paused: {count} approval(s) waiting —"))
                print(_dim("use: approvals / approve <id>, then: watch to reattach"))
                return
            if status in ("resolved", "closed", "failed"):
                print(_dim(f"— investigation settled: {status} —"))
                if detail.get("root_cause_summary"):
                    print(_bold(f"  root cause: {detail['root_cause_summary']}"))
                if status == "failed" or detail.get("root_cause_summary") is None:
                    print(_dim("  read the write-up with: postmortem"))
                return
            time.sleep(3)

    def _poll_print_steps(self, incident_id: str, run_id: str, seen: set[str]) -> None:
        try:
            run = self.request("GET", f"/api/v1/incidents/{incident_id}/runs/{run_id}")
        except ConsoleError:
            return
        for step in run.get("steps", []):
            step_id = str(step.get("id"))
            if step_id in seen:
                continue
            seen.add(step_id)
            state = str(step.get("status"))
            icon = _green("✓") if state == "completed" else _red("✗") if state == "failed" else "·"
            who = f" [{step.get('investigator')}]" if step.get("investigator") else ""
            print(f"    {icon} {step.get('phase')}: {step.get('name')}{who}")
            summary = step.get("output_summary")
            if summary:
                print(f"        {_dim(str(summary)[:110])}")


def _render_event(event: dict[str, Any]) -> bool:
    """Print one agent event. Returns True when the graph has settled."""
    kind = str(event.get("type", ""))
    title = str(event.get("title", ""))
    message = str(event.get("message", ""))
    investigator = event.get("investigator")
    who = f" {_dim(f'[{investigator}]')}" if investigator else ""
    data = event.get("data") or {}

    if kind == "phase.started":
        print(f"\n{_bold('▶ ' + (title or data.get('phase', '?')))}{who}")
    elif kind == "phase.completed":
        print(f"{_green('✓')} {title or data.get('phase', '?')}{who} {_dim(message)[:80]}")
        phase = str(data.get("phase") or "")
        if phase in ("done", "failed"):
            print(_dim(f"— graph settled: {phase} —"))
            return True
    elif kind == "phase.failed":
        print(_red(f"✗ {title}{who} {message}"))
    elif kind in ("tool.started",):
        print(f"  {_dim('→')} {title or message}")
    elif kind in ("tool.completed",):
        print(f"  {_green('✓')} {title or message}")
    elif kind == "tool.failed":
        print(f"  {_red('✗')} {title or message}")
    elif kind == "evidence.added":
        print(f"  {_green('+')} evidence: {title or message}")
    elif kind == "hypothesis.added":
        confidence = data.get("confidence", "?")
        print(f"  {_yellow('~')} hypothesis: {title or message} {_dim(f'confidence={confidence}')}")
    elif kind == "action.proposed":
        print(f"  {_bold('!')} action proposed: {title or message}")
    elif kind == "policy.decision":
        print(f"  {_yellow('§')} policy: {title or message}")
    elif kind == "approval.requested":
        print(f"  {_bold('⏸ approval requested')}: {title or message}")
        print(_dim("    (use: approvals / approve <id>)"))
    elif kind == "approval.resolved":
        print(f"  {_green('⏸ resolved')}: {title or message}")
    elif kind == "execution.result":
        print(f"  {_green('⚡')} executed: {title or message}")
    elif kind == "verification.result":
        print(f"  {'✓' if data.get('recovered') else _red('✗')} verification: {title or message}")
    elif kind == "postmortem.ready":
        print(f"\n{_bold('✎ postmortem ready')} — read it with: postmortem")
        return True
    elif kind == "incident.updated":
        status = data.get("status", "")
        print(f"{_dim(f'— incident now {status} —')}")
    elif kind == "thinking":
        print(f"  {_dim('… ' + (message or title)[:100])}")
    return False


# ---------------------------------------------------------------- shell
class Console:
    """The command shell: parses input, calls the client, renders."""

    def __init__(self, client: Client) -> None:
        self.client = client
        self.current: dict[str, Any] | None = None

    # -- helpers -------------------------------------------------------------
    def banner(self) -> None:
        print(f"{_green('OpsPilot console')} {_dim(self.client.base_url)}")
        print(_dim("help lists commands; quit exits."))

    def signed_in_line(self) -> str:
        if self.client.api_key:
            return "api key"
        user = self.client.session.get("user", {})
        tenant = self.client.session.get("tenant", {})
        if user:
            return f"{user.get('email')} [{user.get('role')}] @ {tenant.get('name')}"
        return "not signed in"

    def require_user(self) -> None:
        if self.client.api_key:
            raise ConsoleError("This action needs a signed-in user, not an API key")

    # -- commands --------------------------------------------------------------
    def do_help(self, args: list[str]) -> None:
        print(HELP)

    def do_login(self, args: list[str]) -> None:
        email = args[0] if len(args) > 0 else prompt("email")
        password = args[1] if len(args) > 1 else prompt_secret("password")
        tenant_slug = args[2] if len(args) > 2 else None
        self.client.login(email, password, tenant_slug)
        print(_green("signed in as "), end="")
        print(self.signed_in_line())

    def do_signup(self, args: list[str]) -> None:
        org = prompt("organisation name")
        email = prompt("your email")
        while True:
            password = prompt_secret("password (min 8 chars)")
            if len(password) >= 8:
                break
            print(_red("too short — need at least 8 characters"))
        name = prompt("full name", default=email.split("@")[0])
        self.client.signup(org, email, password, name)
        print(_green("organisation created; signed in as "), end="")
        print(self.signed_in_line())

    def do_logout(self, args: list[str]) -> None:
        self.client.logout()
        self.current = None
        print("signed out")

    def do_whoami(self, args: list[str]) -> None:
        if self.client.api_key:
            print("authenticated with an API key")
            return
        user = self.client.session.get("user")
        if not user:
            print("not signed in")
            return
        tenant = self.client.session.get("tenant", {})
        _kv("user", user.get("email"))
        _kv("name", user.get("full_name"))
        _kv("role", user.get("role"))
        _kv("tenant", f"{tenant.get('name')} ({tenant.get('slug')}, plan {tenant.get('plan')})")

    def do_status(self, args: list[str]) -> None:
        try:
            health = self.client.request("GET", "/health", auth=False)
        except ConsoleError as exc:
            print(_red(f"api unreachable — {exc}"))
            return
        print(
            f"api {_green(health.get('status', '?'))}  "
            f"env={health.get('environment')}  version={health.get('version')}"
        )
        _kv("database", "ok" if health.get("database") else _red("down"))
        _kv("redis", "ok" if health.get("redis") else _red("down"))

    # -- incidents ----------------------------------------------------------
    def do_incidents(self, args: list[str]) -> None:
        try:
            limit = int(args[0]) if args else 20
        except ValueError:
            raise ConsoleError("usage: incidents [count] — count must be a number") from None
        page = self.client.request("GET", "/api/v1/incidents", params={"limit": limit, "offset": 0})
        items = page.get("items", [])
        if not items:
            print("no incidents — file one with: new")
            return
        for item in items:
            self._print_incident(item)

    def _print_incident(self, incident: dict[str, Any]) -> None:
        current = self.current is not None and self.current.get("id") == incident.get("id")
        marker = _green("*") if current else " "
        sev = _fmt(incident.get("severity")).upper()
        approvals = incident.get("open_approval_count") or 0
        flag = _yellow(f" ⏸{approvals}") if approvals else ""
        print(
            f"{marker} {_bold(incident['reference'])}  {sev:<4} "
            f"{_fmt(incident.get('status')):<18} {_fmt(incident.get('service'), 20):<20} "
            f"{incident['title'][:60]}{flag}"
        )

    def _resolve(self, ref: str) -> dict[str, Any]:
        """Find an incident by reference, id, or the current one."""
        if not ref:
            if self.current:
                return self.current
            raise ConsoleError("no current incident — pass a reference or run: incident <ref>")
        page = self.client.request(
            "GET", "/api/v1/incidents", params={"q": ref, "limit": 50, "offset": 0}
        )
        matches = [i for i in page.get("items", []) if i["reference"] == ref or i["id"] == ref]
        if not matches:
            raise ConsoleError(f"no incident matching '{ref}'")
        return matches[0]

    def do_incident(self, args: list[str]) -> None:
        if not args:
            if self.current:
                args = [self.current["reference"]]
            else:
                raise ConsoleError("usage: incident <ref|id>")
        found = self._resolve(args[0])
        detail = self.client.request("GET", f"/api/v1/incidents/{found['id']}")
        self.current = detail
        print(_bold(f"{detail['reference']} — {detail['title']}"))
        _kv("status", detail.get("status"))
        _kv("severity", f"{detail.get('severity')} (rationale: {detail.get('severity_rationale')})")
        _kv("service", f"{detail.get('service') or '-'} / {detail.get('namespace') or '-'}")
        _kv("environment", detail.get("environment"))
        _kv("detected", detail.get("detected_at"))
        if detail.get("root_cause_summary"):
            conf = detail.get("root_cause_confidence")
            _kv("root cause", f"{detail['root_cause_summary']} {_dim(f'(confidence {conf})')}")
        if detail.get("open_approval_count"):
            print(_yellow(f"  ⏸ {detail['open_approval_count']} approval(s) waiting"))
        timeline = detail.get("timeline") or []
        print(_dim(f"  timeline ({len(timeline)}):"))
        for entry in timeline[-8:]:
            print(
                f"    {_dim(entry.get('occurred_at', ''))[:19]}  "
                f"{entry.get('actor_label')}: {entry.get('title')}"
            )

    def do_new(self, args: list[str]) -> None:
        title = prompt("title")
        description = prompt("description", default="(no description)")
        severity = ""
        while severity not in SEVERITIES:
            severity = prompt(f"severity ({'|'.join(SEVERITIES)})", default="sev3")
        service = prompt("service (e.g. checkout-api)")
        auto = prompt("auto-investigate now? (y/n)", default="y")
        incident = self.client.request(
            "POST",
            "/api/v1/incidents",
            body={
                "title": title,
                "description": description,
                "severity": severity,
                "service": service or None,
                "environment": prompt("environment", default="production"),
                "auto_investigate": auto.lower().startswith("y"),
            },
        )
        self.current = incident
        self._print_incident(incident)
        if auto.lower().startswith("y"):
            self._investigate(incident)

    # -- investigation -------------------------------------------------------
    def do_investigate(self, args: list[str]) -> None:
        incident = self._resolve(args[0] if args else "")
        self.current = incident
        self._investigate(incident)

    def _investigate(self, incident: dict[str, Any]) -> None:
        incident_id = incident["id"]
        force = False
        status = str(incident.get("status"))
        if status in ("closed", "failed"):
            force = True
            print(_dim("incident is terminal — investigating with force=true"))
        ack = self.client.request(
            "POST",
            f"/api/v1/incidents/{incident_id}/investigate",
            params={"force": force} if force else None,
        )
        print(_green(ack.get("message", "investigation queued")))
        print(_dim("streaming the swarm live (Ctrl+C to detach)…\n"))
        try:
            self.client.stream_incident(incident_id)
        except KeyboardInterrupt:
            print(_dim("\ndetached — the investigation keeps running; reattach with: watch"))

    def do_watch(self, args: list[str]) -> None:
        incident = self._resolve(args[0] if args else "")
        self.current = incident
        try:
            self.client.stream_incident(incident["id"])
        except KeyboardInterrupt:
            print(_dim("\ndetached"))

    def do_runs(self, args: list[str]) -> None:
        if not self.current:
            raise ConsoleError("set the current incident first: incident <ref>")
        runs = self.client.request("GET", f"/api/v1/incidents/{self.current['id']}/runs")
        if not runs:
            print("no runs yet — start one with: investigate")
            return
        for run in runs:
            state = str(run.get("status"))
            colour = _green if state == "completed" else _red if state == "failed" else _yellow
            print(
                f"  {run['id']}  {colour(state):<12} phase={run.get('phase')} "
                f"tools={run.get('tool_call_count')} cost=${run.get('cost_usd', 0):.3f} "
                f"{_fmt(run.get('started_at'))}"
            )

    def do_steps(self, args: list[str]) -> None:
        if not args:
            raise ConsoleError("usage: steps <run_id>  (list run ids with: runs)")
        if not self.current:
            raise ConsoleError("set the current incident first: incident <ref>")
        run = self.client.request("GET", f"/api/v1/incidents/{self.current['id']}/runs/{args[0]}")
        for step in run.get("steps", []):
            state = str(step.get("status"))
            icon = _green("✓") if state == "completed" else _red("✗") if state == "failed" else "·"
            who = ""
            if step.get("investigator"):
                who = f" {_dim('[' + str(step['investigator']) + ']')}"
            print(
                f"  {step.get('sequence', 0):>3} {icon} {_fmt(step.get('phase')):<20}"
                f"{step.get('name')}{who}"
            )
            if step.get("output_summary"):
                print(f"        {_dim(step['output_summary'][:110])}")
            if step.get("error"):
                print(f"        {_red(str(step['error'])[:110])}")

    def do_evidence(self, args: list[str]) -> None:
        if not self.current:
            raise ConsoleError("set the current incident first: incident <ref>")
        rows = self.client.request("GET", f"/api/v1/incidents/{self.current['id']}/evidence")
        if not rows:
            print("no evidence collected yet")
            return
        for row in rows:
            meta = _dim(f"relevance={row.get('relevance')} weight={row.get('weight')}")
            print(f"  [{_fmt(row.get('kind'))}] {_bold(row.get('summary', ''))} {meta}")
            detail = row.get("detail") or ""
            if detail:
                print(f"      {_dim(detail[:150])}")

    def do_actions(self, args: list[str]) -> None:
        if not self.current:
            raise ConsoleError("set the current incident first: incident <ref>")
        rows = self.client.request("GET", f"/api/v1/incidents/{self.current['id']}/actions")
        if not rows:
            print("no remediation actions yet")
            return
        for row in rows:
            state = str(row.get("status"))
            colour = (
                _green
                if state in ("succeeded", "approved")
                else _yellow
                if "await" in state
                else _red
            )
            print(
                f"  {row['id']}  {colour(state):<20} {_fmt(row.get('risk_tier')):<8} "
                f"{row.get('title')}"
            )
            if row.get("rationale"):
                print(f"      {_dim(str(row['rationale'])[:110])}")

    def do_postmortem(self, args: list[str]) -> None:
        if not self.current:
            raise ConsoleError("set the current incident first: incident <ref>")
        try:
            doc = self.client.request("GET", f"/api/v1/incidents/{self.current['id']}/postmortem")
        except ConsoleError as exc:
            print(_yellow(f"not ready yet — {exc}"))
            return
        print(_bold(f"# {doc.get('title', 'Postmortem')}"))
        for section in ("summary", "impact", "root_cause", "detection", "resolution"):
            body = doc.get(section)
            if body:
                print(f"\n{_bold(section.replace('_', ' ').title())}\n{body}")
        lessons = doc.get("lessons_learned")
        if lessons:
            print(f"\n{_bold('Lessons')}\n{lessons}")
        items = doc.get("action_items") or []
        if items:
            print(_bold("\nAction items"))
            for item in items:
                if isinstance(item, dict):
                    meta = " ".join(
                        f"{k}={v}" for k, v in item.items() if k != "title" and v is not None
                    )
                    print(f"  - {item.get('title', item)} {_dim(meta)}")
                else:
                    print(f"  - {item}")

    # -- approvals -------------------------------------------------------------
    def do_approvals(self, args: list[str]) -> None:
        page = self.client.request(
            "GET",
            "/api/v1/approvals",
            params={"status": "pending", "limit": 50, "offset": 0},
        )
        items = page.get("items", [])
        if not items:
            print("no pending approvals")
            return
        for row in items:
            action = row.get("action") or {}
            print(
                f"  {row['id']}\n      {row.get('incident_reference', '-')} "
                f"{_yellow(str(row.get('risk_tier')))} — {action.get('title')}"
            )
            summary = row.get("request_summary") or ""
            if summary:
                print(f"      {_dim(summary[:110])}")

    def _decide(self, args: list[str], decision: str) -> None:
        if not args:
            raise ConsoleError(f"usage: {decision} <approval_id> [note]")
        note = " ".join(args[1:])
        self.require_user()
        row = self.client.request(
            "POST",
            f"/api/v1/approvals/{args[0]}/decision",
            body={"decision": decision, "note": note},
        )
        state = str(row.get("status"))
        print(_green(f"{state}: {row.get('incident_reference', '')}"))
        action = row.get("action") or {}
        if action:
            print(f"  action {action.get('title')} -> {action.get('status')}")

    def do_approve(self, args: list[str]) -> None:
        self._decide(args, "approve")

    def do_reject(self, args: list[str]) -> None:
        self._decide(args, "reject")

    # -- integrations -----------------------------------------------------------
    def do_integrations(self, args: list[str]) -> None:
        rows = self.client.request("GET", "/api/v1/integrations")
        if not rows:
            print("none connected — connect one with: connect <provider>")
            return
        for row in rows:
            status = str(row.get("status"))
            colour = (
                _green
                if status == "healthy"
                else _red
                if status in ("error", "disabled")
                else _yellow
            )
            creds = ", ".join(str(k) for k in row.get("credential_keys") or [])
            write = "yes" if row.get("allow_write") else "no"
            print(
                f"  {row['id']}  {colour(status):<10} {_fmt(row.get('provider')):<12} "
                f"{row['name']:<20} {_dim(f'creds=[{creds}] write={write}')}"
            )
            if row.get("last_error"):
                print(f"      {_red(str(row['last_error'])[:110])}")

    def do_connect(self, args: list[str]) -> None:
        if not args:
            raise ConsoleError(f"usage: connect <provider>  (one of: {', '.join(PROVIDERS)})")
        provider = args[0].lower()
        if provider not in PROVIDERS:
            raise ConsoleError(f"unknown provider '{provider}' — one of: {', '.join(PROVIDERS)}")
        cred_keys, config_keys = PROVIDER_FIELDS.get(provider, ((), ()))

        name = prompt("name for this integration", default=provider)
        credentials: dict[str, str] = {}
        for key in cred_keys:
            credentials[key] = prompt_secret(f"credential {key}")
        config: dict[str, Any] = {}
        for key in config_keys:
            if provider == "github" and key == "repos":
                repos = prompt("repos (comma-separated owner/repo)", default="")
                config["repos"] = [r.strip() for r in repos.split(",") if r.strip()]
            elif provider == "cloudwatch" and key == "log_groups":
                groups = prompt("log groups (comma-separated)", default="")
                config[key] = [g.strip() for g in groups.split(",") if g.strip()]
            else:
                config[key] = prompt(f"config {key}")
        allow_write = prompt("allow write access? (y/n)", default="n").lower().startswith("y")

        row = self.client.request(
            "POST",
            "/api/v1/integrations",
            body={
                "provider": provider,
                "name": name,
                "config": config,
                "credentials": credentials,
                "allow_write": allow_write,
            },
        )
        print(_green(f"connected {row['provider']} as {row['name']} ({row['id']})"))
        health = self.client.request("POST", f"/api/v1/integrations/{row['id']}/test")
        detail = health.get("detail", "")
        mark = _green("ok") if health.get("status") == "healthy" else _red("unhealthy")
        print(f"  health: {mark} — {detail}")

    def do_test(self, args: list[str]) -> None:
        if not args:
            raise ConsoleError("usage: test <integration_id>  (ids from: integrations)")
        health = self.client.request("POST", f"/api/v1/integrations/{args[0]}/test")
        mark = _green("ok") if health.get("status") == "healthy" else _red("unhealthy")
        latency = health.get("latency_ms")
        tail = _dim(f"{latency}ms") if latency else ""
        print(f"  {mark} {health.get('provider')} — {health.get('detail', '')} {tail}")

    # -- the github scene ---------------------------------------------------------
    def do_check_github(self, args: list[str]) -> None:
        """One command: ensure GitHub is connected, file a 'what changed?'
        incident for the repo, and swarm it with the live feed."""
        if not args:
            raise ConsoleError("usage: check_github <owner/repo>")
        repo = args[0].strip().strip("/")
        if "/" not in repo:
            raise ConsoleError(
                "usage: check_github <owner/repo> — e.g. check_github R3108/OpsPilot"
            )

        github = self._find_integration("github", repo)
        if github is None:
            print(_dim(f"no GitHub integration covers {repo} — connecting one now"))
            token = prompt_secret("GitHub token (needs repo read access)")
            owner = repo.split("/", 1)[0]
            github = self.client.request(
                "POST",
                "/api/v1/integrations",
                body={
                    "provider": "github",
                    "name": f"github-{owner}",
                    "config": {"owner": owner, "repos": [repo]},
                    "credentials": {"token": token},
                    "allow_write": False,
                },
            )
            health = self.client.request("POST", f"/api/v1/integrations/{github['id']}/test")
            if health.get("status") != "healthy":
                raise ConsoleError(f"GitHub health check failed: {health.get('detail')}")
            print(_green(f"connected as {health.get('detail')}"))

        hours = args[1] if len(args) > 1 else "24"
        incident = self.client.request(
            "POST",
            "/api/v1/incidents",
            body={
                "title": f"GitHub review: what changed in {repo} in the last {hours}h?",
                "description": (
                    f"Operator requested a review of recent activity in {repo}: commits, "
                    "merged pull requests, deployments and workflow runs. Determine "
                    "whether anything risky or unusual landed, and whether any secrets "
                    "or credentials may have been exposed."
                ),
                "severity": "sev4",
                "service": repo,
                "environment": "production",
                "labels": {"repo": repo, "scene": "github_check"},
                "auto_investigate": False,
            },
        )
        self.current = incident
        self._print_incident(incident)
        self._investigate(incident)

    def _find_integration(self, provider: str, repo: str) -> dict[str, Any] | None:
        rows = self.client.request("GET", "/api/v1/integrations")
        for row in rows:
            if str(row.get("provider")) != provider:
                continue
            repos = (row.get("config") or {}).get("repos") or []
            if repo in repos:
                return row
        return None

    # -- misc -----------------------------------------------------------------
    def do_quit(self, args: list[str]) -> None:
        raise SystemExit(0)

    def dispatch(self, line: str) -> None:
        parts = shlex.split(line)
        if not parts:
            return
        command, args = parts[0].lower(), parts[1:]
        handler = getattr(self, f"do_{command}", None)
        if handler is None:
            print(_red(f"unknown command '{command}' — try: help"))
            return
        handler(args)


COMMAND_ALIASES = {"?": "help", "ls": "incidents", "i": "investigate", "w": "watch", "exit": "quit"}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    base_url = argv[0] if argv else os.environ.get("OPSPILOT_URL", "http://localhost:8000")
    client = Client(base_url)
    console = Console(client)

    api_key = os.environ.get("OPSPILOT_API_KEY")
    if api_key:
        client.api_key = api_key
        try:
            client.session = client.request("GET", "/api/v1/auth/session")
            print(_green("authenticated with API key"))
        except ConsoleError as exc:
            print(_red(f"API key rejected: {exc}"))
            client.api_key = None

    console.banner()
    if not (client.token or client.api_key):
        print(_dim("sign in to begin: login <email> <password> [tenant_slug]  (or: signup)"))
        if sys.stdin.isatty() and input("log in now? [Y/n] ").strip().lower() in ("", "y"):
            try:
                console.do_login([])
            except ConsoleError as exc:
                print(_red(str(exc)))

    while True:
        try:
            ref = (console.current or {}).get("reference")
            suffix = f"@{ref} " if ref else ""
            print(f"{_green('opspilot')}{_dim(suffix)}> ", end="", flush=True)
            line = input()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        try:
            words = line.split()
            if words and words[0] in COMMAND_ALIASES:
                line = COMMAND_ALIASES[words[0]] + " " + " ".join(words[1:])
            console.dispatch(line)
        except ConsoleError as exc:
            print(_red(str(exc)))
        except SystemExit:
            return 0
        except (ValueError, EOFError) as exc:
            print(_red(f"{exc}"))
        except KeyboardInterrupt:
            print(_dim("(interrupted — Ctrl+C again or 'quit' to exit)"))


if __name__ == "__main__":
    sys.exit(main())
