"""Check one domain: fetch its Agent Card, validate it, optionally probe it.

The probe is deliberately the most harmless call A2A defines: `GetTask` for
a random task id nobody holds. Nothing is created, sent or run on the other
side. A `SendMessage` would prove more and could make somebody's agent do
work, so this checker never sends one.

Two bindings are probed, and each has its own correct answer:

* **JSONRPC** - POST a `GetTask` request; expect error -32001.
* **HTTP+JSON** - `GET {url}[/{tenant}]/tasks/{id}`; expect HTTP 404 carrying
  a `google.rpc.Status` body whose `ErrorInfo.reason` is `TASK_NOT_FOUND`.
  The body is what matters: a bare 404 is also what a server says when the
  route does not exist at all, so it cannot tell "no such task" from "no
  such endpoint". The path, the tenant prefix and the reason string follow
  the official a2a-sdk (1.2), which is the reference this was checked
  against.

GRPC is not probed: it needs an HTTP/2 gRPC client, which this checker does
not carry.
"""
from __future__ import annotations

import json
import uuid
from urllib.parse import quote
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import card as cardmod
from .card import Finding
from .fetch import FetchRefused, fetch

WELL_KNOWN = "/.well-known/agent-card.json"
TASK_NOT_FOUND = -32001
METHOD_NOT_FOUND = -32601
ERROR_INFO_TYPE = "type.googleapis.com/google.rpc.ErrorInfo"
REST_TASK_NOT_FOUND = "TASK_NOT_FOUND"
PROBED = ("JSONRPC", "HTTP+JSON")


@dataclass
class Report:
    domain: str
    card_url: str
    card: dict | None = None
    findings: list[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        levels = {f.level for f in self.findings}
        return "fail" if "fail" in levels else "warn" if "warn" in levels else "pass"

    def as_dict(self) -> dict:
        return {"domain": self.domain, "card_url": self.card_url, "verdict": self.verdict,
                "agent": (self.card or {}).get("name"),
                "findings": [f.as_dict() for f in self.findings]}


def card_url_for(target: str) -> str:
    """Accept a bare domain or a full https URL; return the card URL to fetch."""
    target = target.strip()
    if "://" not in target:
        return f"https://{target.strip('/').lower()}{WELL_KNOWN}"
    return target


def _task_id() -> str:
    return f"a2a-agent-checker-{uuid.uuid4()}"


def _probe_jsonrpc(iface: dict, fetcher) -> list[Finding]:
    url, version = iface.get("url"), iface.get("protocolVersion") or ""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "GetTask",
                       "params": {"id": _task_id()}}).encode()
    try:
        r = fetcher(url, method="POST", content=body,
                    headers={"Content-Type": "application/json", "A2A-Version": version})
    except FetchRefused as e:
        return [Finding("fail", "probe-unreachable", f"endpoint {url}: {e}")]
    if r.status in (401, 403):
        return [Finding("info", "probe-auth", f"endpoint {url} requires authentication"
                        f" (HTTP {r.status}); not probed further")]
    if r.status != 200:
        return [Finding("fail", "probe-http", f"endpoint {url} answered HTTP {r.status} to JSON-RPC")]
    try:
        answer = json.loads(r.body)
    except ValueError:
        return [Finding("fail", "probe-not-json", f"endpoint {url} did not answer with JSON")]
    if not isinstance(answer, dict) or answer.get("jsonrpc") != "2.0":
        return [Finding("fail", "probe-not-jsonrpc", f"endpoint {url} did not answer JSON-RPC 2.0")]
    code = (answer.get("error") or {}).get("code")
    if code == TASK_NOT_FOUND:
        return [Finding("info", "probe-ok", f"endpoint {url} answers JSON-RPC and reports an"
                        " unknown task correctly (-32001)")]
    if code == METHOD_NOT_FOUND:
        return [Finding("warn", "probe-no-gettask", f"endpoint {url} does not implement GetTask,"
                        " which v1.0 requires")]
    if "result" in answer:
        return [Finding("warn", "probe-found-task", f"endpoint {url} returned a task for an id"
                        " that cannot exist")]
    return [Finding("warn", "probe-odd-error", f"endpoint {url} answered GetTask with error {code}"
                    f" ({(answer.get('error') or {}).get('message', '')!s:.80}); expected -32001")]


def _rest_reason(answer) -> str | None:
    """The ErrorInfo reason in a google.rpc.Status body, or None."""
    if not isinstance(answer, dict) or not isinstance(answer.get("error"), dict):
        return None
    details = answer["error"].get("details")
    for d in details if isinstance(details, list) else []:
        if isinstance(d, dict) and d.get("@type") == ERROR_INFO_TYPE:
            return d.get("reason")
    return None


def _probe_rest(iface: dict, fetcher) -> list[Finding]:
    base, version = iface["url"].rstrip("/"), iface.get("protocolVersion") or ""
    tenant = iface.get("tenant") or ""
    path = (f"/{quote(tenant, safe='')}" if tenant else "") + f"/tasks/{_task_id()}"
    url = base + path
    try:
        r = fetcher(url, method="GET", headers={"Accept": "application/json",
                                                "A2A-Version": version})
    except FetchRefused as e:
        return [Finding("fail", "probe-unreachable", f"endpoint {base}: {e}")]
    try:
        answer = json.loads(r.body) if r.body else None
    except ValueError:
        answer = None
    reason = _rest_reason(answer)
    if r.status == 404 and reason == REST_TASK_NOT_FOUND:
        return [Finding("info", "probe-ok", f"endpoint {base} answers HTTP+JSON and reports an"
                        " unknown task correctly (404, TASK_NOT_FOUND)")]
    if r.status == 404:
        return [Finding("warn", "probe-bare-404", f"endpoint {base} answered GET .../tasks/{{id}}"
                        " with 404 but no TASK_NOT_FOUND error body, so a client cannot tell a"
                        " missing task from a missing route")]
    if r.status == 200:
        return [Finding("warn", "probe-found-task", f"endpoint {base} returned 200 for a task id"
                        " that cannot exist")]
    if r.status in (401, 403):
        return [Finding("info", "probe-auth", f"endpoint {base} requires authentication"
                        f" (HTTP {r.status}); not probed further")]
    if r.status == 405:
        return [Finding("warn", "probe-no-gettask", f"endpoint {base} does not allow GET on"
                        " /tasks/{id}, which v1.0 requires")]
    detail = f" ({reason})" if reason else ""
    return [Finding("warn", "probe-odd-error", f"endpoint {base} answered GET .../tasks/{{id}}"
                    f" with HTTP {r.status}{detail}; expected 404 with TASK_NOT_FOUND")]


PROBES = {"JSONRPC": _probe_jsonrpc, "HTTP+JSON": _probe_rest}


def check(target: str, *, probe: bool = False, fetcher=fetch) -> Report:
    url = card_url_for(target)
    report = Report(domain=target, card_url=url)
    try:
        r = fetcher(url)
    except FetchRefused as e:
        report.findings.append(Finding("fail", "unreachable", str(e)))
        return report
    if r.redirects:
        report.findings.append(Finding("warn", "redirected",
                                       f"the card is only reachable through {len(r.redirects)} redirect(s); it is served at {r.url}"))
    if r.status == 404:
        report.findings.append(Finding("fail", "no-card", f"no Agent Card at {url} (HTTP 404)"))
        return report
    if r.status != 200:
        report.findings.append(Finding("fail", "http-status", f"{url} answered HTTP {r.status}"))
        return report
    ctype = r.headers.get("content-type", "")
    if "json" not in ctype:
        report.findings.append(Finding("warn", "content-type",
                                       f"served as {ctype or 'no content type'}, not application/json"))
    try:
        report.card = json.loads(r.body)
    except ValueError as e:
        report.findings.append(Finding("fail", "not-json", f"the card is not valid JSON ({e})"))
        return report
    report.findings += cardmod.validate(report.card, r.url)
    if probe and isinstance(report.card, dict):
        ifaces = [i for i in report.card.get("supportedInterfaces") or []
                  if isinstance(i, dict) and isinstance(i.get("url"), str)
                  and i.get("protocolBinding") in PROBED]
        if not ifaces:
            report.findings.append(Finding("info", "probe-skipped",
                                           "no JSONRPC or HTTP+JSON interface to probe"))
        card_host = (urlsplit(r.url).hostname or "").lower()
        for iface in ifaces:
            # A card can name any URL as its endpoint, so probing it blindly
            # would let whoever writes a card make this checker POST to a
            # third party. Only the card's own host is probed.
            if (urlsplit(iface["url"]).hostname or "").lower() != card_host:
                report.findings.append(Finding("info", "probe-skipped",
                                               f"not probing {iface['url']}: it is not on {card_host}"))
                continue
            report.findings += PROBES[iface["protocolBinding"]](iface, fetcher)
    return report
