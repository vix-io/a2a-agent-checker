"""Check one domain: fetch its Agent Card, validate it, optionally probe it.

The probe is deliberately the most harmless call A2A defines: `GetTask` for
a random task id nobody holds. A conforming agent answers with error -32001
(TaskNotFound), and nothing is created, sent or run on the other side. A
`SendMessage` would prove more and could make somebody's agent do work, so
this checker never sends one.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import card as cardmod
from .card import Finding
from .fetch import FetchRefused, fetch

WELL_KNOWN = "/.well-known/agent-card.json"
TASK_NOT_FOUND = -32001
METHOD_NOT_FOUND = -32601


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


def _probe(iface: dict, fetcher) -> list[Finding]:
    url, version = iface.get("url"), iface.get("protocolVersion") or ""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "GetTask",
                       "params": {"id": f"a2a-agent-checker-{uuid.uuid4()}"}}).encode()
    try:
        r = fetcher(url, method="POST", content=body,
                    headers={"Content-Type": "application/json", "A2A-Version": version})
    except FetchRefused as e:
        return [Finding("fail", "probe-unreachable", f"endpoint {url}: {e}")]
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
        jsonrpc = [i for i in report.card.get("supportedInterfaces") or []
                   if isinstance(i, dict) and i.get("protocolBinding") == "JSONRPC" and i.get("url")]
        if not jsonrpc:
            report.findings.append(Finding("info", "probe-skipped",
                                           "no JSONRPC interface to probe"))
        card_host = (urlsplit(r.url).hostname or "").lower()
        for iface in jsonrpc:
            # A card can name any URL as its endpoint, so probing it blindly
            # would let whoever writes a card make this checker POST to a
            # third party. Only the card's own host is probed.
            if (urlsplit(iface["url"]).hostname or "").lower() != card_host:
                report.findings.append(Finding("info", "probe-skipped",
                                               f"not probing {iface['url']}: it is not on {card_host}"))
                continue
            report.findings += _probe(iface, fetcher)
    return report
