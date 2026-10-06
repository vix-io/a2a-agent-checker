"""Validating an Agent Card against A2A v1.0.

Pure and offline: `validate(card, card_url)` takes parsed JSON and returns
findings. Nothing here touches the network, so every rule is testable against
a fixture.

Three levels, and the line between them is the point:

* **fail** - a v1.0 client cannot use the card (a required field missing or
  the wrong type).
* **warn** - usable, but something a client or a person will trip on: a
  0.3-era field, an interface on another host, a duplicate skill id.
* **info** - true and worth saying, and not a fault: a signature present
  (we do not verify it), an optional field absent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

PROTOCOL_VERSION = "1.0"
BINDINGS = {"JSONRPC", "GRPC", "HTTP+JSON"}
REQUIRED = ("name", "description", "supportedInterfaces", "version",
            "capabilities", "defaultInputModes", "defaultOutputModes", "skills")
# Fields a 0.3 card carried at the top level and v1.0 moved into
# supportedInterfaces. Their presence is how an older card is recognised.
LEGACY_FIELDS = ("url", "preferredTransport", "additionalInterfaces", "protocolVersion")
SNAKE = re.compile(r"^[a-z]+(_[a-z0-9]+)+$")
MEDIA_TYPE = re.compile(r"^[\w.+-]+/[\w.+-]+$")


@dataclass(frozen=True)
class Finding:
    level: str  # fail | warn | info
    code: str
    message: str

    def as_dict(self) -> dict:
        return {"level": self.level, "code": self.code, "message": self.message}


def _is_text(v) -> bool:
    return isinstance(v, str) and v.strip() != ""


def _string_list(v) -> bool:
    return isinstance(v, list) and len(v) > 0 and all(_is_text(x) for x in v)


def _snake_keys(obj, path="") -> list[str]:
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if SNAKE.match(k):
                found.append(path + k)
            found += _snake_keys(v, f"{path}{k}.")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found += _snake_keys(v, f"{path}[{i}].")
    return found


def validate(card, card_url: str | None = None) -> list[Finding]:
    out: list[Finding] = []
    fail = lambda c, m: out.append(Finding("fail", c, m))
    warn = lambda c, m: out.append(Finding("warn", c, m))
    info = lambda c, m: out.append(Finding("info", c, m))

    if not isinstance(card, dict):
        fail("not-an-object", "the Agent Card is not a JSON object")
        return out

    missing = [k for k in REQUIRED if k not in card]
    for k in missing:
        fail("missing-field", f"required field '{k}' is missing")

    legacy = [k for k in LEGACY_FIELDS if k in card]
    if legacy:
        (fail if "supportedInterfaces" in missing else warn)(
            "legacy-card",
            "looks like an A2A 0.3 card (top-level " + ", ".join(legacy)
            + "); v1.0 lists endpoints in 'supportedInterfaces'")

    for k in ("name", "description", "version"):
        if k in card and not _is_text(card[k]):
            fail("bad-type", f"'{k}' must be a non-empty string")

    if "capabilities" in card and not isinstance(card["capabilities"], dict):
        fail("bad-type", "'capabilities' must be an object")

    for k in ("defaultInputModes", "defaultOutputModes"):
        if k in card:
            if not _string_list(card[k]):
                fail("bad-type", f"'{k}' must be a non-empty list of media types")
            else:
                odd = [m for m in card[k] if not MEDIA_TYPE.match(m)]
                if odd:
                    warn("media-type", f"'{k}' has values that are not media types: {odd}")

    host = (urlsplit(card_url).hostname or "").lower() if card_url else ""
    ifaces = card.get("supportedInterfaces")
    if "supportedInterfaces" in card:
        if not isinstance(ifaces, list) or not ifaces:
            fail("bad-type", "'supportedInterfaces' must be a non-empty list")
            ifaces = []
        for i, iface in enumerate(ifaces):
            where = f"supportedInterfaces[{i}]"
            if not isinstance(iface, dict):
                fail("bad-type", f"{where} must be an object")
                continue
            url = iface.get("url")
            if not _is_text(url):
                fail("missing-field", f"{where}.url is missing")
            else:
                parts = urlsplit(url)
                if parts.scheme != "https":
                    fail("insecure-url", f"{where}.url is not https: {url}")
                elif host and (parts.hostname or "").lower() != host:
                    warn("other-host", f"{where}.url is on {parts.hostname}, not {host}"
                         " - fine if intended, but a client cannot tell it apart from a"
                         " card pointing somewhere it should not")
            binding = iface.get("protocolBinding")
            if binding not in BINDINGS:
                fail("bad-binding", f"{where}.protocolBinding is {binding!r}; expected one of "
                     + ", ".join(sorted(BINDINGS)))
            version = iface.get("protocolVersion")
            if not _is_text(version):
                fail("missing-field", f"{where}.protocolVersion is missing")
            elif version.split(".")[0] != PROTOCOL_VERSION.split(".")[0]:
                warn("old-version", f"{where}.protocolVersion is {version}; current is {PROTOCOL_VERSION}")

    skills = card.get("skills")
    if "skills" in card:
        if not isinstance(skills, list) or not skills:
            fail("bad-type", "'skills' must be a non-empty list")
            skills = []
        ids = []
        for i, skill in enumerate(skills):
            where = f"skills[{i}]"
            if not isinstance(skill, dict):
                fail("bad-type", f"{where} must be an object")
                continue
            for k in ("id", "name", "description"):
                if not _is_text(skill.get(k)):
                    fail("missing-field", f"{where}.{k} is missing or empty")
            if not isinstance(skill.get("tags"), list):
                fail("missing-field", f"{where}.tags must be a list")
            if _is_text(skill.get("id")):
                ids.append(skill["id"])
        dupes = sorted({s for s in ids if ids.count(s) > 1})
        if dupes:
            warn("duplicate-skill", f"skill ids appear more than once: {dupes}")

    snake = _snake_keys(card)
    if snake:
        warn("snake-case", "v1.0 JSON uses camelCase; these keys are snake_case: "
             + ", ".join(snake[:6]) + (" ..." if len(snake) > 6 else ""))

    if "provider" not in card:
        info("no-provider", "no 'provider' - nothing says who operates this agent")
    if "documentationUrl" not in card:
        info("no-docs", "no 'documentationUrl'")
    if card.get("signatures"):
        info("signed", "the card carries signatures; this checker does not verify them yet")
    return out
