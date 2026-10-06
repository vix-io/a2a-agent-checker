"""Fetching a URL somebody else typed in, safely.

The checker is meant to run behind a public web page, so every address it is
handed is untrusted. Three rules, all enforced here rather than by the caller:

* **HTTPS only**, on the default port. An Agent Card on plain HTTP is a
  finding, not something to fetch.
* **Public addresses only, checked on the address actually connected to.**
  The host is resolved once, every result must be a public unicast address,
  and the connection goes to that resolved IP with the original name kept for
  SNI and certificate checks. Checking a name and then letting the HTTP client
  resolve it again is the DNS-rebinding hole: the second answer can be
  127.0.0.1.
* **Bounded**: a timeout per request, a byte cap read in a stream, and
  redirects followed by hand (each hop re-checked) up to a small limit.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

TIMEOUT_S = 10.0
MAX_BYTES = 256 * 1024
MAX_REDIRECTS = 3
USER_AGENT = "a2a-agent-checker/0.1.1 (+https://github.com/vix-io/a2a-agent-checker)"


class FetchRefused(Exception):
    """The URL was not fetched because a safety rule refused it."""


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    redirects: list[str] = field(default_factory=list)


def _public_ips(host: str, resolver=socket.getaddrinfo) -> list[str]:
    try:
        infos = resolver(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise FetchRefused(f"{host} does not resolve ({e})") from None
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise FetchRefused(f"{host} does not resolve")
    for ip in ips:
        addr = ipaddress.ip_address(ip.split("%")[0])
        # Every address must be public: a name answering with one public and
        # one private address is exactly the shape a rebinding attack takes.
        if not addr.is_global or addr.is_multicast:
            raise FetchRefused(f"{host} resolves to a non-public address ({ip})")
    return ips


def check_url(url: str) -> tuple[str, str]:
    """Return (host, path+query) for an acceptable URL, or raise FetchRefused."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise FetchRefused(f"only https:// is fetched, not {parts.scheme or 'no scheme'}")
    if not parts.hostname:
        raise FetchRefused("no host in URL")
    if parts.port not in (None, 443):
        raise FetchRefused(f"only the default https port is fetched, not {parts.port}")
    if parts.username or parts.password:
        raise FetchRefused("URLs carrying credentials are not fetched")
    try:
        ipaddress.ip_address(parts.hostname)
    except ValueError:
        pass
    else:
        raise FetchRefused("give a domain name, not an IP address")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.hostname.lower(), path


def _one(client: httpx.Client, method: str, url: str, *, headers, content,
         resolver) -> Response:
    host, path = check_url(url)
    ip = _public_ips(host, resolver)[0]
    target = f"https://{'[' + ip + ']' if ':' in ip else ip}{path}"
    request = client.build_request(
        method, target, content=content,
        headers={"Host": host, "User-Agent": USER_AGENT, **(headers or {})},
        extensions={"sni_hostname": host, "timeout": {
            "connect": TIMEOUT_S, "read": TIMEOUT_S, "write": TIMEOUT_S, "pool": TIMEOUT_S}},
    )
    response = client.send(request, stream=True)
    try:
        body = bytearray()
        for chunk in response.iter_bytes():
            body += chunk
            if len(body) > MAX_BYTES:
                raise FetchRefused(f"response is larger than {MAX_BYTES // 1024} KB")
        return Response(url, response.status_code,
                        {k.lower(): v for k, v in response.headers.items()}, bytes(body))
    finally:
        response.close()


def fetch(url: str, *, method: str = "GET", headers: dict | None = None,
          content: bytes | None = None, client: httpx.Client | None = None,
          resolver=socket.getaddrinfo) -> Response:
    """Fetch `url` under the rules above. Redirects are followed only for GET."""
    own = client is None
    client = client or httpx.Client(follow_redirects=False, verify=True)
    try:
        seen: list[str] = []
        current = url
        while True:
            response = _one(client, method, current, headers=headers,
                            content=content, resolver=resolver)
            location = response.headers.get("location")
            if method != "GET" or response.status not in (301, 302, 303, 307, 308) or not location:
                response.redirects = seen
                return response
            if len(seen) >= MAX_REDIRECTS:
                raise FetchRefused(f"more than {MAX_REDIRECTS} redirects")
            seen.append(current)
            current = urljoin(current, location)
    except httpx.HTTPError as e:
        raise FetchRefused(f"request failed: {type(e).__name__}: {e}") from None
    finally:
        if own:
            client.close()
