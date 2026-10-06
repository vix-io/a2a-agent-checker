import copy
import json
import socket
import unittest

from a2a_agent_checker import card as cardmod
from a2a_agent_checker import fetch as fetchmod
from a2a_agent_checker.check import check
from a2a_agent_checker.fetch import FetchRefused, Response

GOOD = {
    "name": "Example agent",
    "description": "Finds things.",
    "supportedInterfaces": [{"url": "https://example.com/a2a",
                             "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
    "version": "1.0.0",
    "capabilities": {"streaming": False},
    "defaultInputModes": ["application/json", "text/plain"],
    "defaultOutputModes": ["application/json"],
    "skills": [{"id": "search", "name": "Search", "description": "Search.", "tags": ["s"]}],
    "provider": {"organization": "Example", "url": "https://example.com"},
    "documentationUrl": "https://example.com/docs",
}
URL = "https://example.com/.well-known/agent-card.json"


def codes(findings, level=None):
    return {f.code for f in findings if level is None or f.level == level}


class CardRules(unittest.TestCase):
    def test_a_good_card_has_no_faults(self):
        self.assertEqual(codes(cardmod.validate(GOOD, URL), "fail"), set())
        self.assertEqual(codes(cardmod.validate(GOOD, URL), "warn"), set())

    def test_every_required_field_is_required(self):
        for k in cardmod.REQUIRED:
            card = copy.deepcopy(GOOD)
            del card[k]
            found = [f for f in cardmod.validate(card, URL) if f.code == "missing-field"]
            self.assertTrue(any(k in f.message for f in found), k)

    def test_a_0_3_card_is_named_as_one(self):
        card = copy.deepcopy(GOOD)
        del card["supportedInterfaces"]
        card["url"] = "https://example.com/a2a"
        card["protocolVersion"] = "0.3.0"
        f = cardmod.validate(card, URL)
        self.assertIn("legacy-card", codes(f, "fail"))

    def test_legacy_fields_beside_v1_interfaces_only_warn(self):
        card = copy.deepcopy(GOOD)
        card["url"] = "https://example.com/a2a"
        self.assertIn("legacy-card", codes(cardmod.validate(card, URL), "warn"))

    def test_interface_must_be_https_and_known_binding(self):
        card = copy.deepcopy(GOOD)
        card["supportedInterfaces"][0].update(url="http://example.com/a2a", protocolBinding="REST")
        f = codes(cardmod.validate(card, URL), "fail")
        self.assertIn("insecure-url", f)
        self.assertIn("bad-binding", f)

    def test_interface_on_another_host_warns(self):
        card = copy.deepcopy(GOOD)
        card["supportedInterfaces"][0]["url"] = "https://elsewhere.net/a2a"
        self.assertIn("other-host", codes(cardmod.validate(card, URL), "warn"))

    def test_skill_fields_and_duplicates(self):
        card = copy.deepcopy(GOOD)
        card["skills"].append(dict(card["skills"][0]))
        card["skills"].append({"id": "x"})
        f = cardmod.validate(card, URL)
        self.assertIn("duplicate-skill", codes(f, "warn"))
        self.assertIn("missing-field", codes(f, "fail"))

    def test_snake_case_keys_warn(self):
        card = copy.deepcopy(GOOD)
        card["default_input_modes"] = card["defaultInputModes"]
        self.assertIn("snake-case", codes(cardmod.validate(card, URL), "warn"))

    def test_empty_lists_fail(self):
        for k in ("skills", "supportedInterfaces", "defaultInputModes"):
            card = copy.deepcopy(GOOD)
            card[k] = []
            self.assertIn("bad-type", codes(cardmod.validate(card, URL), "fail"), k)

    def test_not_an_object(self):
        self.assertIn("not-an-object", codes(cardmod.validate([], URL)))


def fake_fetcher(routes):
    """routes: {(method, url): Response or Exception}"""
    calls = []

    def fetcher(url, method="GET", headers=None, content=None):
        calls.append((method, url, headers, content))
        r = routes[(method, url)]
        if isinstance(r, Exception):
            raise r
        return r
    fetcher.calls = calls
    return fetcher


def resp(url, body, status=200, ctype="application/json"):
    return Response(url, status, {"content-type": ctype},
                    body if isinstance(body, bytes) else json.dumps(body).encode())


class Check(unittest.TestCase):
    def test_bare_domain_reads_the_well_known_path(self):
        f = fake_fetcher({("GET", URL): resp(URL, GOOD)})
        r = check("Example.com", fetcher=f)
        self.assertEqual(r.verdict, "pass")
        self.assertEqual(f.calls[0][1], URL)

    def test_404_is_no_card(self):
        f = fake_fetcher({("GET", URL): resp(URL, b"", status=404)})
        self.assertIn("no-card", codes(check("example.com", fetcher=f).findings))

    def test_bad_json_fails(self):
        f = fake_fetcher({("GET", URL): resp(URL, b"<html>")})
        self.assertEqual(check("example.com", fetcher=f).verdict, "fail")

    def test_wrong_content_type_warns(self):
        f = fake_fetcher({("GET", URL): resp(URL, GOOD, ctype="text/html")})
        self.assertIn("content-type", codes(check("example.com", fetcher=f).findings, "warn"))

    def test_refusal_is_reported_not_raised(self):
        f = fake_fetcher({("GET", URL): FetchRefused("resolves to a non-public address")})
        self.assertIn("unreachable", codes(check("example.com", fetcher=f).findings, "fail"))

    def test_no_probe_unless_asked(self):
        f = fake_fetcher({("GET", URL): resp(URL, GOOD)})
        check("example.com", fetcher=f)
        self.assertEqual([c[0] for c in f.calls], ["GET"])

    def probe(self, answer, status=200):
        a2a = "https://example.com/a2a"
        f = fake_fetcher({("GET", URL): resp(URL, GOOD),
                          ("POST", a2a): resp(a2a, answer, status=status)})
        return f, check("example.com", probe=True, fetcher=f)

    def test_probe_sends_only_gettask_with_the_version_header(self):
        f, r = self.probe({"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "x"}})
        method, url, headers, body = f.calls[1]
        sent = json.loads(body)
        self.assertEqual(sent["method"], "GetTask")
        self.assertEqual(headers["A2A-Version"], "1.0")
        self.assertIn("probe-ok", codes(r.findings, "info"))
        self.assertEqual(r.verdict, "pass")

    def test_probe_outcomes(self):
        cases = [({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601}}, 200, "probe-no-gettask"),
                 ({"jsonrpc": "2.0", "id": 1, "result": {}}, 200, "probe-found-task"),
                 ({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000}}, 200, "probe-odd-error"),
                 ({"ok": True}, 200, "probe-not-jsonrpc"),
                 (b"nope", 200, "probe-not-json"),
                 ({}, 500, "probe-http")]
        for answer, status, code in cases:
            _, r = self.probe(answer, status)
            self.assertIn(code, codes(r.findings), code)

    def test_an_endpoint_on_another_host_is_not_probed(self):
        card = copy.deepcopy(GOOD)
        card["supportedInterfaces"][0]["url"] = "https://victim.example/hook"
        f = fake_fetcher({("GET", URL): resp(URL, card)})
        r = check("example.com", probe=True, fetcher=f)
        self.assertEqual([c[0] for c in f.calls], ["GET"])
        self.assertIn("probe-skipped", codes(r.findings, "info"))


class FetchRules(unittest.TestCase):
    def test_url_rules(self):
        for url in ("http://example.com/x", "https://example.com:8443/x",
                    "https://user:pw@example.com/x", "https://127.0.0.1/x", "ftp://example.com"):
            with self.assertRaises(FetchRefused, msg=url):
                fetchmod.check_url(url)
        self.assertEqual(fetchmod.check_url("https://Example.com/a?b=1"), ("example.com", "/a?b=1"))

    def resolver(self, *ips):
        return lambda host, port, type=None: [(socket.AF_INET, type, 6, "", (ip, port)) for ip in ips]

    def test_private_addresses_are_refused(self):
        for ip in ("127.0.0.1", "10.1.2.3", "192.168.0.5", "169.254.169.254", "100.64.0.1",
                   "0.0.0.0", "::1", "fd00::1", "fe80::1"):
            with self.assertRaises(FetchRefused, msg=ip):
                fetchmod._public_ips("example.com", self.resolver(ip))

    def test_one_private_answer_among_public_ones_is_refused(self):
        with self.assertRaises(FetchRefused):
            fetchmod._public_ips("example.com", self.resolver("93.184.216.34", "127.0.0.1"))

    def test_public_address_passes(self):
        self.assertEqual(fetchmod._public_ips("example.com", self.resolver("93.184.216.34")),
                         ["93.184.216.34"])

    def test_the_connection_goes_to_the_checked_address(self):
        import httpx
        seen = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, json=GOOD)
        client = httpx.Client(transport=httpx.MockTransport(handler))
        r = fetchmod.fetch(URL, client=client, resolver=self.resolver("93.184.216.34"))
        self.assertEqual(r.status, 200)
        self.assertEqual(seen[0].url.host, "93.184.216.34")
        self.assertEqual(seen[0].headers["host"], "example.com")
        self.assertEqual(seen[0].extensions["sni_hostname"], "example.com")

    def test_each_redirect_hop_is_rechecked(self):
        import httpx

        def handler(request):
            return httpx.Response(302, headers={"location": "https://internal.example/x"})
        calls = {"n": 0}

        def resolver(host, port, type=None):
            calls["n"] += 1
            ip = "93.184.216.34" if host == "example.com" else "10.0.0.1"
            return [(socket.AF_INET, type, 6, "", (ip, port))]
        client = httpx.Client(transport=httpx.MockTransport(handler))
        with self.assertRaises(FetchRefused):
            fetchmod.fetch(URL, client=client, resolver=resolver)
        self.assertEqual(calls["n"], 2)

    def test_redirect_limit(self):
        import httpx
        client = httpx.Client(transport=httpx.MockTransport(
            lambda r: httpx.Response(302, headers={"location": URL})))
        with self.assertRaises(FetchRefused):
            fetchmod.fetch(URL, client=client, resolver=self.resolver("93.184.216.34"))

    def test_size_cap(self):
        import httpx
        client = httpx.Client(transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=b"x" * (fetchmod.MAX_BYTES + 1))))
        with self.assertRaises(FetchRefused):
            fetchmod.fetch(URL, client=client, resolver=self.resolver("93.184.216.34"))


if __name__ == "__main__":
    unittest.main()
