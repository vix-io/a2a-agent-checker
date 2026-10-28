"""Signature verification (spec 8.4). Cards are signed here with
`cryptography` directly, from the spec's steps, so the verifier is checked
against an independent signer rather than against itself."""
import base64
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import hashes                      # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from a2a_agent_checker import signatures as sg                          # noqa: E402
from a2a_agent_checker.check import check                               # noqa: E402
from a2a_agent_checker.fetch import FetchRefused                        # noqa: E402
from test_checker import GOOD, URL, codes, fake_fetcher, resp           # noqa: E402

JKU = "https://example.com/.well-known/jwks.json"


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def uint(n, size):
    return b64(n.to_bytes(size, "big"))


def canonical(card):
    body = {k: v for k, v in card.items() if k != "signatures"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def make_key(alg, kid="k1"):
    """(sign(data)->bytes, jwk)"""
    if alg == "EdDSA":
        k = Ed25519PrivateKey.generate()
        x = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return k.sign, {"kty": "OKP", "crv": "Ed25519", "x": b64(x), "kid": kid}
    if alg == "ES256":
        k = ec.generate_private_key(ec.SECP256R1())
        n = k.public_key().public_numbers()

        def sign(d):
            r, s = decode_dss_signature(k.sign(d, ec.ECDSA(hashes.SHA256())))
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return sign, {"kty": "EC", "crv": "P-256", "x": uint(n.x, 32), "y": uint(n.y, 32), "kid": kid}
    k = rsa.generate_private_key(65537, 2048)
    n = k.public_key().public_numbers()
    pad = (padding.PKCS1v15() if alg == "RS256"
           else padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH))
    return (lambda d: k.sign(d, pad, hashes.SHA256()),
            {"kty": "RSA", "n": uint(n.n, 256), "e": uint(n.e, 3), "kid": kid})


def signed(card, alg, sign, kid="k1", jku=JKU):
    header = {"alg": alg, "typ": "JOSE", "kid": kid}
    if jku:
        header["jku"] = jku
    protected = b64(json.dumps(header).encode())
    sig = sign(f"{protected}.{b64(canonical(card))}".encode())
    return {**card, "signatures": [{"protected": protected, "signature": b64(sig)}]}


def run(card, jwks=None, jwks_status=200):
    routes = {("GET", URL): resp(URL, card)}
    if jwks is not None:
        routes[("GET", JKU)] = resp(JKU, {"keys": jwks}, status=jwks_status)
    return check("example.com", fetcher=fake_fetcher(routes)).findings


class Verify(unittest.TestCase):

    def test_each_algorithm_family_verifies(self):
        for alg in ("EdDSA", "ES256", "RS256", "PS256"):
            sign, jwk = make_key(alg)
            f = run(signed(GOOD, alg, sign), [jwk])
            self.assertIn("signature-valid", codes(f, "info"), alg)

    def test_a_changed_card_is_invalid(self):
        sign, jwk = make_key("EdDSA")
        card = signed(GOOD, "EdDSA", sign)
        card["name"] = "Someone Else"
        self.assertIn("signature-invalid", codes(run(card, [jwk]), "warn"))

    def test_a_key_on_the_cards_own_host_says_it_proves_no_identity(self):
        sign, jwk = make_key("EdDSA")
        f = [x for x in run(signed(GOOD, "EdDSA", sign), [jwk]) if x.code == "signature-valid"]
        self.assertIn("not who signed it", f[0].message)

    def test_a_card_signed_with_its_empty_fields_kept_is_noncanonical_not_invalid(self):
        card = {**GOOD, "capabilities": {**GOOD["capabilities"], "extensions": []}}
        sign, jwk = make_key("EdDSA")
        header = {"alg": "EdDSA", "typ": "JOSE", "kid": "k1", "jku": JKU}
        protected = b64(json.dumps(header).encode())
        served = json.dumps(card, sort_keys=True, separators=(",", ":")).encode()
        sig = sign(f"{protected}.{b64(served)}".encode())
        f = run({**card, "signatures": [{"protected": protected, "signature": b64(sig)}]}, [jwk])
        self.assertIn("signature-noncanonical", codes(f, "warn"))
        self.assertNotIn("signature-invalid", codes(f))
        self.assertNotIn("signature-valid", codes(f))

    def test_unknown_kid_no_jku_bad_jwks_and_unknown_alg_are_unverifiable(self):
        sign, jwk = make_key("EdDSA")
        cases = [
            run(signed(GOOD, "EdDSA", sign, kid="other"), [jwk]),
            run(signed(GOOD, "EdDSA", sign, jku=None)),
            run(signed(GOOD, "EdDSA", sign), [jwk], jwks_status=404),
            run(signed(GOOD, "HS256", sign), [jwk]),
        ]
        for f in cases:
            self.assertIn("signature-unverifiable", codes(f, "info"))
            self.assertNotIn("signature-invalid", codes(f))

    def test_an_unfetchable_jwks_is_reported_not_raised(self):
        sign, _ = make_key("EdDSA")
        f = check("example.com", fetcher=fake_fetcher({
            ("GET", URL): resp(URL, signed(GOOD, "EdDSA", sign)),
            ("GET", JKU): FetchRefused("non-public address")})).findings
        self.assertIn("signature-unverifiable", codes(f))

    def test_one_jwks_fetch_for_several_signatures(self):
        sign, jwk = make_key("EdDSA")
        card = signed(GOOD, "EdDSA", sign)
        card["signatures"] *= 2
        f = fake_fetcher({("GET", URL): resp(URL, card), ("GET", JKU): resp(JKU, {"keys": [jwk]})})
        check("example.com", fetcher=f)
        self.assertEqual([c[1] for c in f.calls].count(JKU), 1)

    def test_malformed_signature_entries_warn(self):
        f = run({**GOOD, "signatures": [{"protected": 1}]})
        self.assertIn("signature-malformed", codes(f, "warn"))

    def test_without_cryptography_it_says_how_to_verify(self):
        sign, jwk = make_key("EdDSA")
        with mock.patch.object(sg, "HAVE_CRYPTO", False):
            f = run(signed(GOOD, "EdDSA", sign), [jwk])
        self.assertIn("signature-unverifiable", codes(f))

    def test_an_unsigned_card_gets_no_signature_findings(self):
        self.assertFalse([x for x in run(GOOD) if x.code.startswith("signature")])

    def test_verdict_is_unaffected_by_a_valid_signature(self):
        sign, jwk = make_key("EdDSA")
        r = check("example.com", fetcher=fake_fetcher({
            ("GET", URL): resp(URL, signed(GOOD, "EdDSA", sign)),
            ("GET", JKU): resp(JKU, {"keys": [jwk]})}))
        self.assertEqual(r.verdict, "pass")


class Canonical(unittest.TestCase):

    def test_spec_example(self):
        card = {"name": "Example Agent", "version": "1.0.0",
                "capabilities": {"streaming": False, "extensions": []},
                "signatures": [{}]}
        self.assertEqual(sg.signing_payload(card).decode(),
                         '{"capabilities":{"streaming":false},"name":"Example Agent","version":"1.0.0"}')

    def test_integral_floats_have_no_fraction(self):
        self.assertEqual(sg.jcs({"a": 2.0, "b": 1}), '{"a":2,"b":1}')


if __name__ == "__main__":
    unittest.main()
