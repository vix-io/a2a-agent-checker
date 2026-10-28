"""Verifying Agent Card signatures (A2A v1.0, section 8.4).

Each entry of `signatures` is a JWS (RFC 7515) over the card's RFC 8785
canonical form, with `signatures` itself excluded and empty repeated fields
omitted (8.4.1). The protected header names the key by `kid` and, optionally,
where to fetch it by `jku` (a JWKS). Every signature gets one of three
verdicts, and the line between them is the point:

* **valid** - the key was fetched and the signature checks out.
* **invalid** - the key was fetched and the signature does not match: the
  card was changed after signing, or was signed over a different form.
* **unverifiable** - nothing could be checked: no `jku`, the JWKS could not
  be read, no key with that `kid`, an algorithm this checker does not
  implement, or `cryptography` not installed. Unverifiable is not invalid.

A valid signature says the card is unaltered since the holder of that key
signed it. When the JWKS sits on the card's own host it says nothing about
who that holder is; the finding says so rather than letting "valid" read as
an identity claim.

The JWKS is fetched through the same fetcher as the card, so it inherits
every safety rule (HTTPS, public addresses, size cap). One fetch per distinct
`jku` per check.
"""
from __future__ import annotations

import base64
import json
from urllib.parse import urlsplit

from .card import Finding

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised by patching HAVE_CRYPTO
    HAVE_CRYPTO = False

from .fetch import FetchRefused


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _num(n) -> str:
    # RFC 8785 numbers follow ECMAScript; an integral value has no fraction.
    if isinstance(n, float) and n.is_integer() and abs(n) < 2 ** 53:
        return str(int(n))
    return json.dumps(n)


def jcs(value) -> str:
    """RFC 8785: keys sorted by UTF-16 code unit, no insignificant whitespace,
    strings escaped as `json.dumps` does (the same set JCS escapes)."""
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v)
                              for k, v in items) + "}"
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    return _num(value)


def _drop_empty(value):
    if isinstance(value, dict):
        return {k: _drop_empty(v) for k, v in value.items() if v != [] and v != {}}
    if isinstance(value, list):
        return [_drop_empty(v) for v in value]
    return value


def signing_payload(card: dict) -> bytes:
    body = {k: v for k, v in card.items() if k != "signatures"}
    return jcs(_drop_empty(body)).encode()


def served_payload(card: dict) -> bytes:
    """The card as served, empty fields kept. Not the spec's form (8.4.1
    drops them), but what many signers sign: measured 2026-10-28 over the
    a2aregistry.org cards, 13 of 29 verifiable signatures verify only this
    way. Accepting it silently would hide that a strict verifier rejects
    them; rejecting it outright called them tampered, which they are not."""
    body = {k: v for k, v in card.items() if k != "signatures"}
    return jcs(body).encode()


_HASH = {"256": "SHA256", "384": "SHA384", "512": "SHA512"}
_CURVE = {"ES256": ("P-256", 32), "ES384": ("P-384", 48), "ES512": ("P-521", 66)}
ALGORITHMS = ("EdDSA", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512",
              "PS256", "PS384", "PS512")


def _int(text: str) -> int:
    return int.from_bytes(b64u_decode(text), "big")


def _verify(alg: str, jwk: dict, sig: bytes, data: bytes) -> None:
    """Raise InvalidSignature, or ValueError for a key that does not fit."""
    if alg == "EdDSA":
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError("EdDSA needs an OKP Ed25519 key")
        Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"])).verify(sig, data)
    elif alg in _CURVE:
        crv, size = _CURVE[alg]
        if jwk.get("kty") != "EC" or jwk.get("crv") != crv or len(sig) != 2 * size:
            raise ValueError(f"{alg} needs an EC {crv} key and a {2 * size}-byte signature")
        curve = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}[crv]()
        key = ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), curve).public_key()
        der = encode_dss_signature(int.from_bytes(sig[:size], "big"),
                                   int.from_bytes(sig[size:], "big"))
        key.verify(der, data, ec.ECDSA(getattr(hashes, _HASH[alg[2:]])()))
    else:  # RS*/PS*
        if jwk.get("kty") != "RSA":
            raise ValueError(f"{alg} needs an RSA key")
        key = rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
        h = getattr(hashes, _HASH[alg[2:]])()
        pad = (padding.PKCS1v15() if alg.startswith("RS")
               else padding.PSS(padding.MGF1(h), padding.PSS.DIGEST_LENGTH))
        key.verify(sig, data, pad, h)


def verify(card: dict, card_url: str, fetcher) -> list[Finding]:
    sigs = card.get("signatures")
    if not sigs:
        return []
    out: list[Finding] = []
    if not isinstance(sigs, list):
        return [Finding("warn", "signature-malformed", "'signatures' is not a list")]
    if not HAVE_CRYPTO:
        return [Finding("info", "signature-unverifiable",
                        f"{len(sigs)} signature(s) present; install "
                        "a2a-agent-checker[signatures] to verify them")]
    payload = b64u(signing_payload(card))
    served = b64u(served_payload(card))
    card_host = (urlsplit(card_url).hostname or "").lower()
    jwks_cache: dict[str, list | str] = {}

    def keys_at(jku: str):
        if jku not in jwks_cache:
            try:
                r = fetcher(jku)
                if r.status != 200:
                    jwks_cache[jku] = f"{jku} answered HTTP {r.status}"
                else:
                    keys = json.loads(r.body).get("keys")
                    jwks_cache[jku] = keys if isinstance(keys, list) else f"{jku} has no 'keys' list"
            except (FetchRefused, ValueError, AttributeError) as e:
                jwks_cache[jku] = f"could not read {jku} ({e})"
        return jwks_cache[jku]

    for i, sig in enumerate(sigs, 1):
        label = f"signature {i}"
        if not (isinstance(sig, dict) and isinstance(sig.get("protected"), str)
                and isinstance(sig.get("signature"), str)):
            out.append(Finding("warn", "signature-malformed",
                               f"{label} needs string 'protected' and 'signature'"))
            continue
        try:
            header = json.loads(b64u_decode(sig["protected"]))
            raw_sig = b64u_decode(sig["signature"])
        except ValueError:
            out.append(Finding("warn", "signature-malformed",
                               f"{label}: 'protected' or 'signature' is not base64url JSON"))
            continue
        if not isinstance(header, dict):
            out.append(Finding("warn", "signature-malformed", f"{label}: the header is not an object"))
            continue
        alg, kid, jku = header.get("alg"), header.get("kid"), header.get("jku")
        label = f"signature {i} (kid {kid!r}, {alg})"

        def unverifiable(why):
            out.append(Finding("info", "signature-unverifiable", f"{label}: {why}"))

        if alg not in ALGORITHMS:
            unverifiable(f"algorithm {alg!r} is not one this checker verifies")
            continue
        if not kid:
            out.append(Finding("warn", "signature-malformed", f"{label}: no 'kid' in the header (8.4.2)"))
        if not isinstance(jku, str) or not jku.startswith("https://"):
            unverifiable("no https 'jku' in the header, so there is no key to fetch")
            continue
        keys = keys_at(jku)
        if isinstance(keys, str):
            unverifiable(keys)
            continue
        jwk = next((k for k in keys if isinstance(k, dict) and k.get("kid") == kid), None)
        if jwk is None:
            unverifiable(f"{jku} lists no key with kid {kid!r}")
            continue
        try:
            _verify(alg, jwk, raw_sig, f"{sig['protected']}.{payload}".encode())
        except InvalidSignature:
            try:
                if served == payload:
                    raise InvalidSignature()
                _verify(alg, jwk, raw_sig, f"{sig['protected']}.{served}".encode())
            except InvalidSignature:
                out.append(Finding("warn", "signature-invalid",
                                   f"{label} does not match this card: it was changed after "
                                   "signing, or signed over a different canonical form"))
                continue
            out.append(Finding("warn", "signature-noncanonical",
                               f"{label} verifies over the card as served, not over the "
                               "spec's canonical form, which drops empty fields (8.4.1); "
                               "the card is unaltered, but a strict verifier will reject it"))
            continue
        except (ValueError, KeyError, TypeError) as e:
            unverifiable(f"the key does not fit the algorithm ({e})")
            continue
        where = ((urlsplit(jku).hostname or "").lower())
        note = ("the key is published on the card's own host, so this proves the card "
                "is unaltered, not who signed it") if where == card_host else \
            f"the key is published by {where}"
        out.append(Finding("info", "signature-valid", f"{label} is valid; {note}"))
    return out
