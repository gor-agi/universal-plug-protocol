# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Credentials issued under a trust framework: SD-JWT VC (RFC 9901, draft-ietf-oauth-sd-jwt-vc) and ISO/IEC
18013-5 mdoc.

Each verifier checks the issuer's X.509 chain to the anchors you give it (for example `TrustedList.anchors`), the
issuer signature, validity, and every disclosure, and returns the disclosed claims with the issuer key as a
did:key, ready for a trust policy. Closed by default: no anchors, no credential. Requires the `eudi` extra.
"""
from __future__ import annotations
import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Iterable, Optional

from .core import PlugError
from . import suites

SD_JWT_VC_TYPES = ("dc+sd-jwt", "vc+sd-jwt")
_SKEW = 300


def _b64u(text: str) -> bytes:
    if not isinstance(text, str):
        raise PlugError("proof_invalid", "expected base64url text")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as e:
        raise PlugError("proof_invalid", f"bad base64url: {e}") from e


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def validate_chain(certificates: list, anchors: Iterable, at: Optional[datetime] = None):
    """The leaf of `certificates` once it chains to one of `anchors` at `at` (X.509, RFC 5280 via
    cryptography's verifier; issuer certificates need no TLS extended key usage). Raises PlugError."""
    from cryptography.x509 import verification as v
    anchors = list(anchors or [])
    if not anchors:
        raise PlugError("not_authorized", "no trust anchors (closed by default)")
    if not certificates:
        raise PlugError("proof_invalid", "no issuer certificate")
    at = at or datetime.now(timezone.utc)
    verifier = (v.PolicyBuilder().store(v.Store(anchors)).time(at).max_chain_depth(8)
                .extension_policies(ca_policy=v.ExtensionPolicy.webpki_defaults_ca(),
                                    ee_policy=v.ExtensionPolicy.permit_all())
                .build_client_verifier())
    try:
        verifier.verify(certificates[0], list(certificates[1:]))
    except v.VerificationError as e:
        raise PlugError("proof_invalid", f"issuer certificate does not chain to a trust anchor: {e}") from e
    return certificates[0]


def certificate_did(cert) -> str:
    """did:key of a certificate's P-256 or Ed25519 public key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    key = cert.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1":
        return suites.did_key("ecdsa-p256", key.public_bytes(serialization.Encoding.X962,
                                                              serialization.PublicFormat.CompressedPoint))
    if isinstance(key, ed25519.Ed25519PublicKey):
        return suites.did_key("ed25519", key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    raise PlugError("unsupported_op", "issuer key must be P-256 or Ed25519")


def _jwk_did(jwk: dict) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    if not isinstance(jwk, dict):
        raise PlugError("proof_invalid", "cnf.jwk must be a JWK")
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        x, y = int.from_bytes(_b64u(jwk.get("x")), "big"), int.from_bytes(_b64u(jwk.get("y")), "big")
        try:
            point = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        except ValueError as e:
            raise PlugError("proof_invalid", "cnf.jwk is not a P-256 point") from e
        return suites.did_key("ecdsa-p256", point.public_bytes(serialization.Encoding.X962,
                                                                serialization.PublicFormat.CompressedPoint))
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        return suites.did_key("ed25519", _b64u(jwk.get("x")))
    raise PlugError("unsupported_op", "holder key must be P-256 or Ed25519")


def _jws(token: str) -> tuple[dict, dict, bytes, bytes]:
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise PlugError("proof_invalid", "not a compact JWS")
    try:
        header, claims = json.loads(_b64u(parts[0])), json.loads(_b64u(parts[1]))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise PlugError("proof_invalid", f"bad JWS JSON: {e}") from e
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise PlugError("proof_invalid", "bad JWS JSON")
    return header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), _b64u(parts[2])


def _numeric(claims: dict, name: str):
    value = claims.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PlugError("proof_invalid", f"{name} must be a number")
    return value


def verify_sd_jwt_vc(sd_jwt: str, anchors: Iterable, *, at: Optional[datetime] = None,
                     audience: Optional[str] = None, nonce: Optional[str] = None, max_key_binding_age: int = 300) -> dict:
    """Verify an SD-JWT VC presentation `<issuer JWT>~<disclosure>~...~[<KB-JWT>]` and return
    {"issuer": did:key, "certificate", "vct", "claims", "status", "holder"}.

    Key binding is required when `audience` or `nonce` is given, and checked whenever present."""
    at = at or datetime.now(timezone.utc)
    now = at.timestamp()
    if not isinstance(sd_jwt, str) or "~" not in sd_jwt:
        raise PlugError("proof_invalid", "not an SD-JWT")
    parts = sd_jwt.split("~")
    issuer_jwt, disclosures, kb_jwt = parts[0], parts[1:-1], parts[-1]

    header, payload, signing_input, signature = _jws(issuer_jwt)
    if header.get("typ") not in SD_JWT_VC_TYPES:
        raise PlugError("proof_invalid", f"typ must be one of {', '.join(SD_JWT_VC_TYPES)}")
    if not isinstance(header.get("x5c"), list) or not header["x5c"]:
        raise PlugError("proof_invalid", "issuer JWT carries no x5c certificate chain")
    from cryptography import x509
    try:
        chain = [x509.load_der_x509_certificate(base64.b64decode(c, validate=True)) for c in header["x5c"]]
    except (ValueError, TypeError) as e:
        raise PlugError("proof_invalid", f"bad x5c: {e}") from e
    leaf = validate_chain(chain, anchors, at)
    issuer = certificate_did(leaf)
    if not suites.verify_jws(signing_input, signature, header.get("alg", ""), issuer):
        raise PlugError("proof_invalid", "issuer signature does not verify under the certificate key")
    for name in ("iss", "vct"):
        if not isinstance(payload.get(name), str) or not payload[name]:
            raise PlugError("proof_invalid", f"SD-JWT VC needs {name}")
    exp, nbf, iat = (_numeric(payload, n) for n in ("exp", "nbf", "iat"))
    if exp is not None and now >= exp:
        raise PlugError("proof_invalid", "credential expired")
    if (nbf is not None and nbf > now + _SKEW) or (iat is not None and iat > now + _SKEW):
        raise PlugError("proof_invalid", "credential not yet valid")
    if payload.get("_sd_alg", "sha-256") != "sha-256":
        raise PlugError("unsupported_op", "only sha-256 disclosure digests are supported")

    by_digest = {}
    for d in disclosures:
        digest = _b64u_encode(hashlib.sha256(d.encode("ascii")).digest())
        if digest in by_digest:
            raise PlugError("proof_invalid", "a disclosure is presented twice")
        try:
            value = json.loads(_b64u(d))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise PlugError("proof_invalid", f"bad disclosure: {e}") from e
        if not isinstance(value, list) or len(value) not in (2, 3) or not isinstance(value[0], str):
            raise PlugError("proof_invalid", "a disclosure is [salt, value] or [salt, name, value]")
        by_digest[digest] = value
    used, seen = set(), set()

    def take(digest: str, size: int):
        if not isinstance(digest, str):
            raise PlugError("proof_invalid", "digests are strings")
        if digest in seen:
            raise PlugError("proof_invalid", "a digest appears twice in the credential")
        seen.add(digest)
        value = by_digest.get(digest)
        if value is None:
            return None  # a decoy, or a claim the holder did not disclose
        if len(value) != size:
            raise PlugError("proof_invalid", "disclosure kind does not match where it is referenced")
        used.add(digest)
        return value

    def reveal(node):
        if isinstance(node, dict):
            if "_sd" in node and not isinstance(node["_sd"], list):
                raise PlugError("proof_invalid", "_sd must be an array")
            out = {k: reveal(v) for k, v in node.items() if k not in ("_sd", "_sd_alg")}
            for digest in node.get("_sd", []):
                value = take(digest, 3)
                if value is None:
                    continue
                _, name, claim = value
                if not isinstance(name, str) or name in ("_sd", "...") or name in out:
                    raise PlugError("proof_invalid", f"disclosed claim name {name!r} is not allowed here")
                out[name] = reveal(claim)
            return out
        if isinstance(node, list):
            out = []
            for element in node:
                if isinstance(element, dict) and set(element) == {"..."}:
                    value = take(element["..."], 2)
                    if value is not None:
                        out.append(reveal(value[1]))
                else:
                    out.append(reveal(element))
            return out
        return node

    claims = reveal(payload)
    if used != set(by_digest):
        raise PlugError("proof_invalid", "a disclosure is not referenced by the issuer-signed credential")

    holder = None
    if kb_jwt or audience is not None or nonce is not None:
        if not kb_jwt:
            raise PlugError("proof_invalid", "key binding is required")
        kb_header, kb, kb_input, kb_sig = _jws(kb_jwt)
        if kb_header.get("typ") != "kb+jwt":
            raise PlugError("proof_invalid", "key binding JWT typ must be kb+jwt")
        holder = _jwk_did((payload.get("cnf") or {}).get("jwk"))
        if not suites.verify_jws(kb_input, kb_sig, kb_header.get("alg", ""), holder):
            raise PlugError("proof_invalid", "key binding signature does not verify under cnf.jwk")
        presented = "~".join(parts[:-1]) + "~"
        if kb.get("sd_hash") != _b64u_encode(hashlib.sha256(presented.encode("ascii")).digest()):
            raise PlugError("proof_invalid", "key binding sd_hash does not match the presentation")
        if audience is not None and kb.get("aud") != audience:
            raise PlugError("proof_invalid", "key binding audience mismatch")
        if nonce is not None and kb.get("nonce") != nonce:
            raise PlugError("proof_invalid", "key binding nonce mismatch")
        kb_iat = _numeric(kb, "iat")
        if kb_iat is None or not now - max_key_binding_age <= kb_iat <= now + _SKEW:
            raise PlugError("proof_invalid", "key binding is not fresh")
    return {"issuer": issuer, "certificate": leaf, "vct": payload["vct"], "claims": claims,
            "status": payload.get("status"), "holder": holder}


def verify_mdoc(issuer_signed, anchors: Iterable, *, at: Optional[datetime] = None,
                doctype: Optional[str] = None) -> dict:
    """Verify an ISO/IEC 18013-5 IssuerSigned structure ({"nameSpaces", "issuerAuth"}, as a dict or CBOR bytes)
    and return {"issuer": did:key, "certificate", "doctype", "claims": {namespace: {element: value}}}."""
    import cbor2
    from cryptography import x509
    from pymdoccbor.mso.verifier import MsoVerifier
    at = at or datetime.now(timezone.utc)
    if isinstance(issuer_signed, (bytes, bytearray)):
        issuer_signed = cbor2.loads(issuer_signed)
    if not isinstance(issuer_signed, dict) or "issuerAuth" not in issuer_signed:
        raise PlugError("proof_invalid", "not an IssuerSigned structure")
    namespaces = issuer_signed.get("nameSpaces") or {}
    try:
        mso = MsoVerifier(issuer_signed["issuerAuth"])
        chain = [x509.load_der_x509_certificate(c) for c in mso.raw_public_keys]
    except Exception as e:
        raise PlugError("proof_invalid", f"bad issuerAuth: {type(e).__name__}") from e
    leaf = validate_chain(chain, anchors, at)  # strict path validation first; pymdoccbor's own check is weaker
    issuer = certificate_did(leaf)
    try:
        signed = mso.verify_signature(trusted_root_certs=list(anchors))
    except Exception as e:
        raise PlugError("proof_invalid", f"issuer signature: {type(e).__name__}") from e
    if not signed:
        raise PlugError("proof_invalid", "issuer signature does not verify")
    payload = mso.payload_as_dict
    if doctype is not None and payload.get("docType") != doctype:
        raise PlugError("proof_invalid", "unexpected docType")
    if payload.get("digestAlgorithm") != "SHA-256":
        raise PlugError("unsupported_op", "only SHA-256 element digests are supported")
    validity = payload.get("validityInfo") or {}

    def when(name):
        value = validity.get(name)
        value = getattr(value, "value", value)
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc)
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError as e:
            raise PlugError("proof_invalid", f"bad validityInfo.{name}") from e
    if not when("validFrom").timestamp() - _SKEW <= at.timestamp() < when("validUntil").timestamp():
        raise PlugError("proof_invalid", "mdoc is not valid at this time")
    digests = payload.get("valueDigests") or {}
    if not namespaces or any(ns not in digests for ns in namespaces):
        raise PlugError("proof_invalid", "a disclosed namespace has no signed digests")
    checked = mso.verify_element_hashes(namespaces)
    if not checked.get("valid") or checked.get("failed") or checked.get("total", 0) == 0:
        raise PlugError("proof_invalid", "a disclosed element does not match its signed digest")
    claims = {}
    for ns, items in namespaces.items():
        for item in items:
            raw = cbor2.dumps(item) if isinstance(item, cbor2.CBORTag) else item
            decoded = cbor2.loads(raw)
            decoded = cbor2.loads(decoded.value) if isinstance(decoded, cbor2.CBORTag) else decoded
            claims.setdefault(ns, {})[decoded["elementIdentifier"]] = decoded["elementValue"]
    return {"issuer": issuer, "certificate": leaf, "doctype": payload.get("docType"), "claims": claims}
