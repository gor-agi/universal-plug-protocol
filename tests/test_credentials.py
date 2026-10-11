# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""SD-JWT VC and mdoc verification against trust anchors. Credentials are issued by independent implementations
(openwallet-foundation-labs/sd-jwt-python and IdentityPython pyMDOC-CBOR) under a test PKI."""
import base64
import datetime as dt
import json
import time

import pytest

pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from plug import PlugError
from plug.credentials import certificate_did, validate_chain, verify_mdoc, verify_sd_jwt_vc

NOW = dt.datetime.now(dt.timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "LU"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(NOW - dt.timedelta(days=30))
            .not_valid_after(NOW + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def _issuer(ca_key, ca_cert, cn="PID Provider", days=365):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(NOW - dt.timedelta(days=1))
            .not_valid_after(NOW + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


@pytest.fixture(scope="module")
def pki():
    root_key, root = _ca("Test PID Root")
    issuer_key, issuer = _issuer(root_key, root)
    _, rogue_root = _ca("Rogue Root")
    return {"root": root, "issuer_key": issuer_key, "issuer": issuer, "rogue_root": rogue_root}


def test_chain_validation_is_closed_and_strict(pki):
    assert validate_chain([pki["issuer"]], [pki["root"]]) == pki["issuer"]
    assert certificate_did(pki["issuer"]).startswith("did:key:zDn")
    with pytest.raises(PlugError, match="closed by default"):
        validate_chain([pki["issuer"]], [])
    with pytest.raises(PlugError, match="does not chain"):
        validate_chain([pki["issuer"]], [pki["rogue_root"]])
    with pytest.raises(PlugError, match="does not chain"):
        validate_chain([pki["issuer"]], [pki["root"]], at=NOW + dt.timedelta(days=400))


# ---- SD-JWT VC, issued by sd-jwt-python ----

def _jwk(private_key):
    jwk = pytest.importorskip("jwcrypto.jwk")
    key = jwk.JWK.from_pem(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
    fields = {k: v for k, v in key.export(private_key=True, as_dict=True).items() if k != "kid"}
    return jwk.JWK(**fields)


def _issue(pki, typ="dc+sd-jwt", exp_delta=3600, x5c=None):
    pytest.importorskip("sd_jwt")
    from sd_jwt.common import SDObj
    from sd_jwt.issuer import SDJWTIssuer
    holder = ec.generate_private_key(ec.SECP256R1())
    claims = {"iss": "https://pid.example.lu", "vct": "urn:eudi:pid:1", "iat": int(time.time()),
              "exp": int(time.time()) + exp_delta, SDObj("given_name"): "Marie", SDObj("family_name"): "Curie",
              "address": {SDObj("country"): "LU", SDObj("locality"): "Luxembourg"},
              "nationalities": [SDObj("PL"), "FR"]}
    der = pki["issuer"].public_bytes(serialization.Encoding.DER)
    issuer = SDJWTIssuer(claims, _jwk(pki["issuer_key"]), holder_key=_jwk(holder), sign_alg="ES256",
                         extra_header_parameters={"typ": typ, "x5c": x5c or [base64.b64encode(der).decode()]})
    return issuer.sd_jwt_issuance, holder


def _present(issuance, holder, disclose, nonce="n-1", aud="https://verifier.example"):
    from sd_jwt.holder import SDJWTHolder
    h = SDJWTHolder(issuance)
    h.create_presentation(disclose, nonce=nonce, aud=aud, holder_key=_jwk(holder), sign_alg="ES256")
    return h.sd_jwt_presentation


def test_sd_jwt_vc_from_an_independent_issuer_verifies(pki):
    issuance, holder = _issue(pki)
    full = verify_sd_jwt_vc(issuance, [pki["root"]])
    assert full["claims"]["given_name"] == "Marie" and full["claims"]["address"] == {"country": "LU",
                                                                                     "locality": "Luxembourg"}
    assert full["claims"]["nationalities"] == ["PL", "FR"] and full["issuer"] == certificate_did(pki["issuer"])
    presentation = _present(issuance, holder, {"given_name": True, "address": {"country": True}})
    shown = verify_sd_jwt_vc(presentation, [pki["root"]], audience="https://verifier.example", nonce="n-1")
    assert shown["claims"].get("given_name") == "Marie" and "family_name" not in shown["claims"]
    assert shown["claims"]["address"] == {"country": "LU"} and shown["holder"].startswith("did:key:zDn")


def test_sd_jwt_vc_agrees_with_the_reference_verifier(pki):
    from sd_jwt.verifier import SDJWTVerifier
    issuance, holder = _issue(pki)
    presentation = _present(issuance, holder, {"given_name": True, "nationalities": [True, False]})
    ours = verify_sd_jwt_vc(presentation, [pki["root"]], audience="https://verifier.example", nonce="n-1")
    theirs = SDJWTVerifier(presentation, lambda iss, header: _jwk(pki["issuer_key"]),
                           expected_aud="https://verifier.example", expected_nonce="n-1").get_verified_payload()
    for name in ("given_name", "nationalities", "vct", "iss"):
        assert ours["claims"].get(name) == theirs.get(name), name


def test_sd_jwt_vc_rejections(pki):
    issuance, holder = _issue(pki)
    presentation = _present(issuance, holder, {"given_name": True})
    reject = {
        "closed by default": (issuance, dict(anchors=[])),
        "does not chain": (issuance, dict(anchors=[pki["rogue_root"]])),
        "not referenced": (issuance[:-1] + "~" + base64.urlsafe_b64encode(
            json.dumps(["salt", "family_name", "Mallory"]).encode()).rstrip(b"=").decode() + "~", {}),
        "key binding is required": (issuance, dict(audience="https://verifier.example")),
        "nonce mismatch": (presentation, dict(audience="https://verifier.example", nonce="other")),
        "audience mismatch": (presentation, dict(audience="https://elsewhere.example", nonce="n-1")),
        "sd_hash does not match": (
            presentation.replace("~", "~" + issuance.split("~")[2] + "~", 1), dict(audience="https://verifier.example")),
    }
    for reason, (token, kw) in reject.items():
        kw = {"anchors": [pki["root"]], **kw}
        with pytest.raises(PlugError, match=reason):
            verify_sd_jwt_vc(token, kw.pop("anchors"), **kw)
    for reason, kw in {"typ must be": dict(typ="example+sd-jwt"), "expired": dict(exp_delta=-10)}.items():
        token, _ = _issue(pki, **kw)
        with pytest.raises(PlugError, match=reason):
            verify_sd_jwt_vc(token, [pki["root"]])


def test_sd_jwt_vc_issuer_must_sign_with_its_certified_key(pki):
    other_ca_key, other_ca = _ca("Unrelated CA")
    _, other_cert = _issuer(other_ca_key, other_ca, cn="Other")
    token, _ = _issue(pki, x5c=[base64.b64encode(other_cert.public_bytes(serialization.Encoding.DER)).decode()])
    with pytest.raises(PlugError, match="issuer signature does not verify"):
        verify_sd_jwt_vc(token, [pki["root"], other_ca])


# ---- ISO mdoc, issued by pyMDOC-CBOR ----

def _mdoc(pki, valid_days=30, data=None):
    pytest.importorskip("pymdoccbor")
    from pymdoccbor.mdoc.issuer import MdocCborIssuer
    d = pki["issuer_key"].private_numbers().private_value.to_bytes(32, "big")
    issuer = MdocCborIssuer(private_key={"KTY": "EC2", "CURVE": "P_256", "ALG": "ES256", "D": d, "KID": b"pid"},
                            alg="ES256")
    issuer.new(data=data or {"eu.europa.ec.eudi.pid.1": {"given_name": "Marie", "family_name": "Curie",
                                                         "birth_date": "1867-11-07"}},
               doctype="eu.europa.ec.eudi.pid.1",
               validity={"issuance_date": NOW.strftime("%Y-%m-%d"),
                         "expiry_date": (NOW + dt.timedelta(days=valid_days)).strftime("%Y-%m-%d")},
               x509_chain=[pki["issuer"]])
    return issuer.signed["documents"][0]["issuerSigned"]


def test_mdoc_from_an_independent_issuer_verifies(pki):
    signed = _mdoc(pki)
    out = verify_mdoc(signed, [pki["root"]], doctype="eu.europa.ec.eudi.pid.1")
    assert out["claims"]["eu.europa.ec.eudi.pid.1"]["family_name"] == "Curie"
    assert out["issuer"] == certificate_did(pki["issuer"])


def test_mdoc_rejections(pki):
    import cbor2
    signed = _mdoc(pki)
    with pytest.raises(PlugError, match="closed by default"):
        verify_mdoc(signed, [])
    with pytest.raises(PlugError, match="does not chain"):
        verify_mdoc(signed, [pki["rogue_root"]])
    with pytest.raises(PlugError, match="unexpected docType"):
        verify_mdoc(signed, [pki["root"]], doctype="org.iso.18013.5.1.mDL")
    with pytest.raises(PlugError, match="not valid at this time"):
        verify_mdoc(signed, [pki["root"]], at=NOW + dt.timedelta(days=60))
    items = signed["nameSpaces"]["eu.europa.ec.eudi.pid.1"]
    item = cbor2.loads(items[0].value) if isinstance(items[0], cbor2.CBORTag) else cbor2.loads(cbor2.loads(items[0]).value)
    item["elementValue"] = "Mallory"
    forged = dict(signed, nameSpaces={"eu.europa.ec.eudi.pid.1": [cbor2.CBORTag(24, cbor2.dumps(item))] + items[1:]})
    with pytest.raises(PlugError, match="does not match its signed digest"):
        verify_mdoc(forged, [pki["root"]])
    extra = dict(signed, nameSpaces={**signed["nameSpaces"], "unsigned.namespace": items[:1]})
    with pytest.raises(PlugError, match="no signed digests"):
        verify_mdoc(extra, [pki["root"]])
