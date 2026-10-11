# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""SD-JWT VC and mdoc verification against trust anchors. Credentials are issued by independent implementations
(openwallet-foundation-labs/sd-jwt-python and IdentityPython pyMDOC-CBOR) under a test PKI."""
import base64
import datetime as dt
import json
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from upp import PlugError
from upp.ext.eudi.credentials import certificate_did, validate_chain, verify_mdoc, verify_sd_jwt_vc

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


def _issue(pki, typ="dc+sd-jwt", exp_delta=3600, x5c=None, extra=None):
    pytest.importorskip("sd_jwt")
    from sd_jwt.common import SDObj
    from sd_jwt.issuer import SDJWTIssuer
    holder = ec.generate_private_key(ec.SECP256R1())
    claims = {"iss": "https://pid.example.lu", "vct": "urn:eudi:pid:1", "iat": int(time.time()),
              "exp": int(time.time()) + exp_delta, SDObj("given_name"): "Marie", SDObj("family_name"): "Curie",
              "address": {SDObj("country"): "LU", SDObj("locality"): "Luxembourg"},
              "nationalities": [SDObj("PL"), "FR"], **(extra or {})}
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


# ---- SD-JWT VC with a status claim: closed unless a status list shows it VALID ----

class _StatusServer:
    def __init__(self):
        self.docs, self.hits = {}, {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hits[self.path] = outer.hits.get(self.path, 0) + 1
                body = outer.docs.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/statuslist+jwt")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def url(self, path):
        return f"http://127.0.0.1:{self.httpd.server_port}{path}"


@pytest.fixture
def status_server():
    s = _StatusServer()
    yield s
    s.httpd.shutdown()


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _status_token(private_key, uri, statuses):
    """A Status List Token (bits 1) signed ES256 by `private_key`."""
    from upp import suites
    array = bytearray((len(statuses) + 7) // 8)
    for i, value in enumerate(statuses):
        array[i // 8] |= value << (i % 8)
    head = {"alg": "ES256", "typ": "statuslist+jwt"}
    body = {"sub": uri, "iat": int(time.time()), "ttl": 600,
            "status_list": {"bits": 1, "lst": _b64u(zlib.compress(bytes(array), 9))}}
    signing_input = f"{_b64u(json.dumps(head).encode())}.{_b64u(json.dumps(body).encode())}"
    sig, _ = suites._p256_sign(f"{private_key.private_numbers().private_value:064x}", signing_input.encode())
    return f"{signing_input}.{_b64u(sig)}".encode()


def test_sd_jwt_vc_with_a_status_is_closed_without_status_lists(pki, status_server):
    uri = status_server.url("/sl/pid")
    status_server.docs["/sl/pid"] = _status_token(pki["issuer_key"], uri, [0, 1])
    token, _ = _issue(pki, extra={"status": {"status_list": {"idx": 0, "uri": uri}}})
    with pytest.raises(PlugError, match="pass status_lists") as e:
        verify_sd_jwt_vc(token, [pki["root"]])
    assert e.value.code == "not_authorized"


def test_sd_jwt_vc_status_is_checked_against_the_issuers_status_list(pki, status_server):
    from upp.ext.eudi.status_lists import StatusLists
    uri = status_server.url("/sl/pid")
    status_server.docs["/sl/pid"] = _status_token(pki["issuer_key"], uri, [0, 1])
    lists = StatusLists()
    valid, _ = _issue(pki, extra={"status": {"status_list": {"idx": 0, "uri": uri}}})
    out = verify_sd_jwt_vc(valid, [pki["root"]], status_lists=lists)
    assert out["status"] == {"status_list": {"idx": 0, "uri": uri}}
    assert out["issuer"] == certificate_did(pki["issuer"])
    revoked, _ = _issue(pki, extra={"status": {"status_list": {"idx": 1, "uri": uri}}})
    with pytest.raises(PlugError, match="revoked via status list") as e:
        verify_sd_jwt_vc(revoked, [pki["root"]], status_lists=lists)
    assert e.value.code == "proof_invalid"


def test_sd_jwt_vc_status_list_must_be_signed_by_the_credential_issuer(pki, status_server):
    from upp.ext.eudi.status_lists import StatusLists
    uri = status_server.url("/sl/forged")
    status_server.docs["/sl/forged"] = _status_token(ec.generate_private_key(ec.SECP256R1()), uri, [0])
    token, _ = _issue(pki, extra={"status": {"status_list": {"idx": 0, "uri": uri}}})
    with pytest.raises(PlugError, match="not signed by a key of the issuer"):
        verify_sd_jwt_vc(token, [pki["root"]], status_lists=StatusLists())


def test_status_list_is_fetched_only_after_the_credential_signature_verifies(pki, status_server):
    from upp.ext.eudi.status_lists import StatusLists
    other_ca_key, other_ca = _ca("Unrelated CA")
    _, other_cert = _issuer(other_ca_key, other_ca, cn="Other")
    uri = status_server.url("/sl/order")
    status_server.docs["/sl/order"] = _status_token(pki["issuer_key"], uri, [0])
    forged, _ = _issue(pki, x5c=[base64.b64encode(other_cert.public_bytes(serialization.Encoding.DER)).decode()],
                       extra={"status": {"status_list": {"idx": 0, "uri": uri}}})
    with pytest.raises(PlugError, match="issuer signature does not verify"):
        verify_sd_jwt_vc(forged, [pki["root"], other_ca], status_lists=StatusLists())
    assert status_server.hits.get("/sl/order", 0) == 0


def test_sd_jwt_vc_without_a_status_needs_no_status_lists(pki):
    token, _ = _issue(pki)
    assert verify_sd_jwt_vc(token, [pki["root"]])["status"] is None


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
