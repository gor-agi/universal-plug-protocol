# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""EudiAdapter: trusted lists and IETF Token Status Lists over a local HTTP server. Real signatures, no network."""
import base64
import json
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("cryptography")

from plug import ANY
from plug import suites
from plug.adapters.eudi import EudiAdapter, decode_status_list, status_at
from plug.core import Attestation, Plug, PlugError, statement_hash

NET = "eudi"
NOW = lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Server:
    """Serves path -> (content type, body); counts hits; can go down."""

    def __init__(self):
        self.docs, self.hits, self.down = {}, {}, False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hits[self.path] = outer.hits.get(self.path, 0) + 1
                if outer.down or self.path not in outer.docs:
                    self.send_response(503 if outer.down else 404)
                    self.end_headers()
                    return
                ctype, body = outer.docs[self.path]
                if ctype == "redirect":
                    self.send_response(302)
                    self.send_header("Location", body)
                    self.end_headers()
                    return
                raw = body if isinstance(body, bytes) else body.encode()
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def url(self, path):
        return self.base + path


@pytest.fixture
def server():
    s = Server()
    yield s
    s.httpd.shutdown()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def lst(statuses, bits=1) -> str:
    array = bytearray((len(statuses) * bits + 7) // 8)
    for i, value in enumerate(statuses):
        array[(i * bits) // 8] |= value << ((i * bits) % 8)
    return b64u(zlib.compress(bytes(array), 9))


class Issuer:
    def __init__(self, alg="ecdsa-p256"):
        self.alg, self.key = alg, suites.generate_key(alg)
        self.did = suites.sign(alg, self.key, "00" * 32)["verification_method"]

    def token(self, uri, statuses=None, bits=1, header=None, claims=None, status_list=None):
        jose = {"ecdsa-p256": "ES256", "ed25519": "EdDSA"}[self.alg]
        head = dict({"alg": jose, "typ": "statuslist+jwt", "kid": self.did}, **(header or {}))
        body = dict({"sub": uri, "iat": int(time.time()), "ttl": 3600,
                     "status_list": status_list or {"bits": bits, "lst": lst(statuses or [0], bits)}},
                    **(claims or {}))
        signing_input = f"{b64u(json.dumps(head).encode())}.{b64u(json.dumps(body).encode())}"
        signer = {"ecdsa-p256": suites._p256_sign, "ed25519": suites._ed_sign}[self.alg]
        sig, _ = signer(self.key, signing_input.encode())
        return f"{signing_input}.{b64u(sig)}"

    def credential(self, p, fact, idx, uri, issuer=None):
        meta = {"status": {"status_list": {"idx": idx, "uri": uri}}} if uri else {}
        att = Attestation(suites.digest(fact.encode()), "identity.pid", issuer or self.did, NOW(), meta=meta)
        att.proof = suites.sign(self.alg, self.key, statement_hash(att))
        p.attest(NET, att)
        return att


def plug(**kw):
    p = Plug(trust={NET: ANY})
    p.register_adapter(NET, EudiAdapter(**kw))
    return p


def publish(server, issuer, path, statuses, bits=1, **kw):
    server.docs[path] = ("application/statuslist+jwt", issuer.token(server.url(path), statuses, bits, **kw))
    return server.url(path)


# ---- the draft's own examples (draft-ietf-oauth-status-list, section 4.2) ----

def test_decodes_the_drafts_worked_examples():
    bits, array = decode_status_list({"bits": 1, "lst": "eNrbuRgAAhcBXQ"})
    assert array == bytes([0xB9, 0xA3])
    assert [status_at(bits, array, i) for i in range(16)] == [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]
    bits, array = decode_status_list({"bits": 2, "lst": "eNo76fITAAPfAgc"})
    assert array == bytes([0xC9, 0x44, 0xF9])
    assert [status_at(bits, array, i) for i in range(12)] == [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3]
    with pytest.raises(PlugError, match="out of range"):
        status_at(1, bytes([0xB9, 0xA3]), 16)


def test_malformed_and_oversized_lists_are_rejected():
    for bad in ({"bits": 3, "lst": "eNrbuRgAAhcBXQ"}, {"bits": True, "lst": "eNrbuRgAAhcBXQ"},
                {"bits": 1, "lst": b64u(b"not zlib")}, {"bits": 1, "lst": 7}, "nope",
                {"bits": 1, "lst": b64u(zlib.compress(bytes(32))[:-4])}):
        with pytest.raises(PlugError):
            decode_status_list(bad)
    bomb = b64u(zlib.compress(bytes(17 << 20), 9))
    with pytest.raises(PlugError, match="too large"):
        decode_status_list({"bits": 1, "lst": bomb})


# ---- status checks through check() ----

@pytest.mark.parametrize("alg", ["ecdsa-p256", "ed25519"])
def test_valid_revoked_and_suspended(server, alg):
    issuer, p = Issuer(alg), plug()
    uri = publish(server, issuer, "/sl/1", [0, 1, 2, 0], bits=2)
    expect = {0: None, 1: "proof_invalid: revoked via status list", 2: "proof_invalid: suspended via status list"}
    for idx, error in expect.items():
        v = p.check(issuer.credential(p, f"pid-{idx}", idx, uri), network=NET)
        assert v["valid"] is (error is None) and v["receipt"].error == error, idx


def test_out_of_range_index_fails_closed(server):
    issuer, p = Issuer(), plug()
    uri = publish(server, issuer, "/sl/1", [0] * 8)
    v = p.check(issuer.credential(p, "pid", 8, uri), network=NET)
    assert v["receipt"].error == "proof_invalid: status list: idx is out of range"


def test_status_list_token_must_be_the_issuers_and_well_formed(server):
    issuer, stranger, p = Issuer(), Issuer(), plug()
    cases = {
        "/forged": (stranger, {}, "proof_invalid: status list token is not signed by a key of the issuer"),
        "/typ": (issuer, {"header": {"typ": "JWT"}}, "proof_invalid: status list token typ is not statuslist+jwt"),
        "/sub": (issuer, {"claims": {"sub": "https://elsewhere.example/sl"}},
                 "proof_invalid: status list token sub does not match the reference uri"),
        "/exp": (issuer, {"claims": {"exp": int(time.time()) - 1}}, "proof_invalid: status list token expired"),
        "/iat": (issuer, {"claims": {"iat": None}}, "proof_invalid: status list token has no iat"),
        "/alg": (issuer, {"header": {"alg": "none"}},
                 "proof_invalid: status list token is not signed by a key of the issuer"),
    }
    for path, (signer, kw, error) in cases.items():
        uri = publish(server, signer, path, [0], **kw)
        v = p.check(issuer.credential(p, path, 0, uri), network=NET)
        assert v["valid"] is False and v["receipt"].error == error, path
    head, body, sig = issuer.token(server.url("/tampered"), [1]).split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["status_list"]["lst"] = lst([0])
    server.docs["/tampered"] = ("application/statuslist+jwt", f"{head}.{b64u(json.dumps(claims).encode())}.{sig}")
    v = p.check(issuer.credential(p, "tampered", 0, server.url("/tampered")), network=NET)
    assert v["receipt"].error == "proof_invalid: status list token is not signed by a key of the issuer"


def test_legacy_or_malformed_status_references_are_rejected_not_skipped(server):
    issuer, p = Issuer(), plug()
    for meta in ({"status_list_url": server.url("/x"), "status_list_index": 0}, {"status": {}},
                 {"status": {"status_list": {"idx": -1, "uri": server.url("/x")}}},
                 {"status": {"status_list": {"idx": "0", "uri": server.url("/x")}}}):
        att = Attestation(suites.digest(json.dumps(meta).encode()), "identity.pid", issuer.did, NOW(), meta=meta)
        att.proof = suites.sign(issuer.alg, issuer.key, statement_hash(att))
        p.attest(NET, att)
        v = p.check(att, network=NET)
        assert v["valid"] is False and "status list" in v["receipt"].error, meta


def test_cache_respects_poll_and_ttl_and_fails_closed(server):
    issuer, p = Issuer(), plug(status_list_poll=300)
    uri = publish(server, issuer, "/sl/c", [0, 1])
    good, revoked = issuer.credential(p, "a", 0, uri), issuer.credential(p, "b", 1, uri)
    assert p.check(good, network=NET)["valid"] is True
    assert p.check(revoked, network=NET)["valid"] is False
    assert server.hits["/sl/c"] == 1, "a fresh token is reused within the poll interval"

    server.down = True
    p0 = plug(status_list_poll=0)
    assert p0.check(issuer.credential(p0, "c", 0, uri), network=NET)["receipt"].error.startswith(
        "not_found: status list unreachable")

    server.down = False
    short = plug(status_list_poll=0)
    uri2 = publish(server, issuer, "/sl/short", [0], claims={"exp": int(time.time()) + 2})
    att = issuer.credential(short, "d", 0, uri2)
    assert short.check(att, network=NET)["valid"] is True
    server.down = True
    assert short.check(att, network=NET)["valid"] is True, "an unexpired cached copy is served while down"
    time.sleep(2.1)
    v = short.check(att, network=NET)
    assert v["valid"] is False and "status list unreachable" in v["receipt"].error, "never past exp"


# ---- trusted lists ----

def test_trusted_lists_supply_issuers_and_keys(server):
    provider = Issuer()
    did_web = "did:web:pid-provider.example"
    server.docs["/tl/a.json"] = ("application/json", json.dumps({"issuers": [did_web]}))
    server.docs["/tl/b.json"] = ("application/json", json.dumps(
        {"issuers": ["did:web:other.example"], "keys": {did_web: [{"verification_method": provider.did}]}}))
    p = plug(trusted_lists=[server.url("/tl/a.json"), server.url("/tl/b.json")])
    uri = publish(server, provider, "/sl/web", [0, 1])
    v = p.check(provider.credential(p, "pid", 0, uri, issuer=did_web), network=NET)
    assert v["valid"] is True, v["receipt"].error
    assert v["receipt"].data["trust_registry"]["keys"][did_web][0]["verification_method"] == provider.did
    assert p.check(provider.credential(p, "pid-r", 1, uri, issuer=did_web), network=NET)["receipt"].error == \
        "proof_invalid: revoked via status list"

    outsider = Issuer()
    v = p.check(outsider.credential(p, "x", 0, None), network=NET)
    assert v["receipt"].error == "not_authorized: issuer not in trust registry"

    explicit = {"issuers": [outsider.did]}
    v = p.check(outsider.credential(p, "y", 0, None), network=NET, trust_registry=explicit)
    assert v["receipt"].error == "not_authorized: issuer not in trust registry", "a caller cannot widen operator trust"
    narrowed = p.check(provider.credential(p, "pid-n", 0, uri, issuer=did_web), network=NET,
                       trust_registry={"issuers": ["did:web:someone-else.example"]})
    assert narrowed["receipt"].error == "not_authorized: issuer not in trust registry", "but it can narrow it"
    both = p.check(provider.credential(p, "pid-b", 0, uri, issuer=did_web), network=NET,
                   trust_registry={"issuers": [did_web]})
    assert both["valid"] is True, both["receipt"].error

    down = plug(trusted_lists=[server.url("/tl/a.json"), server.url("/tl/missing.json")])
    v = down.check(provider.credential(down, "z", 0, uri, issuer=did_web), network=NET)
    assert v["valid"] is False and "trusted list" in v["receipt"].error


def test_remote_documents_from_private_addresses_are_refused_by_default(server):
    from plug.adapters import base
    from plug.adapters.base import fetch_document
    server.docs["/r"] = ("application/json", "{}")
    redirect_to_local = Server()
    try:
        base.allow_private_networks(False)
        for url in (server.url("/r"), "http://localhost:%d/r" % server.httpd.server_port,
                    "http://[::1]:%d/r" % server.httpd.server_port):
            with pytest.raises(PlugError) as e:
                fetch_document(url)
            assert e.value.code in ("not_authorized", "not_found"), url
        assert server.hits.get("/r", 0) == 0, "no request reaches a private host"
        issuer, p = Issuer(), plug()
        uri = publish(server, issuer, "/sl/private", [0])
        v = p.check(issuer.credential(p, "pid", 0, uri), network=NET)
        assert v["valid"] is False and "not a public address" in v["receipt"].error
    finally:
        base.allow_private_networks(True)
        redirect_to_local.httpd.shutdown()


def test_status_list_is_fetched_only_after_the_credential_signature_verifies(server):
    issuer, forger, p = Issuer(), Issuer(), plug()
    uri = publish(server, issuer, "/sl/order", [0])
    att = Attestation(suites.digest(b"forged"), "identity.pid", issuer.did, NOW(),
                      meta={"status": {"status_list": {"idx": 0, "uri": uri}}})
    att.proof = suites.sign(forger.alg, forger.key, statement_hash(att))
    p.attest(NET, att)
    assert p.check(att, network=NET)["valid"] is False
    assert server.hits.get("/sl/order", 0) == 0


def test_blocking_the_status_host_cannot_hide_a_revocation_for_long(server):
    issuer = Issuer()
    for kw, claims in (({"status_list_poll": 0}, {"ttl": 1}),                              # bounded by ttl
                       ({"status_list_poll": 0, "status_list_max_stale": 1}, {"ttl": 3600})):  # bounded by max_stale
        server.down = False
        p = plug(**kw)
        path = f"/sl/stale-{len(server.docs)}"
        uri = publish(server, issuer, path, [0], claims=claims)  # no exp
        att = issuer.credential(p, path, 0, uri)
        assert p.check(att, network=NET)["valid"] is True
        server.docs[path] = ("application/statuslist+jwt", issuer.token(uri, [1], claims=claims))
        server.down = True
        assert p.check(att, network=NET)["valid"] is True, "briefly served from cache"
        time.sleep(1.2)
        v = p.check(att, network=NET)
        assert v["valid"] is False and "status list unreachable" in v["receipt"].error, kw


def test_an_older_status_list_token_cannot_roll_back_a_revocation(server):
    issuer, p = Issuer(), plug(status_list_poll=0)
    uri = server.url("/sl/rollback")
    older_valid = issuer.token(uri, [0], claims={"iat": int(time.time()) - 600})
    server.docs["/sl/rollback"] = ("application/statuslist+jwt", issuer.token(uri, [1]))
    att = issuer.credential(p, "rb", 0, uri)
    assert p.check(att, network=NET)["receipt"].error == "proof_invalid: revoked via status list"
    server.docs["/sl/rollback"] = ("application/statuslist+jwt", older_valid)
    assert p.check(att, network=NET)["receipt"].error == "proof_invalid: revoked via status list"
    p._adapter(NET).status_list_max_stale = 0  # no cached stand-in: the rollback itself is the error
    v = p.check(att, network=NET)
    assert v["receipt"].error == "proof_invalid: status list token is older than one already seen"


@pytest.mark.parametrize("peer,allowed", [
    ("8.8.8.8", True), ("2001:4860:4860::8888", True), ("::ffff:8.8.8.8", True), ("64:ff9b::808:808", True),
    ("127.0.0.1", False), ("10.0.0.5", False), ("169.254.169.254", False), ("::1", False), ("fe80::1%en0", False),
    ("::ffff:10.0.0.1", False), ("64:ff9b::a00:5", False), ("64:ff9b::a9fe:a9fe", False), ("64:ff9b:1::a00:5", False),
    ("2002:a00:1::1", False), ("2001:0:4136:e378:8000:63bf:f5ff:fffe", False), ("100.64.0.1", False),
    ("198.18.0.1", False), ("192.0.0.1", False), ("3fff::1", False), ("5f00::1", False), ("0.0.0.0", False),
    ("255.255.255.255", False), ("224.0.0.1", False), ("ff02::1", False), ("ff0e::1", False),
    ("::a00:1", False), ("::808:808", False), ("::ffff:0:a00:1", False), ("64:ff9b:1::808:808", False),
])
def test_peer_address_guard(peer, allowed):
    from plug.adapters import base

    class Sock:
        closed = False

        def getpeername(self):
            return (peer, 80)

        def close(self):
            self.closed = True

    base.allow_private_networks(False)
    try:
        sock = Sock()
        if allowed:
            base._check_peer(sock)
            assert not sock.closed
        else:
            with pytest.raises(PlugError, match="not a public address"):
                base._check_peer(sock)
            assert sock.closed
    finally:
        base.allow_private_networks(True)


def test_environment_proxies_are_not_used(server, monkeypatch):
    from plug.adapters.base import fetch_document
    proxy = Server()
    try:
        monkeypatch.setenv("HTTP_PROXY", proxy.base)
        monkeypatch.setenv("http_proxy", proxy.base)
        server.docs["/direct"] = ("application/json", "{}")
        assert fetch_document(server.url("/direct")) == b"{}"
        assert proxy.hits == {} and server.hits["/direct"] == 1
    finally:
        proxy.httpd.shutdown()


def test_old_status_list_tokens_are_refused_by_their_signed_iat(server):
    issuer = Issuer()
    year_ago = int(time.time()) - 365 * 86400
    p = plug(status_list_poll=1, status_list_max_stale=1)
    cases = {
        "/sl/ancient": ({"iat": year_ago, "ttl": 60}, "proof_invalid: status list token is too old"),
        "/sl/ancient-no-ttl": ({"iat": year_ago, "ttl": None}, "proof_invalid: status list token is too old"),
        "/sl/future": ({"iat": int(time.time()) + 3600}, "proof_invalid: status list token iat is in the future"),
        "/sl/recent": ({"iat": int(time.time()) - 30, "ttl": 60}, None),
    }
    for path, (claims, error) in cases.items():
        uri = publish(server, issuer, path, [0], claims=claims)
        v = p.check(issuer.credential(p, path, 0, uri), network=NET)
        assert v["receipt"].error == error, path


@pytest.mark.parametrize("alg,jose", [("ecdsa-p256", "ES256"), ("ed25519", "Ed25519"), ("ed25519", "EdDSA")])
def test_status_list_tokens_from_an_independent_jose_library(server, alg, jose):
    """joserfc (Authlib) signs; our verifier must accept its tokens and reject its unsigned ones."""
    import warnings
    pytest.importorskip("joserfc")
    from joserfc import jwk, jwt
    issuer, p = Issuer(alg), plug()
    if alg == "ecdsa-p256":
        from cryptography.hazmat.primitives.asymmetric import ec
        numbers = ec.derive_private_key(int(issuer.key, 16), ec.SECP256R1()).private_numbers()
        key = jwk.ECKey.import_key({"kty": "EC", "crv": "P-256", "d": b64u(numbers.private_value.to_bytes(32, "big")),
                                    "x": b64u(numbers.public_numbers.x.to_bytes(32, "big")),
                                    "y": b64u(numbers.public_numbers.y.to_bytes(32, "big"))})
    else:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        public = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(issuer.key)).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key = jwk.OKPKey.import_key({"kty": "OKP", "crv": "Ed25519", "d": b64u(bytes.fromhex(issuer.key)),
                                     "x": b64u(public)})
    uri = server.url(f"/sl/joserfc-{jose}")
    claims = {"sub": uri, "iat": int(time.time()), "ttl": 600, "status_list": {"bits": 1, "lst": lst([0, 1])}}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        token = jwt.encode({"alg": jose, "typ": "statuslist+jwt"}, claims, key, algorithms=[jose])
    server.docs[f"/sl/joserfc-{jose}"] = ("application/statuslist+jwt", token)
    assert p.check(issuer.credential(p, f"ok-{jose}", 0, uri), network=NET)["valid"] is True
    assert p.check(issuer.credential(p, f"rev-{jose}", 1, uri), network=NET)["receipt"].error == \
        "proof_invalid: revoked via status list"
    head, body, _ = token.split(".")
    unsigned = b64u(json.dumps({"alg": "none", "typ": "statuslist+jwt"}).encode()) + "." + body + "."
    server.docs[f"/sl/joserfc-{jose}"] = ("application/statuslist+jwt", unsigned)
    fresh = plug()
    v = fresh.check(issuer.credential(fresh, f"none-{jose}", 0, uri), network=NET)
    assert v["valid"] is False and "not signed by a key of the issuer" in v["receipt"].error


def test_remote_documents_are_fetched_only_from_allowed_hosts(server):
    from plug.adapters import base
    from plug.adapters.base import fetch_document
    server.docs["/doc"] = ("application/json", "{}")
    base.reset_fetch_policy()
    base.allow_private_networks(True)
    with pytest.raises(PlugError, match="not allowed \\(closed by default\\)"):
        fetch_document(server.url("/doc"))
    assert server.hits.get("/doc", 0) == 0
    base.allow_hosts("127.0.0.1")
    assert fetch_document(server.url("/doc")) == b"{}"
    with pytest.raises(PlugError, match="not allowed"):
        fetch_document(f"http://localhost:{server.httpd.server_port}/doc")
    server.docs["/hop"] = ("redirect", f"http://localhost:{server.httpd.server_port}/doc")
    hits = server.hits.get("/doc", 0)
    with pytest.raises(PlugError, match="not allowed"):
        fetch_document(server.url("/hop"))
    assert server.hits.get("/doc", 0) == hits, "a redirect to a host not allowed is not followed"
    for bad in ("*.example.org", "http://x", "", "a/b"):
        with pytest.raises(ValueError):
            base.allow_hosts(bad)

