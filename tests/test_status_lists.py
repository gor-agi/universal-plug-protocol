# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""IETF Token Status Lists and the guarded fetching of remote documents, over a local HTTP server.
Real signatures, no network."""
import base64
import json
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("cryptography")

from upp import PlugError, allow_hosts, allow_private_networks, reset_fetch_policy, suites
from upp.ext.eudi.status_lists import StatusLists, decode_status_list, status_at
from upp.registry import _check_peer, fetch_document


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
    """A status list issuer whose key is a did:key verification method."""

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


def ref(idx, uri):
    return {"status_list": {"idx": idx, "uri": uri}}


def outcome(lists, reference, keys):
    """None when VALID, else the error as "code: message"."""
    try:
        lists.check(reference, keys)
    except PlugError as e:
        return f"{e.code}: {e.message}"
    return None


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


# ---- status and check ----

@pytest.mark.parametrize("alg", ["ecdsa-p256", "ed25519"])
def test_valid_revoked_and_suspended(server, alg):
    issuer, lists = Issuer(alg), StatusLists()
    uri = publish(server, issuer, "/sl/1", [0, 1, 2, 0], bits=2)
    expect = {0: None, 1: "proof_invalid: revoked via status list", 2: "proof_invalid: suspended via status list",
              3: None}
    for idx, error in expect.items():
        assert lists.status(ref(idx, uri), [issuer.did]) == [0, 1, 2, 0][idx]
        assert outcome(lists, ref(idx, uri), [issuer.did]) == error, idx


def test_any_named_key_may_sign_but_no_key_means_no_status(server):
    issuer, other = Issuer(), Issuer("ed25519")
    uri = publish(server, issuer, "/sl/keys", [0])
    assert outcome(StatusLists(), ref(0, uri), [other.did, issuer.did]) is None
    for keys in ([], [other.did], ["did:web:issuer.example"], [issuer.did.replace("did:key:", "did:nope:")]):
        assert outcome(StatusLists(), ref(0, uri), keys) == \
            "proof_invalid: status list token is not signed by a key of the issuer", keys


def test_out_of_range_index_fails_closed(server):
    issuer = Issuer()
    uri = publish(server, issuer, "/sl/1", [0] * 8)
    assert outcome(StatusLists(), ref(8, uri), [issuer.did]) == "proof_invalid: status list: idx is out of range"


def test_status_list_token_must_be_the_issuers_and_well_formed(server):
    issuer, stranger = Issuer(), Issuer()
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
        assert outcome(StatusLists(), ref(0, uri), [issuer.did]) == error, path
    head, body, sig = issuer.token(server.url("/tampered"), [1]).split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["status_list"]["lst"] = lst([0])
    server.docs["/tampered"] = ("application/statuslist+jwt", f"{head}.{b64u(json.dumps(claims).encode())}.{sig}")
    assert outcome(StatusLists(), ref(0, server.url("/tampered")), [issuer.did]) == \
        "proof_invalid: status list token is not signed by a key of the issuer"
    server.docs["/garbage"] = ("application/statuslist+jwt", "not.a-jwt")
    assert outcome(StatusLists(), ref(0, server.url("/garbage")), [issuer.did]).startswith("proof_invalid: ")


def test_legacy_or_malformed_status_references_are_rejected_not_skipped(server):
    issuer = Issuer()
    publish(server, issuer, "/x", [0])
    for reference in ({"status_list_url": server.url("/x"), "status_list_index": 0}, {}, None, {"status_list": {}},
                      ref(-1, server.url("/x")), ref("0", server.url("/x")), ref(True, server.url("/x")),
                      ref(0, None)):
        with pytest.raises(PlugError, match="status") as e:
            StatusLists().check(reference, [issuer.did])
        assert e.value.code == "proof_invalid", reference
    assert server.hits.get("/x", 0) == 0, "nothing is fetched for a malformed reference"


def test_cache_respects_poll_and_ttl_and_fails_closed(server):
    issuer, lists = Issuer(), StatusLists(poll=300)
    uri = publish(server, issuer, "/sl/c", [0, 1])
    assert outcome(lists, ref(0, uri), [issuer.did]) is None
    assert outcome(lists, ref(1, uri), [issuer.did]) == "proof_invalid: revoked via status list"
    assert server.hits["/sl/c"] == 1, "a fresh token is reused within the poll interval"
    assert outcome(lists, ref(0, uri), [Issuer().did]) == \
        "proof_invalid: status list token is not signed by a key of the issuer", "a cached token is re-validated"

    server.down = True
    assert outcome(StatusLists(poll=0), ref(0, uri), [issuer.did]).startswith("not_found: status list unreachable")

    server.down = False
    short = StatusLists(poll=0)
    uri2 = publish(server, issuer, "/sl/short", [0], claims={"exp": int(time.time()) + 2})
    assert outcome(short, ref(0, uri2), [issuer.did]) is None
    server.down = True
    assert outcome(short, ref(0, uri2), [issuer.did]) is None, "an unexpired cached copy is served while down"
    time.sleep(2.1)
    error = outcome(short, ref(0, uri2), [issuer.did])
    assert error is not None and "status list unreachable" in error, "never past exp"


def test_blocking_the_status_host_cannot_hide_a_revocation_for_long(server):
    issuer = Issuer()
    for kw, claims in (({"poll": 0}, {"ttl": 1}),                       # bounded by ttl
                       ({"poll": 0, "max_stale": 1}, {"ttl": 3600})):   # bounded by max_stale
        server.down = False
        lists = StatusLists(**kw)
        path = f"/sl/stale-{len(server.docs)}"
        uri = publish(server, issuer, path, [0], claims=claims)  # no exp
        assert outcome(lists, ref(0, uri), [issuer.did]) is None
        server.docs[path] = ("application/statuslist+jwt", issuer.token(uri, [1], claims=claims))
        server.down = True
        assert outcome(lists, ref(0, uri), [issuer.did]) is None, "briefly served from cache"
        time.sleep(1.2)
        error = outcome(lists, ref(0, uri), [issuer.did])
        assert error is not None and "status list unreachable" in error, kw


def test_an_older_status_list_token_cannot_roll_back_a_revocation(server):
    issuer, lists = Issuer(), StatusLists(poll=0)
    uri = server.url("/sl/rollback")
    older_valid = issuer.token(uri, [0], claims={"iat": int(time.time()) - 600})
    server.docs["/sl/rollback"] = ("application/statuslist+jwt", issuer.token(uri, [1]))
    assert outcome(lists, ref(0, uri), [issuer.did]) == "proof_invalid: revoked via status list"
    server.docs["/sl/rollback"] = ("application/statuslist+jwt", older_valid)
    assert outcome(lists, ref(0, uri), [issuer.did]) == "proof_invalid: revoked via status list"
    lists.max_stale = 0  # no cached stand-in: the rollback itself is the error
    assert outcome(lists, ref(0, uri), [issuer.did]) == \
        "proof_invalid: status list token is older than one already seen"


def test_old_status_list_tokens_are_refused_by_their_signed_iat(server):
    issuer = Issuer()
    year_ago = int(time.time()) - 365 * 86400
    lists = StatusLists(poll=1, max_stale=1)
    cases = {
        "/sl/ancient": ({"iat": year_ago, "ttl": 60}, "proof_invalid: status list token is too old"),
        "/sl/ancient-no-ttl": ({"iat": year_ago, "ttl": None}, "proof_invalid: status list token is too old"),
        "/sl/future": ({"iat": int(time.time()) + 3600}, "proof_invalid: status list token iat is in the future"),
        "/sl/recent": ({"iat": int(time.time()) - 30, "ttl": 60}, None),
    }
    for path, (claims, error) in cases.items():
        uri = publish(server, issuer, path, [0], claims=claims)
        assert outcome(lists, ref(0, uri), [issuer.did]) == error, path
    uri = publish(server, issuer, "/sl/max-age", [0], claims={"iat": int(time.time()) - 120, "ttl": None})
    assert outcome(StatusLists(max_age=60), ref(0, uri), [issuer.did]) == \
        "proof_invalid: status list token is too old"
    assert outcome(StatusLists(max_age=600), ref(0, uri), [issuer.did]) is None


@pytest.mark.parametrize("alg,jose", [("ecdsa-p256", "ES256"), ("ed25519", "Ed25519"), ("ed25519", "EdDSA")])
def test_status_list_tokens_from_an_independent_jose_library(server, alg, jose):
    """joserfc (Authlib) signs; our verifier must accept its tokens and reject its unsigned ones."""
    import warnings
    pytest.importorskip("joserfc")
    from joserfc import jwk, jwt
    issuer = Issuer(alg)
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
    path = f"/sl/joserfc-{jose}"
    uri = server.url(path)
    claims = {"sub": uri, "iat": int(time.time()), "ttl": 600, "status_list": {"bits": 1, "lst": lst([0, 1])}}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        token = jwt.encode({"alg": jose, "typ": "statuslist+jwt"}, claims, key, algorithms=[jose])
    server.docs[path] = ("application/statuslist+jwt", token)
    lists = StatusLists()
    assert outcome(lists, ref(0, uri), [issuer.did]) is None
    assert outcome(lists, ref(1, uri), [issuer.did]) == "proof_invalid: revoked via status list"
    head, body, _ = token.split(".")
    unsigned = b64u(json.dumps({"alg": "none", "typ": "statuslist+jwt"}).encode()) + "." + body + "."
    server.docs[path] = ("application/statuslist+jwt", unsigned)
    error = outcome(StatusLists(), ref(0, uri), [issuer.did])
    assert error is not None and "not signed by a key of the issuer" in error


# ---- remote document fetching: closed by default ----

def test_remote_documents_from_private_addresses_are_refused_by_default(server):
    server.docs["/r"] = ("application/json", "{}")
    allow_private_networks(False)
    for url in (server.url("/r"), "http://localhost:%d/r" % server.httpd.server_port,
                "http://[::1]:%d/r" % server.httpd.server_port):
        with pytest.raises(PlugError) as e:
            fetch_document(url)
        assert e.value.code in ("not_authorized", "not_found"), url
    assert server.hits.get("/r", 0) == 0, "no request reaches a private host"
    issuer = Issuer()
    uri = publish(server, issuer, "/sl/private", [0])
    error = outcome(StatusLists(), ref(0, uri), [issuer.did])
    assert error is not None and "not a public address" in error


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
    class Sock:
        closed = False

        def getpeername(self):
            return (peer, 80)

        def close(self):
            self.closed = True

    allow_private_networks(False)
    sock = Sock()
    if allowed:
        _check_peer(sock)
        assert not sock.closed
    else:
        with pytest.raises(PlugError, match="not a public address"):
            _check_peer(sock)
        assert sock.closed


def test_environment_proxies_are_not_used(server, monkeypatch):
    proxy = Server()
    try:
        monkeypatch.setenv("HTTP_PROXY", proxy.base)
        monkeypatch.setenv("http_proxy", proxy.base)
        server.docs["/direct"] = ("application/json", "{}")
        assert fetch_document(server.url("/direct")) == b"{}"
        assert proxy.hits == {} and server.hits["/direct"] == 1
    finally:
        proxy.httpd.shutdown()


def test_remote_documents_are_fetched_only_from_allowed_hosts(server):
    server.docs["/doc"] = ("application/json", "{}")
    reset_fetch_policy()
    allow_private_networks(True)
    with pytest.raises(PlugError, match="not allowed \\(closed by default\\)"):
        fetch_document(server.url("/doc"))
    assert server.hits.get("/doc", 0) == 0
    issuer = Issuer()
    uri = publish(server, issuer, "/sl/closed", [0])
    error = outcome(StatusLists(), ref(0, uri), [issuer.did])
    assert error is not None and error.startswith("not_authorized: status list unreachable")
    assert server.hits.get("/sl/closed", 0) == 0
    allow_hosts("127.0.0.1")
    assert fetch_document(server.url("/doc")) == b"{}"
    assert outcome(StatusLists(), ref(0, uri), [issuer.did]) is None
    with pytest.raises(PlugError, match="not allowed"):
        fetch_document(f"http://localhost:{server.httpd.server_port}/doc")
    server.docs["/hop"] = ("redirect", f"http://localhost:{server.httpd.server_port}/doc")
    hits = server.hits.get("/doc", 0)
    with pytest.raises(PlugError, match="not allowed"):
        fetch_document(server.url("/hop"))
    assert server.hits.get("/doc", 0) == hits, "a redirect to a host not allowed is not followed"
    for bad in ("*.example.org", "http://x", "", "a/b"):
        with pytest.raises(ValueError):
            allow_hosts(bad)
