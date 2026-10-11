# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Keyed trust registries: issuer keys with validity windows, judged at the time the ledger anchored the statement."""
import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from upp import ANY, Attestation, LocalLedger, Plug, Status, sha256_hex, statement_hash
from upp.core import parse_time
from upp.registry import check_signature, registry_key_status, resolve_registry
from upp.suites import KeySigner, generate_key

pytest.importorskip("cryptography")

NET = "eudi"
NOW = datetime.now(timezone.utc)
ISSUER = "did:web:pid-provider.example"  # a DID method nothing resolves on its own


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class NamedSigner:
    """An issuer known by a DID that does not name its key (did:web): the key comes from a trust registry."""

    def __init__(self, did=ISSUER, alg="ecdsa-p256"):
        self._inner = KeySigner(alg, generate_key(alg))
        self.verification_method = did
        self.key_method = self._inner.verification_method

    def sign(self, message):
        return self._inner.sign(message)


@pytest.fixture
def ledger_path():
    """A JSONL ledger file inside the repository, removed afterwards."""
    path = os.path.join(os.path.dirname(__file__), f".ledger-{secrets.token_hex(6)}.jsonl")
    yield path
    if os.path.exists(path):
        os.remove(path)


def plug(path=None):
    p = Plug(trust={NET: ANY})
    p.register(NET, LocalLedger(path))
    return p


def issue(p, signer, subject, issued=NOW):
    p.open(NET, {"signer": signer})
    r = p.attest(Attestation(subject, "identity.pid", signer.verification_method, iso(issued)), NET)
    assert r.status == Status.OK
    return Attestation.from_receipt(r)


def keys(*entries):
    return {"issuers": [ISSUER], "keys": {ISSUER: list(entries)}}


def test_registry_keys_make_an_unresolvable_issuer_verifiable():
    p, signer = plug(), NamedSigner()
    att = issue(p, signer, sha256_hex(b"pid credential"))
    assert p.check(att)["receipt"].error == "proof_invalid: unverifiable issuer"
    registry = keys({"verification_method": signer.key_method})
    v = p.check(att, trust_registry=registry)
    assert v["valid"] is True, v["receipt"].error
    assert v["receipt"].data["verification_method"] == signer.key_method
    anchored = parse_time(v["receipt"].data["anchored_at"])
    assert v["receipt"].data["key_checked_at"] == iso(anchored), "the key is judged at the anchoring time"
    other = issue(p, NamedSigner(), sha256_hex(b"another credential"))
    v = p.check(other, trust_registry=registry)
    assert v["receipt"].error == "proof_invalid: key not listed for issuer in trust registry"


def test_rotated_or_revoked_key_fails_whatever_issuance_the_issuer_claims():
    p, old, new = plug(), NamedSigner(), NamedSigner()
    registry = keys({"verification_method": old.key_method, "valid_until": iso(NOW - timedelta(days=1))},
                    {"verification_method": new.key_method, "valid_from": iso(NOW - timedelta(days=1))})
    month_ago = NOW - timedelta(days=30)
    backdated = issue(p, old, sha256_hex(b"claims backdated issuance"), month_ago)  # issued_at is a claim
    v = p.check(backdated, trust_registry=registry)
    assert v["receipt"].error.startswith("proof_invalid: key not valid at")
    current = issue(p, new, sha256_hex(b"claims backdated issuance"), month_ago)
    assert p.check(current, trust_registry=registry)["valid"] is True


def test_ledger_judges_the_key_at_anchored_time():
    p, signer = plug(), NamedSigner()
    att = issue(p, signer, sha256_hex(b"signed while the key was valid"))
    anchored = parse_time(p.check(att, trust_registry=keys({"verification_method": signer.key_method}))
                          ["receipt"].data["anchored_at"])
    revoked_later = keys({"verification_method": signer.key_method, "valid_until": iso(anchored + timedelta(seconds=1))})
    assert p.check(att, trust_registry=revoked_later)["valid"] is True, "valid when anchored"
    revoked_before = keys({"verification_method": signer.key_method, "valid_until": iso(anchored)})
    assert p.check(att, trust_registry=revoked_before)["receipt"].error.startswith("proof_invalid: key not valid at")
    not_yet = keys({"verification_method": signer.key_method, "valid_from": iso(anchored + timedelta(days=1))})
    assert p.check(att, trust_registry=not_yet)["receipt"].error.startswith("proof_invalid: key not valid at")
    starts_then = keys({"verification_method": signer.key_method, "valid_from": iso(anchored)})
    assert p.check(att, trust_registry=starts_then)["valid"] is True, "valid_from is inclusive"


def _set_anchored_at(path, when):
    with open(path, encoding="utf-8") as f:
        recs = [json.loads(line) for line in f if line.strip()]
    for rec in recs:
        rec["anchored_at"] = when
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(json.dumps(rec, sort_keys=True) + "\n" for rec in recs)


def test_key_revoked_after_anchoring_still_verifies(ledger_path):
    p, old, new = plug(ledger_path), NamedSigner(), NamedSigner()
    by_old = issue(p, old, sha256_hex(b"anchored a month ago"))
    by_new = issue(p, new, sha256_hex(b"anchored a month ago, by the new key"))
    month_ago = iso(NOW - timedelta(days=30))
    _set_anchored_at(ledger_path, month_ago)
    reader = plug(ledger_path)
    registry = keys({"verification_method": old.key_method, "valid_until": iso(NOW - timedelta(days=10))},
                    {"verification_method": new.key_method, "valid_from": iso(NOW - timedelta(days=10))})
    v = reader.check(by_old, trust_registry=registry)
    assert v["valid"] is True, v["receipt"].error
    assert v["receipt"].data["anchored_at"] == v["receipt"].data["key_checked_at"] == month_ago
    v = reader.check(by_new, trust_registry=registry)
    assert v["receipt"].error == f"proof_invalid: key not valid at {month_ago}", "anchored before the key was valid"


def test_a_future_anchoring_time_is_judged_as_now(ledger_path):
    p, signer = plug(ledger_path), NamedSigner()
    att = issue(p, signer, sha256_hex(b"clock skew"))
    _set_anchored_at(ledger_path, "2999-01-01T00:00:00Z")
    reader = plug(ledger_path)
    revoked = keys({"verification_method": signer.key_method, "valid_until": iso(NOW - timedelta(days=1))})
    assert reader.check(att, trust_registry=revoked)["receipt"].error.startswith("proof_invalid: key not valid at")
    future = keys({"verification_method": signer.key_method, "valid_from": "2998-01-01T00:00:00Z"})
    assert reader.check(att, trust_registry=future)["valid"] is False


def test_registry_keys_pin_self_describing_issuers_too():
    p = plug()
    p.open(NET, {"key": generate_key("ed25519"), "alg": "ed25519"})
    me = p.active().subject
    att = Attestation.from_receipt(p.prove("x", "doc.sha256"))
    other = KeySigner("ed25519", generate_key("ed25519")).verification_method
    pinned_other = {"issuers": [me], "keys": {me: [{"verification_method": other}]}}
    assert p.check(att, trust_registry=pinned_other)["receipt"].error == \
        "proof_invalid: key not listed for issuer in trust registry"
    pinned_me = {"issuers": [me], "keys": {me: [{"verification_method": me + "#" + me.split(":")[-1]}]}}
    v = p.check(att, trust_registry=pinned_me)
    assert v["valid"] is True, v["receipt"].error
    unpinned = {"issuers": [me], "keys": {"did:key:zSomeoneElse": [{"verification_method": other}]}}
    v = p.check(att, trust_registry=unpinned)
    assert v["valid"] is True and "key_checked_at" not in v["receipt"].data


def test_account_keys_compare_case_insensitively():
    pytest.importorskip("eth_account")
    from eth_account import Account
    key = generate_key("ecdsa-secp256k1")
    checksum = Account.from_key(key).address
    p = plug()
    p.open(NET, {"key": key, "alg": "ecdsa-secp256k1"})
    me = p.active().subject
    att = Attestation.from_receipt(p.prove("x", "doc.sha256"))
    v = p.check(att, trust_registry={"issuers": [me], "keys": {me: [{"verification_method": checksum}]}})
    assert v["valid"] is True, v["receipt"].error


def test_malformed_registry_keys_are_rejected():
    p = plug()
    att = issue(p, NamedSigner(), sha256_hex(b"x"))
    for bad in ({ISSUER: []}, {ISSUER: [{"vm": "x"}]}, {ISSUER: [{"verification_method": "x", "valid_from": "soon"}]},
                {ISSUER: [{"verification_method": 7}]}, {ISSUER: "did:key:x"}, {ISSUER: ["did:key:x"]}, ["nope"]):
        v = p.check(att, trust_registry={"issuers": [ISSUER], "keys": bad})
        assert v["valid"] is False and "trust registry keys" in (v["receipt"].error or ""), bad


def test_operator_keys_apply_under_a_caller_registry():
    p, signer = plug(), NamedSigner()
    att = issue(p, signer, sha256_hex(b"pid"))
    p.trust(NET, keys({"verification_method": signer.key_method, "valid_until": iso(NOW - timedelta(days=1))}))
    v = p.check(att, trust_registry={"issuers": [ISSUER]})
    assert v["receipt"].error.startswith("proof_invalid: key not valid at"), "the caller cannot drop operator keys"
    p.trust(NET, keys({"verification_method": signer.key_method}))
    assert p.check(att, trust_registry={"issuers": [ISSUER]})["receipt"].error == "proof_invalid: unverifiable issuer"
    assert p.check(att)["valid"] is True


def test_url_registry_with_keys():
    p, signer = plug(), NamedSigner()
    att = issue(p, signer, sha256_hex(b"pid over http"))
    docs = {"/keys.json": keys({"verification_method": signer.key_method}),
            "/revoked.json": keys({"verification_method": signer.key_method,
                                   "valid_until": iso(NOW - timedelta(days=1))}),
            "/bad.json": {"issuers": [ISSUER], "keys": {ISSUER: []}}}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            raw = json.dumps(docs.get(self.path, {})).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        v = p.check(att, trust_registry=base + "/keys.json")
        assert v["valid"] is True, v["receipt"].error
        assert v["receipt"].data["trust_registry"]["keys"] == docs["/keys.json"]["keys"]
        assert p.check(att, trust_registry=base + "/revoked.json")["receipt"].error.startswith(
            "proof_invalid: key not valid at")
        assert "trust registry keys" in p.check(att, trust_registry=base + "/bad.json")["receipt"].error
        operator = Plug(trust={NET: base + "/keys.json"})
        operator.register(NET, p._ledger(NET))
        assert operator.check(att, NET)["valid"] is True
    finally:
        server.shutdown()
        server.server_close()


def test_registry_functions_enforce_keys_directly():
    signer = NamedSigner()
    att = Attestation(sha256_hex(b"pid"), "identity.pid", ISSUER, iso(NOW))
    att.proof = signer.sign(bytes.fromhex(statement_hash(att)))
    revoked = {ISSUER: [{"verification_method": signer.key_method, "valid_until": iso(NOW - timedelta(days=1))}]}
    data = resolve_registry({"issuers": [ISSUER], "keys": revoked}, NET, ISSUER)
    assert data["trust_registry"]["keys"] == revoked
    assert check_signature(att, NET, data).error.startswith("proof_invalid: key not valid at")
    earlier = NOW - timedelta(days=2)
    ok = check_signature(att, NET, data, at=earlier)
    assert ok.status == Status.OK and ok.data["key_checked_at"] == iso(earlier)
    assert check_signature(att, NET, {}).error == "proof_invalid: unverifiable issuer"
    keys_only = resolve_registry({"keys": revoked}, NET, ISSUER)
    assert keys_only.status == Status.REJECTED and "issuers" in keys_only.error
    bad = resolve_registry({"issuers": [ISSUER], "keys": {ISSUER: []}}, NET, ISSUER)
    assert bad.status == Status.REJECTED and "trust registry keys" in bad.error
    assert resolve_registry(None, NET, ISSUER) is None
    assert resolve_registry({"issuers": ["did:web:other"]}, NET, ISSUER).error == \
        "not_authorized: issuer not in trust registry"
    assert registry_key_status({}, ISSUER, signer.key_method, NOW) == (False, None)
