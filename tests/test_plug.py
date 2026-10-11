# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Plug core tests: in memory or a local JSONL ledger, no network. Public surfaces only."""
import json
import logging
import os
import secrets
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import upp
from upp import (ANY, Attestation, FactType, LocalLedger, Plug, PlugError, Receipt, StateRef, Status, canonical,
                 commitment, digest, fact_bytes, sha256_hex, statement_hash)
from upp.core import Ledger, canon_fact_type, statement
from upp.suites import KeySigner, generate_key

NET = "testnet"


def setup(**kw):
    p = Plug(trust={NET: ANY}, **kw)
    p.register(NET, LocalLedger())
    p.open(NET, {})
    return p


@pytest.fixture
def ledger_path():
    """A JSONL ledger file inside the repository, removed afterwards."""
    path = os.path.join(os.path.dirname(__file__), f".ledger-{secrets.token_hex(6)}.jsonl")
    yield path
    if os.path.exists(path):
        os.remove(path)


# ---- version, canonical form, digests ----

def test_spec_version_matches_package():
    assert upp.SPEC_VERSION == "0.6.0"
    assert upp.__version__.startswith(upp.SPEC_VERSION)


def test_canonical_roundtrip_and_key_order():
    a = canonical({"z": 1, "a": {"y": 2, "b": 3}})
    assert a == canonical({"a": {"b": 3, "y": 2}, "z": 1}) == '{"a":{"b":3,"y":2},"z":1}'
    # RFC 8785 sorts by UTF-16 code units: U+E000 (one unit) after U+1F600 (surrogates D83D DE00)
    assert canonical({"\ue000": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"\ue000":1}'
    assert canonical([None, True, False, "é"]) == '[null,true,false,"é"]'


@pytest.mark.parametrize("value,want", [(0.0, "0"), (-0.0, "0"), (1.0, "1"), (1e21, "1e+21"), (1e20, "100000000000000000000"),
                                        (1e-7, "1e-7"), (0.000001, "0.000001"), (-1.5, "-1.5"),
                                        (123456789012345680000.0, "123456789012345680000"), (5e-324, "5e-324")])
def test_canonical_numbers_follow_ecmascript(value, want):
    assert canonical(value) == want


@pytest.mark.parametrize("bad,exc", [(float("nan"), ValueError), (float("inf"), ValueError), (2**53 + 1, ValueError),
                                     ("\ud800", ValueError), ({1: "x"}, TypeError), ({"s": {1, 2}}, TypeError)])
def test_canonical_refuses_non_i_json(bad, exc):
    with pytest.raises(exc):
        canonical(bad)
    assert canonical(2**53) == str(2**53)


def test_digests():
    assert digest(b"abc") == sha256_hex(b"abc") == \
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert digest("abc", "sha3-256") == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    pytest.importorskip("gmssl")
    assert digest("abc", "sm3") == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    with pytest.raises(PlugError) as e:
        digest(b"x", "md5")
    assert e.value.code == "unsupported_op"


def test_fact_bytes():
    assert fact_bytes(b"\x00raw") == b"\x00raw"
    assert fact_bytes(bytearray(b"ab")) == b"ab"
    assert fact_bytes("héllo") == "héllo".encode("utf-8")
    assert fact_bytes({"b": 1, "a": [1.0, None]}) == b'{"a":[1,null],"b":1}'
    assert fact_bytes(7) == b"7" and fact_bytes(None) == b"null" and fact_bytes(True) == b"true"
    for bad in (object(), {1, 2}, {"x": float("nan")}, {"n": 2**60}):
        with pytest.raises(PlugError) as e:
            fact_bytes(bad)
        assert e.value.code == "unsupported_op"


def test_commitment_is_salted_hash_of_fact_bytes():
    salt = "11" * 32
    person = {"name": "Anna"}
    assert commitment(person, salt) == sha256_hex(bytes.fromhex(salt) + fact_bytes(person))
    assert commitment(person, salt, "sha3-256") == digest(bytes.fromhex(salt) + fact_bytes(person), "sha3-256")
    assert commitment(person, "22" * 32) != commitment(person, salt)


def test_fact_type_and_model_family_are_canonical():
    assert canon_fact_type(" Sensor_Reading ") == "sensor.reading"
    assert canon_fact_type("Agent Action") == "agent.action"
    att = Attestation("ab" * 32, "Sensor_Reading", "did:x", "2026-10-10T00:00:00Z", meta={"model_family": " GPT "})
    assert att.fact_type == "sensor.reading" and att.meta["model_family"] == "gpt"


def test_plug_error_codes():
    assert PlugError("timeout").retries is True and PlugError("proof_invalid").retries is False
    with pytest.raises(ValueError):
        PlugError("not_a_code")


def test_receipt_and_types_are_minimal():
    assert {s.value for s in Status} == {"ok", "rejected"}
    r = Receipt("attest", Status.OK, NET, StateRef(NET, "local:ab"), {"k": 1}, None)
    assert (r.op, r.status, r.network, r.state_ref.address, r.data, r.error) == \
        ("attest", Status.OK, NET, "local:ab", {"k": 1}, None)
    for gone in ("spec_version", "seq"):
        assert not hasattr(r, gone)
    assert not hasattr(StateRef(NET, "x"), "kind")
    att = Attestation("ab" * 32, "doc.sha256", "did:x", "2026-10-10T00:00:00Z")
    assert not hasattr(att, "role") and not hasattr(att, "disclosure")


def test_constructor_validation():
    with pytest.raises(PlugError):
        Plug(hash_alg="md5")
    with pytest.raises(ValueError):
        Plug(commitment="peppered")


# ---- prove, attest, check ----

def test_prove_check_loop():
    p = setup()
    r = p.prove({"temp": 21.5, "unit": "C"}, "Sensor_Reading", meta={"site": "lab-1"})
    assert r.op == "attest" and r.status == Status.OK and r.network == NET
    assert r.data["subject_hash"] == sha256_hex(canonical({"temp": 21.5, "unit": "C"}))
    assert r.data["fact_type"] == "sensor.reading" and r.data["meta"] == {"site": "lab-1"}
    assert r.data["issuer"] == p.active().subject and r.data["issuer"].startswith("did:key:z")
    assert r.data["proof"]["alg"] == "ed25519" and r.data["proof"]["verification_method"] == r.data["issuer"]
    att = Attestation.from_receipt(r)
    assert statement_hash(att) == r.data["statement_hash"]
    assert r.state_ref == StateRef(NET, "local:" + r.data["statement_hash"])
    v = p.check(att)
    assert v["valid"] is True, v["receipt"].error
    assert v["receipt"].op == "verify" and v["receipt"].data["verified"] is True
    assert v["receipt"].state_ref == r.state_ref
    assert v["receipt"].data["anchored_at"] == r.data["anchored_at"]


def test_statement_covers_every_label():
    att = Attestation("AB" * 32, "doc.sha256", "did:x", "2026-10-10T00:00:00Z", expires_at="2030-01-01T00:00:00Z",
                      meta={"a": 1, "_internal": 2})
    assert statement(att) == {"upp.statement": {
        "subject_hash": "ab" * 32, "hash_alg": "sha-256", "fact_type": "doc.sha256", "issuer": "did:x",
        "issued_at": "2026-10-10T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z", "meta": {"a": 1}}}
    assert statement_hash(att) == sha256_hex(canonical(statement(att)))


def test_prove_hashes_raw_bytes_and_text():
    p = setup()
    assert p.prove(b"abc", FactType.DOC_SHA256).data["subject_hash"] == sha256_hex(b"abc")
    assert p.prove("abc", FactType.DOC_SHA256).data["subject_hash"] == sha256_hex(b"abc")


@pytest.mark.parametrize("field,value", [("subject_hash", "00" * 32), ("fact_type", "contract.signed"),
                                         ("issued_at", "2020-01-01T00:00:00Z"),
                                         ("expires_at", "2999-01-01T00:00:00Z"), ("meta", {"site": "lab-2"}),
                                         ("hash_alg", "sha3-256")])
def test_tampered_label_is_rejected(field, value):
    p = setup()
    r = p.prove("x", "sensor.reading", meta={"site": "lab-1"})
    v = p.check(replace(Attestation.from_receipt(r), **{field: value}))
    assert v["valid"] is False
    assert v["receipt"].error in ("proof_invalid: statement does not match the anchor", "not_found")


def test_tampered_or_foreign_proof_is_rejected():
    p = setup()
    att = Attestation.from_receipt(p.prove("x", "sensor.reading"))
    bad_sig = replace(att, proof=dict(att.proof, sig="0x" + "00" * 64))
    assert p.check(bad_sig)["receipt"].error == "proof_invalid: bad signature"
    other = KeySigner("ed25519", generate_key("ed25519"))
    foreign = replace(att, proof=other.sign(bytes.fromhex(statement_hash(att))))
    assert p.check(foreign)["receipt"].error == "proof_invalid: issuer is not bound to the signing key"
    unsupported = replace(att, proof=dict(att.proof, alg="rsa-sha256"))
    assert "unsupported" in p.check(unsupported)["receipt"].error
    assert p.check(replace(att, proof={}))["valid"] is False


def test_unverifiable_issuer_is_rejected():
    p = setup()
    att = Attestation.from_receipt(p.prove("x", "sensor.reading"))
    att.issuer = "did:web:example.org"
    assert p.check(att)["valid"] is False


def test_anchor_on_another_network_is_rejected():
    p = setup()
    att = Attestation.from_receipt(p.prove("x", "sensor.reading"))
    att.anchor = StateRef("othernet", att.anchor.address)
    assert p.check(att)["receipt"].error == "proof_invalid: anchor is on another network"


def test_unanchored_statement_is_not_found():
    p = setup()
    signer = KeySigner("ed25519", generate_key("ed25519"))
    att = Attestation(sha256_hex(b"never anchored"), "doc.sha256", signer.verification_method, "2026-10-10T00:00:00Z")
    att.proof = signer.sign(bytes.fromhex(statement_hash(att)))
    assert p.check(att)["receipt"].error == "not_found"


def test_expiry():
    p = setup()
    future = p.prove("x", "sensor.reading", expires_at="2999-01-01T00:00:00Z")
    assert future.data["expires_at"] == "2999-01-01T00:00:00Z"
    assert p.check(Attestation.from_receipt(future))["valid"] is True
    past = p.prove("y", "sensor.reading", expires_at="2000-01-01T00:00:00Z")
    v = p.check(Attestation.from_receipt(past))
    assert v["valid"] is False and v["receipt"].error == "proof_invalid: expired"
    garbled = replace(Attestation.from_receipt(future), expires_at="soon")
    assert p.check(garbled)["receipt"].error == "proof_invalid: bad expires_at"


def test_internal_meta_is_unsigned_and_kept_out_of_receipts():
    p = setup()
    meta = {"site": "lab-1", "_trace": "t-1", "tags": ["a"]}
    r = p.prove("x", "sensor.reading", meta=meta)
    assert r.data["meta"] == {"site": "lab-1", "tags": ["a"]}
    meta["tags"].append("b")
    r.data["meta"]["tags"].append("c")
    att = Attestation.from_receipt(r)
    att.meta["tags"] = ["a"]
    assert p.check(att)["valid"] is True
    att.meta["_trace"] = "anything"
    assert p.check(att)["valid"] is True, "internal keys are not part of the statement"


def test_hash_alg_is_signed_and_used():
    p = setup(hash_alg="sha3-256")
    r = p.prove(b"abc", "doc.sha256")
    assert r.data["hash_alg"] == "sha3-256" and r.data["subject_hash"] == digest(b"abc", "sha3-256")
    att = Attestation.from_receipt(r)
    assert att.hash_alg == "sha3-256" and statement_hash(att) == r.data["statement_hash"]
    assert p.check(att)["valid"] is True
    assert p.check(replace(att, hash_alg="sha-256"))["valid"] is False


def test_sm3_hash_alg():
    pytest.importorskip("gmssl")
    p = setup(hash_alg="sm3")
    r = p.prove(b"abc", "doc.sha256")
    assert r.data["subject_hash"] == digest(b"abc", "sm3")
    assert p.check(Attestation.from_receipt(r))["valid"] is True


@pytest.mark.parametrize("alg", ["ed25519", "ecdsa-p256", "sm2-sm3", "ecdsa-secp256k1"])
def test_every_suite_signs_and_checks(alg):
    pytest.importorskip({"ecdsa-p256": "cryptography", "sm2-sm3": "gmssl",
                         "ecdsa-secp256k1": "eth_account"}.get(alg, "upp"))
    p = Plug(trust={NET: ANY})
    p.register(NET, LocalLedger())
    p.open(NET, {"key": generate_key(alg), "alg": alg})
    subject = p.active().subject
    assert subject.startswith("did:pkh:eip155:1:0x" if alg == "ecdsa-secp256k1" else "did:key:z")
    r = p.prove({"alg": alg}, "doc.sha256")
    assert r.data["issuer"] == subject and r.data["proof"]["alg"] == alg
    assert p.check(Attestation.from_receipt(r))["valid"] is True


def test_signer_credential_and_stable_subject():
    key = generate_key("ed25519")
    signer = KeySigner("ed25519", key)
    p = Plug(trust={NET: ANY})
    p.register(NET, LocalLedger())
    p.open(NET, {"signer": signer})
    assert p.active().subject == signer.verification_method
    p.open(NET, {"key": key, "alg": "ed25519"})
    assert p.active().subject == signer.verification_method, "the same key is the same subject"
    p.open(NET, {})
    assert p.active().subject != signer.verification_method, "an empty credential is a fresh key"


# ---- sessions ----

def test_session_rules():
    p = Plug(trust={NET: ANY})
    p.register(NET, LocalLedger())
    assert p.active() is None
    alice = p.open(NET, {})
    alice_did = p.active().subject
    bob = p.open(NET, {})
    assert p.active().id == bob and p.active().network == NET and p.active().subject != alice_did
    p.use(alice)
    assert p.active().subject == alice_did
    assert p.prove("from alice", "doc.sha256").data["issuer"] == alice_did
    with pytest.raises(PlugError) as e:
        p.use("missing")
    assert e.value.code == "not_found"
    p.close(alice)
    assert p.active().id == bob
    p.close(bob)
    assert p.active() is None
    p.close("missing")


def test_network_defaults_to_the_only_one_registered():
    p = Plug()
    p.register(NET, LocalLedger())
    with pytest.raises(PlugError) as e:
        p.prove("hello", "doc.sha256")
    assert e.value.code == "auth_failed" and NET in e.value.message, "the network is known, but nobody signs"
    v = p.check(Attestation("ab" * 32, "x", "did:x", ""))
    assert v["receipt"].network == NET and "closed by default" in v["receipt"].error


def test_no_network_no_session_and_several_networks_is_an_error():
    p = Plug()
    p.register(NET, LocalLedger())
    p.register("othernet", LocalLedger())
    for call in (lambda: p.prove("hello", "doc.sha256"), lambda: p.check(Attestation("ab" * 32, "x", "did:x", ""))):
        with pytest.raises(PlugError) as e:
            call()
        assert e.value.code == "auth_failed"


def test_explicit_network_without_session_cannot_sign():
    p = Plug()
    p.register(NET, LocalLedger())
    with pytest.raises(PlugError) as e:
        p.prove("hello", "doc.sha256", network=NET)
    assert e.value.code == "auth_failed"


def test_missing_ledger_is_not_found():
    p = setup()
    for call in (lambda: p.open("missing", {}),
                 lambda: p.attest(Attestation("ab" * 32, "x", p.active().subject, ""), "missing"),
                 lambda: p.check(Attestation("ab" * 32, "x", "did:x", ""), "missing")):
        with pytest.raises(PlugError) as e:
            call()
        assert e.value.code == "not_found"


def test_attest_refuses_an_issuer_that_is_not_the_session():
    p = setup()
    me = p.active().subject
    other = KeySigner("ed25519", generate_key("ed25519")).verification_method
    with pytest.raises(PlugError) as e:
        p.attest(Attestation(sha256_hex(b"x"), "doc.sha256", other, "2026-10-10T00:00:00Z"))
    assert e.value.code == "auth_failed"
    r = p.attest(Attestation(sha256_hex(b"x"), "doc.sha256", me + "#key-1", "2026-10-10T00:00:00Z"))
    assert r.status == Status.OK, "the session's own key, with a fragment"
    assert p.check(Attestation.from_receipt(r))["valid"] is True


def test_session_on_another_network_does_not_sign():
    p = setup()
    p.register("othernet", LocalLedger())
    with pytest.raises(PlugError) as e:
        p.prove("x", "doc.sha256", network="othernet")
    assert e.value.code == "auth_failed"
    with pytest.raises(PlugError):
        p.attest(Attestation(sha256_hex(b"x"), "doc.sha256", p.active().subject, "2026-10-10T00:00:00Z"), "othernet")


def test_failing_ledger_propagates_its_error():
    class Boom(LocalLedger):
        def attest(self, network, att):
            raise PlugError("timeout", "rpc down")
    p = Plug()
    p.register(NET, Boom())
    p.open(NET, {})
    with pytest.raises(PlugError) as e:
        p.prove("x", "doc.sha256")
    assert e.value.code == "timeout" and e.value.retries is True


# ---- trust ----

def test_closed_by_default_without_policy():
    p = Plug()
    p.register(NET, LocalLedger())
    p.open(NET, {})
    att = Attestation.from_receipt(p.prove("x", "doc.sha256"))
    v = p.check(att)
    assert v["valid"] is False
    assert v["receipt"].error == f"not_authorized: no trust policy for {NET} (closed by default)"


def test_any_opens_trust_and_is_logged(caplog):
    with caplog.at_level(logging.WARNING, logger="upp.policy"):
        p = setup()
    assert "opened to ANY" in caplog.text
    assert p.check(Attestation.from_receipt(p.prove("x", "doc.sha256")))["valid"] is True


def test_ledger_with_its_own_trust_policy():
    class Trusting(LocalLedger):
        trust_policy = True
    p = Plug()
    p.register(NET, Trusting())
    p.open(NET, {})
    assert p.check(Attestation.from_receipt(p.prove("x", "doc.sha256")))["valid"] is True


def test_inline_trust_registry():
    p = setup()
    r = p.prove("x", "sensor.reading")
    att = Attestation.from_receipt(r)
    me = r.data["issuer"]
    listed = p.check(att, trust_registry={"issuers": [me]})
    assert listed["valid"] is True and listed["receipt"].data["trust_registry"]["issuers"] == [me]
    blocked = p.check(att, trust_registry={"issuers": ["did:key:zOther"]})
    assert blocked["receipt"].error == "not_authorized: issuer not in trust registry"
    for bad in ({"issuers": []}, {"issuers": "alice"}, {"issuers": [""]}, {}):
        assert "non-empty list" in p.check(att, trust_registry=bad)["receipt"].error
    assert "dict or an http(s) URL" in p.check(att, trust_registry=["nope"])["receipt"].error
    assert "dict or an http(s) URL" in p.check(att, trust_registry=r.state_ref)["receipt"].error


def serve(docs, status=200):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            doc = docs.get(self.path, {})
            if isinstance(doc, tuple):  # ("redirect", location)
                self.send_response(302)
                self.send_header("Location", doc[1])
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            raw = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def test_url_trust_registry():
    p = setup()
    r = p.prove("x", "sensor.reading")
    issuer = r.data["issuer"]
    att = Attestation.from_receipt(r)
    docs = {"/ok.json": {"issuers": [issuer, "did:key:zBob"]}, "/other.json": {"issuers": ["did:key:zBob"]},
            "/bad.json": {"issuers": "alice"}, "/notjson": b"<html>", "/huge.json": b" " * (65 * 1024),
            "/to-file": ("redirect", "file:///etc/passwd"), "/to-ok": ("redirect", "/ok.json")}
    server, base = serve(docs)
    try:
        listed = p.check(att, trust_registry=base + "/ok.json")
        assert listed["valid"] is True, listed["receipt"].error
        assert listed["receipt"].data["trust_registry"]["issuers"] == docs["/ok.json"]["issuers"]
        assert listed["receipt"].data["trust_registry"]["url"] == base + "/ok.json"
        assert p.check(att, trust_registry=base + "/to-ok")["valid"] is True
        assert p.check(att, trust_registry=base + "/to-file")["valid"] is False, "no redirect off http(s)"
        blocked = p.check(att, trust_registry=base + "/other.json")
        assert blocked["receipt"].error == "not_authorized: issuer not in trust registry"
        assert "issuers must be a non-empty list" in p.check(att, trust_registry=base + "/bad.json")["receipt"].error
        assert "not JSON" in p.check(att, trust_registry=base + "/notjson")["receipt"].error
        assert "too large" in p.check(att, trust_registry=base + "/huge.json")["receipt"].error
        refused = p.check(att, trust_registry="http://127.0.0.1:1/registry.json")
        assert refused["valid"] is False and refused["receipt"].error.startswith("not_found:")
        local = p.check(att, trust_registry="file:///etc/passwd")
        assert local["valid"] is False and "http or https" in local["receipt"].error

        operator = Plug(trust={NET: base + "/ok.json"})
        operator.register(NET, p._ledger(NET))
        assert operator.check(att, NET)["valid"] is True
        narrowed = Plug(trust={NET: base + "/other.json"})
        narrowed.register(NET, p._ledger(NET))
        assert narrowed.check(att, NET)["receipt"].error == "not_authorized: issuer not in trust registry"
    finally:
        server.shutdown()
        server.server_close()


def test_url_registry_error_status_fails_closed():
    p = setup()
    att = Attestation.from_receipt(p.prove("x", "sensor.reading"))
    server, base = serve({"/r.json": {"issuers": [att.issuer]}}, status=500)
    try:
        v = p.check(att, trust_registry=base + "/r.json")
        assert v["valid"] is False and v["receipt"].error.startswith("not_found:")
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_policy_is_closed_until_opened():
    p = setup()
    att = Attestation.from_receipt(p.prove("x", "sensor.reading"))
    server, base = serve({"/r.json": {"issuers": [att.issuer]}})
    port = server.server_address[1]
    try:
        upp.reset_fetch_policy()
        v = p.check(att, trust_registry=base + "/r.json")
        assert v["receipt"].error.startswith("not_authorized: remote document host 127.0.0.1 is not allowed")
        upp.allow_hosts("127.0.0.1")
        v = p.check(att, trust_registry=base + "/r.json")
        assert v["receipt"].error == "not_authorized: remote document host is not a public address"
        upp.allow_private_networks(True)
        assert p.check(att, trust_registry=base + "/r.json")["valid"] is True
        hop, hop_base = serve({"/hop": ("redirect", f"http://localhost:{port}/r.json")})
        try:
            v = p.check(att, trust_registry=hop_base + "/hop")
            assert v["receipt"].error.startswith("not_authorized: remote document host localhost is not allowed")
        finally:
            hop.shutdown()
            hop.server_close()
        upp.allow_private_networks(False)
        assert p.check(att, trust_registry=base + "/r.json")["valid"] is False
    finally:
        server.shutdown()
        server.server_close()
    for bad in ("", "a/b", "*.example.org", 7):
        with pytest.raises(ValueError):
            upp.allow_hosts(bad)


# ---- salted commitments ----

def test_salted_commitment_for_personal_data():
    """GDPR: the anchored hash is unlinkable without the salt; deleting the salt erases the link."""
    p = setup(commitment="salted")
    person = {"name": "Anna Petrosyan", "email": "anna@example.org"}
    r = p.prove(person, "identity.email")
    salt = r.data["salt"]
    assert len(bytes.fromhex(salt)) == 32
    assert r.data["subject_hash"] != sha256_hex(canonical(person)), "dictionary attack must not open it"
    assert r.data["subject_hash"] == commitment(person, salt)
    assert p.check(Attestation.from_receipt(r))["valid"] is True
    again = p.prove(person, "identity.email")
    assert again.data["salt"] != salt and again.data["subject_hash"] != r.data["subject_hash"], "no salt reuse"


def test_salt_never_reaches_the_ledger_file(ledger_path):
    p = Plug(trust={NET: ANY}, commitment="salted")
    p.register(NET, LocalLedger(ledger_path))
    p.open(NET, {})
    r = p.prove("anna@example.org", "identity.email")
    with open(ledger_path, encoding="utf-8") as f:
        text = f.read()
    assert r.data["salt"] not in text and "anna" not in text
    assert r.data["subject_hash"] in text


def test_plain_commitment_has_no_salt():
    assert "salt" not in setup().prove("x", "sensor.reading").data


def test_reserved_domain_cannot_be_proven():
    p = setup()
    for fact in ({"upp.batch": {"root": "00" * 32, "size": 1}}, {"upp.statement": {}}, '{"upp.x":1}', b'{"upp.'):
        with pytest.raises(PlugError) as e:
            p.prove(fact, "doc.sha256")
        assert e.value.code == "unsupported_op"
    assert p.prove({"uppercase": "fine"}, "doc.sha256").status == Status.OK
    assert p.prove({"plug.batch": "no longer reserved"}, "doc.sha256").status == Status.OK


# ---- the local ledger ----

def test_local_ledger_persists_and_reloads(ledger_path):
    p = Plug(trust={NET: ANY})
    p.register(NET, LocalLedger(ledger_path))
    p.open(NET, {})
    receipts = [p.prove({"n": i}, "doc.sha256") for i in range(3)]
    with open(ledger_path, encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    assert [rec["statement_hash"] for rec in lines] == [r.data["statement_hash"] for r in receipts]
    assert [rec["seq"] for rec in lines] == [0, 1, 2]
    assert all(rec["network"] == NET and rec["anchored_at"] for rec in lines)

    p.attest(Attestation.from_receipt(receipts[0]), NET)  # the same statement again is not appended
    with open(ledger_path, encoding="utf-8") as f:
        assert sum(1 for line in f if line.strip()) == 3

    reader = Plug(trust={NET: ANY})
    reader.register(NET, LocalLedger(ledger_path))  # no session: checking needs no key
    for r in receipts:
        v = reader.check(Attestation.from_receipt(r), NET)
        assert v["valid"] is True, v["receipt"].error
        assert v["receipt"].data["anchored_at"] == r.data["anchored_at"]
    forged = replace(Attestation.from_receipt(receipts[1]), fact_type="contract.signed")
    assert reader.check(forged, NET)["receipt"].error == "proof_invalid: statement does not match the anchor"
    assert reader.check(Attestation.from_receipt(receipts[0]), NET)["valid"] is True

    fresh = Plug(trust={NET: ANY})
    fresh.register(NET, LocalLedger())
    assert fresh.check(Attestation.from_receipt(receipts[0]), NET)["receipt"].error == "not_found"


def test_local_ledger_on_reload_keeps_appending(ledger_path):
    first = Plug(trust={NET: ANY})
    first.register(NET, LocalLedger(ledger_path))
    first.open(NET, {})
    a = first.prove("a", "doc.sha256")
    second = Plug(trust={NET: ANY})
    second.register(NET, LocalLedger(ledger_path))
    second.open(NET, {})
    b = second.prove("b", "doc.sha256")
    third = Plug(trust={NET: ANY})
    third.register(NET, LocalLedger(ledger_path))
    assert all(third.check(Attestation.from_receipt(r), NET)["valid"] for r in (a, b))


def test_one_local_ledger_on_two_networks():
    ledger, key = LocalLedger(), generate_key("ed25519")
    p = Plug(trust={"a": ANY, "b": ANY})
    p.register("a", ledger)
    p.register("b", ledger)
    receipts = []
    for net in ("a", "b"):
        p.open(net, {"key": key, "alg": "ed25519"})
        att = Attestation(sha256_hex(b"same"), "doc.sha256", p.active().subject, "2026-10-10T00:00:00Z")
        receipts.append(p.attest(att, net))
    assert receipts[1].status == Status.OK and receipts[1].state_ref.network == "b"
    assert receipts[0].state_ref.address == receipts[1].state_ref.address
    for net, r in zip(("a", "b"), receipts):
        assert p.check(Attestation.from_receipt(r), net)["valid"] is True
    moved = Attestation.from_receipt(receipts[0])
    assert p.check(moved, "b")["receipt"].error == "proof_invalid: anchor is on another network"
    moved.anchor = None
    assert p.check(moved, "b")["valid"] is True, "the same statement is anchored on b as well"
    p.register("c", ledger)
    p.trust("c", ANY)
    assert p.check(moved, "c")["receipt"].error == "not_found"


def test_local_ledger_reads_records_appended_by_another_process(ledger_path):
    reader = Plug(trust={NET: ANY})
    reader.register(NET, LocalLedger(ledger_path))  # created before the record exists
    writer = Plug(trust={NET: ANY})
    writer.register(NET, LocalLedger(ledger_path))
    writer.open(NET, {})
    r = writer.prove("appended later", "doc.sha256")
    assert reader.check(Attestation.from_receipt(r), NET)["valid"] is True


def test_ledger_interface_is_abstract():
    ledger = Ledger()
    assert ledger.trust_policy is False
    for call in (lambda: ledger.connect(NET, {}), lambda: ledger.bind(None),
                 lambda: ledger.attest(NET, None), lambda: ledger.verify(None, NET)):
        with pytest.raises(NotImplementedError):
            call()


def test_from_receipt_rejects_non_attest_receipts():
    with pytest.raises(PlugError) as e:
        Attestation.from_receipt(Receipt("verify", Status.OK, NET, data={"x": 1}))
    assert e.value.code == "proof_invalid"


def test_corrupt_lines_in_a_shared_log_are_skipped(tmp_path):
    from upp import ANY, Attestation, LocalLedger, Plug
    path = tmp_path / "log.jsonl"
    p = Plug(trust={"log": ANY})
    p.register("log", LocalLedger(str(path)))
    p.open("log")
    r = p.prove("kept", "doc.sha256")
    with open(path, "a") as f:
        f.write("not json\n[1]\n{\"network\": \"log\"}\n\n")
    q = Plug(trust={"log": ANY})
    q.register("log", LocalLedger(str(path)))
    assert q.check(Attestation.from_receipt(r))["valid"] is True
