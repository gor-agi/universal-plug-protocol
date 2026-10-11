# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Plug core tests - in-memory, no network. Public surfaces only."""
import time
from plug.core import (Plug, Attestation, Identity, StateRef, Status, Role, FactType,
                  PlugError, sha256_hex, Receipt, Session, canonical)
from plug.adapters.stub import StubAdapter

def setup():
    p = Plug()
    p.register_adapter("testnet", StubAdapter())
    p.open("testnet", {"scheme": "raw", "material": "test-key-1", "subject": "alice"})
    return p

def test_prove_check_verify_loop():
    p = setup()
    r1 = p.prove({"temp": 21.5, "unit": "C"}, FactType.SENSOR_READING)
    assert r1.status == Status.OK and r1.data["subject_hash"]
    assert r1.seq == 0
    h = r1.receipt_hash()
    r2 = p.prove({"temp": 21.5, "unit": "C"}, FactType.SENSOR_READING)  # identical -> cached
    assert r2.receipt_hash() == h, "idempotency broken"
    ref = StateRef("testnet", r1.state_ref.address, "event")
    chk = p.check(ref)
    assert chk["valid"] is True
    att = Attestation(subject_hash=r1.data["subject_hash"], fact_type=FactType.SENSOR_READING,
                      issuer="did:plug:testnet:alice", issued_at="2026-10-10T00:00:00Z",
                      proof={"alg": "ecdsa-secp256k1", "sig": "0xdead", "verification_method": "0xabc"})
    v = p.check(att)
    assert v["valid"] is False
    assert "unverifiable" in (v["receipt"].error or "")
    att.proof["alg"] = "rsa-sha256"
    v2 = p.check(att)
    assert v2["valid"] is False
    assert "unsupported" in (v2["receipt"].error or "")

def test_session_rules():
    p = setup()
    assert p.active().network == "testnet"
    p.open("testnet", {"scheme": "raw", "material": "k2", "subject": "bob"})
    assert p.list_sessions() and len(p.list_sessions()) == 2
    p.close(p.list_sessions()[0].session_id)
    assert len(p.list_sessions()) == 1

def test_anon_prove_no_session():
    """No network and no session is an error. The plug does not guess an adapter."""
    p = Plug()
    p.register_adapter("testnet", StubAdapter())
    raised = False
    try:
        p.prove("hello", FactType.SENSOR_READING)
    except PlugError as e:
        raised = True
        assert e.code == "auth_failed"
    assert raised

def test_explicit_network_without_session():
    p = Plug()
    p.register_adapter("testnet", StubAdapter())
    r = p.prove("hello", FactType.SENSOR_READING, network="testnet")
    assert r.status == Status.OK and r.network == "testnet"

def test_seq_stamped_in_address():
    p = setup()
    r1 = p.prove("a", FactType.SENSOR_READING)
    r2 = p.prove("b", FactType.SENSOR_READING)
    assert r1.seq == 0 and r2.seq == 1
    assert r1.state_ref.address != r2.state_ref.address
    log = p.adapter_log("testnet")
    assert log.last()["seq"] == 1

def test_seq_hash_invariant():
    """Identical proves share a receipt hash; seq differs but is excluded from hash inputs."""
    p = setup()
    r1 = p.prove("same", FactType.SENSOR_READING)
    r2 = p.prove("same", FactType.SENSOR_READING)
    assert r1.receipt_hash() == r2.receipt_hash()
    assert r1.seq != r2.seq  # second call got a fresh seq before cache hit

def test_fact_type_canonicalization():
    p = setup()
    p.prove("data", "Sensor_Reading")
    assert p.adapter_log("testnet").last()["fact_type"] == "sensor.reading"

def test_role_tag_and_receipt_fields():
    p = setup()
    r = p.prove("x", FactType.OWNERSHIP_CLAIM, meta={})
    att = Attestation(subject_hash=r.data["subject_hash"], fact_type=FactType.OWNERSHIP_CLAIM,
                      issuer="did:x", issued_at="2026-10-10T00:00:00Z", role=Role.ASSET)
    p.attest("testnet", att)
    assert p.adapter_log("testnet").last()["role"] == "asset"

def test_monoculture_warning_once():
    """Monoculture warning fires at most once per market per 24h."""
    p = setup()
    for i in range(25):
        p.prove({"forecast": i}, FactType.PREDICTION_MARKET,
                meta={"model_family": "gpt", "market_id": "m1"})
    facts = [rec["fact_type"] for rec in p.adapter_log("testnet").log]
    assert facts.count(FactType.MONOCULTURE_WARNING) == 1

def test_seq_stripped_from_meta():
    """Internal _seq must not leak into the caller's Attestation object."""
    p = setup()
    att = Attestation(subject_hash="abc", fact_type=FactType.SENSOR_READING,
                      issuer="did:x", issued_at="2026-10-10T00:00:00Z")
    p.attest("testnet", att)
    assert "_seq" not in att.meta

def test_watch_content_key():
    """Two StateRef objects with identical content share one stream key."""
    p = setup()
    ref1 = StateRef("testnet", "0xabc", "event")
    ref2 = StateRef("testnet", "0xabc", "event")
    h1 = p.watch(ref1)
    h2 = p.watch(ref2)
    assert h1 == h2

def test_settle_and_bridge():
    p = setup()
    s = p.settle(None, "settle", {"to": "0xabc", "amount": "1"})
    assert s.status == Status.PENDING
    b = p.bridge(StateRef("testnet", "0xabc", "asset"), "net-b")
    assert b.network == "net-b"

def test_canonical_roundtrip():
    a = canonical({"z": 1, "a": {"y": 2, "b": 3}})
    b = canonical({"a": {"b": 3, "y": 2}, "z": 1})
    assert a == b

def test_prove_hashes_raw_bytes():
    p = setup()
    r = p.prove(b"abc", FactType.DOC_SHA256)
    assert r.data["subject_hash"] == sha256_hex(b"abc")

def test_spec_version_matches_package():
    from plug import __version__
    from plug.core import SPEC_VERSION
    assert SPEC_VERSION == "0.2.0" == __version__

def test_seq_cleared_when_attest_fails():
    class Boom(StubAdapter):
        def attest(self, network, att):
            raise PlugError("timeout", "rpc down")
    p = Plug()
    p.register_adapter("testnet", Boom())
    p.open("testnet", {"scheme": "raw", "material": "m", "subject": "alice"})
    att = Attestation(subject_hash="abc", fact_type=FactType.SENSOR_READING,
                      issuer="did:x", issued_at="2026-10-10T00:00:00Z")
    raised = False
    try:
        p.attest("testnet", att)
    except PlugError as e:
        raised = True
        assert e.code == "timeout"
    assert raised and "_seq" not in att.meta

def test_missing_adapter_is_not_found():
    p = setup()
    raised = False
    try:
        p.identify("missing", Identity("did:plug:missing:alice", "plug"))
    except PlugError as e:
        raised = True
        assert e.code == "not_found"
    except KeyError:
        raised = False
    assert raised

def test_adapter_log_hides_adapter():
    p = setup()
    p.prove("x", FactType.SENSOR_READING)
    view = p.adapter_log("testnet")
    assert view.last()["op"] == "attest"
    assert not hasattr(view, "_store")
    assert not hasattr(view, "_private_key")

def test_expired_attestation_rejected():
    p = setup()
    r = p.prove("x", FactType.SENSOR_READING)
    att = Attestation(subject_hash=r.data["subject_hash"], fact_type=FactType.SENSOR_READING,
                      issuer="did:plug:testnet:alice", issued_at="2026-10-10T00:00:00Z",
                      expires_at="2000-01-01T00:00:00Z",
                      proof={"alg": "ecdsa-secp256k1", "sig": "00", "verification_method": "0xabc"})
    v = p.check(att)
    assert v["valid"] is False
    assert v["receipt"].error == "proof_invalid: expired"

def test_disclosure_shape():
    from plug import Credential
    c = Credential(issuer="did:plug:testnet:alice", subject="did:plug:testnet:bob", hash="ab" * 32)
    assert c.claims == {} and c.proof == {}
    p = setup()
    r = p.prove("x", FactType.SENSOR_READING)
    att = Attestation(subject_hash=r.data["subject_hash"], fact_type=FactType.SENSOR_READING,
                      issuer="did:plug:testnet:alice", issued_at="2026-10-10T00:00:00Z",
                      proof={"alg": "ecdsa-secp256k1", "sig": "0xdead", "verification_method": "0xabc"},
                      disclosure=[{"salt": "s", "hash": "zz"}])
    v = p.check(att)
    assert v["valid"] is False and "bad disclosure" in (v["receipt"].error or "")

def test_trust_registry_passthrough():
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    p = setup()
    r = p.prove("x", FactType.SENSOR_READING)
    issuer = "did:plug:testnet:alice"
    att = Attestation(subject_hash=r.data["subject_hash"], fact_type=FactType.SENSOR_READING,
                      issuer=issuer, issued_at="2026-10-10T00:00:00Z",
                      proof={"alg": "ecdsa-secp256k1", "sig": "0xdead", "verification_method": "0xabc"})
    docs = {
        "/ok.json": {"issuers": [issuer, "did:plug:testnet:bob"]},
        "/other.json": {"issuers": ["did:plug:testnet:bob"]},
        "/bad.json": {"issuers": "alice"},
    }

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
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        listed = p.check(att, trust_registry=base + "/ok.json")
        assert listed["valid"] is False
        assert "unverifiable" in (listed["receipt"].error or "")
        assert listed["receipt"].data["trust_registry"]["issuers"] == docs["/ok.json"]["issuers"]

        blocked = p.check(att, trust_registry=base + "/other.json")
        assert blocked["valid"] is False
        assert blocked["receipt"].error == "not_authorized: issuer not in trust registry"

        malformed = p.check(att, trust_registry=base + "/bad.json")
        assert malformed["valid"] is False
        assert "issuers must be a non-empty list" in (malformed["receipt"].error or "")

        refused = p.check(att, trust_registry="http://127.0.0.1:1/registry.json")
        assert refused["valid"] is False and refused["receipt"].error.startswith("not_found:")

        local = p.check(att, trust_registry="file:///etc/passwd")
        assert local["valid"] is False and "http or https" in (local["receipt"].error or "")
    finally:
        server.shutdown()
        server.server_close()

    missing = p.check(att, trust_registry=StateRef("testnet", "stub:0xmissing", "event"))
    assert missing["valid"] is False and "not_found" in (missing["receipt"].error or "")
    found = p.check(att, trust_registry=r.state_ref)
    assert found["valid"] is False
    assert found["receipt"].data["trust_registry"]["address"] == r.state_ref.address

def test_watch_delivers_matching_events():
    p = setup()
    r = p.prove("z", FactType.SENSOR_READING)
    other = p.prove("q", FactType.SENSOR_READING)
    matched = p.watch(r.state_ref, ["attest"])
    skipped = p.watch(other.state_ref, ["settle"])
    events = [e for e in p.adapter_log("testnet").log if e.get("op") == "event"]
    assert [e["handle"] for e in events] == [matched]
    assert events[0]["event"] == "attest"
    assert not any(e.get("handle") == skipped for e in events)

def test_monoculture_window_keeps_aged_events():
    p = setup()
    old = time.time() - 90000
    p._pred_window["m1"] = [("gpt", old)] * 19
    p.prove({"forecast": 1}, FactType.PREDICTION_MARKET,
            meta={"model_family": "gpt", "market_id": "m1"})
    facts = [rec["fact_type"] for rec in p.adapter_log("testnet").log]
    assert facts.count(FactType.MONOCULTURE_WARNING) == 1

def test_idempotency_eviction():
    p = setup()
    r = p.prove("x", FactType.SENSOR_READING)
    h = r.receipt_hash()
    assert h in p.idempotency_keys()
    # TTL testing requires injecting a stale timestamp; no public hook for that.
    rec, _ = p._idempotency[h]
    p._idempotency[h] = (rec, time.time() - 90000)
    p._evict_idempotency()
    assert h not in p.idempotency_keys()

def test_idempotency_separates_issuers_and_fact_types():
    p = setup()
    alice = p.prove({"temp": 21.5}, FactType.SENSOR_READING)
    relabeled = p.prove({"temp": 21.5}, FactType.OWNERSHIP_CLAIM)
    assert relabeled.state_ref.address != alice.state_ref.address
    assert relabeled.data["fact_type"] == FactType.OWNERSHIP_CLAIM
    p.open("testnet", {"scheme": "raw", "material": "k2", "subject": "bob"})
    bob = p.prove({"temp": 21.5}, FactType.SENSOR_READING)
    assert bob.state_ref.address != alice.state_ref.address
    assert bob.data["issuer"] == "did:plug:testnet:bob" and alice.data["issuer"] == "did:plug:testnet:alice"
    assert p.check(alice.state_ref)["valid"] is True, "bob's attest must not overwrite alice's record"
    assert bob.receipt_hash() != alice.receipt_hash()

def test_rejected_receipt_is_not_cached():
    class Flaky(StubAdapter):
        calls = 0
        def attest(self, network, att):
            Flaky.calls += 1
            r = super().attest(network, att)
            if Flaky.calls == 1:
                r.status = Status.REJECTED
            return r
    p = Plug()
    p.register_adapter("testnet", Flaky())
    p.open("testnet", {"scheme": "raw", "material": "m", "subject": "alice"})
    assert p.prove("x", FactType.SENSOR_READING).status == Status.REJECTED
    assert p.prove("x", FactType.SENSOR_READING).status == Status.OK
    assert Flaky.calls == 2

def test_inline_trust_registry():
    p = setup()
    r = p.prove("x", FactType.SENSOR_READING)
    att = Attestation(subject_hash=r.data["subject_hash"], fact_type=FactType.SENSOR_READING,
                      issuer="did:plug:testnet:alice", issued_at="2026-10-10T00:00:00Z",
                      proof={"alg": "ecdsa-secp256k1", "sig": "0xdead", "verification_method": "0xabc"})
    blocked = p.check(att, trust_registry={"issuers": ["did:plug:testnet:bob"]})
    assert blocked["receipt"].error == "not_authorized: issuer not in trust registry"
    bad = p.check(att, trust_registry={"issuers": []})
    assert "non-empty list" in (bad["receipt"].error or "")

def test_salted_commitment_for_personal_data():
    """GDPR: the anchored hash is unlinkable without the salt; deleting the salt erases the link."""
    import json
    from plug import commitment
    p = Plug(commitment="salted")
    p.register_adapter("testnet", StubAdapter())
    p.open("testnet", {"scheme": "raw", "material": "k", "subject": "alice"})
    person = {"name": "Anna Petrosyan", "email": "anna@example.org"}
    r = p.prove(person, FactType.OWNERSHIP_CLAIM)
    salt = r.data["salt"]
    assert len(bytes.fromhex(salt)) == 32
    assert r.data["subject_hash"] != sha256_hex(canonical(person)), "dictionary attack must not open it"
    assert r.data["subject_hash"] == commitment(person, salt)
    log_text = json.dumps(list(p.adapter_log("testnet")))
    assert salt not in log_text, "salt must never reach the adapter"
    again = p.prove(person, FactType.OWNERSHIP_CLAIM)
    assert again.state_ref.address == r.state_ref.address and again.data["salt"] == salt
    other = Plug(commitment="salted")
    other.register_adapter("testnet", StubAdapter())
    assert other.prove(person, FactType.OWNERSHIP_CLAIM, network="testnet").data["subject_hash"] != r.data["subject_hash"]

def test_plain_commitment_has_no_salt():
    p = setup()
    assert "salt" not in p.prove("x", FactType.SENSOR_READING).data

if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
    print("ALL PASSED")
