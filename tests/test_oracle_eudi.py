# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""OracleAdapter and EudiAdapter tests - in-memory, no network. Public surfaces only."""
import time
from plug.core import (Plug, Attestation, Identity, StateRef, Status, Role, FactType, statement_hash,
                  PlugError, sha256_hex)
from plug.adapters.oracle import OracleAdapter
from plug.adapters.eudi import EudiAdapter


def setup_oracle():
    p = Plug()
    p.register_adapter("oracle", OracleAdapter())
    p.open("oracle", {"scheme": "raw", "material": "oracle-key-1", "subject": "sensor-01"})
    return p


def setup_eudi():
    p = Plug()
    p.register_adapter("eudi", EudiAdapter())
    p.open("eudi", {"scheme": "raw", "material": "wallet-key-1", "subject": "alice"})
    return p


def test_oracle_fresh_observation_accepted():
    p = setup_oracle()
    r = p.prove({"temp": 21.5}, FactType.SENSOR_READING,
                meta={"value": 21.5})
    assert r.status == Status.OK
    assert r.data["value"] == 21.5
    assert r.state_ref.address.startswith("oracle:0x")


def test_oracle_stale_observation_rejected():
    p = setup_oracle()
    old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 7200))
    att = Attestation(subject_hash=sha256_hex("stale"), fact_type=FactType.SENSOR_READING,
                      issuer="did:plug:oracle:sensor-01", issued_at=old,
                      meta={"value": 21.5})
    raised = False
    try:
        p.attest("oracle", att)
    except PlugError as e:
        raised = True
        assert e.code == "proof_invalid"
        assert "stale" in e.message
    assert raised


def test_oracle_jump_bound_enforced():
    p = setup_oracle()
    p.prove({"temp": 20.0}, FactType.SENSOR_READING, meta={"value": 20.0})
    raised = False
    try:
        p.prove({"temp": 50.0}, FactType.SENSOR_READING, meta={"value": 50.0})
    except PlugError as e:
        raised = True
        assert e.code == "proof_invalid"
        assert "jump" in e.message
    assert raised


def test_oracle_authorized_issuer_gate():
    p = Plug()
    p.register_adapter("oracle", OracleAdapter(authorized_issuers={"did:plug:oracle:sensor-01"}))
    p.open("oracle", {"scheme": "raw", "material": "k", "subject": "sensor-01"})
    r = p.prove("x", FactType.SENSOR_READING)
    assert r.status == Status.OK
    att = Attestation(subject_hash="abc", fact_type=FactType.SENSOR_READING,
                      issuer="did:plug:oracle:intruder", issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    raised = False
    try:
        p.attest("oracle", att)
    except PlugError as e:
        raised = True
        assert e.code == "not_authorized"
    assert raised


def test_oracle_trust_registry_passthrough():
    p = setup_oracle()
    r = p.prove("x", FactType.SENSOR_READING)
    att = Attestation(subject_hash=r.data["subject_hash"], fact_type=FactType.SENSOR_READING,
                      issuer="did:plug:oracle:sensor-01", issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      proof={"alg": "signature", "sig": "0x1", "verification_method": "0x2"})
    v = p.check(att, trust_registry={"issuers": ["did:plug:oracle:bob"]})
    assert v["valid"] is False
    assert v["receipt"].error == "not_authorized: issuer not in trust registry"


def test_oracle_subscribe_delivers():
    p = setup_oracle()
    r = p.prove("z", FactType.SENSOR_READING)
    h = p.watch(r.state_ref, ["attest"])
    events = [e for e in p.adapter_log("oracle").log if e.get("op") == "event"]
    assert [e["handle"] for e in events] == [h]
    assert events[0]["event"] == "attest"


def test_eudi_credential_format_gate():
    p = setup_eudi()
    r = p.prove("x", FactType.SENSOR_READING, meta={"credential_format": "sd-jwt-vc"})
    assert r.status == Status.OK
    raised = False
    try:
        p.prove("y", FactType.SENSOR_READING, meta={"credential_format": "unsupported-fmt"})
    except PlugError as e:
        raised = True
        assert e.code == "unsupported_op"
    assert raised


def test_eudi_trusted_list_resolution():
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    p = Plug()
    issuer = "did:eudi:eudi:alice"
    p.register_adapter("eudi", EudiAdapter(trusted_lists=[]))  # explicit empty; test passes registry directly
    p.open("eudi", {"scheme": "raw", "material": "k", "subject": "alice"})
    r = p.prove("x", FactType.SENSOR_READING)
    att = Attestation(subject_hash=r.data["subject_hash"], fact_type=FactType.SENSOR_READING,
                      issuer=issuer, issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      proof={"alg": "signature", "sig": "0x1", "verification_method": "0x2"})

    docs = {"/ok.json": {"issuers": [issuer, "did:eudi:eudi:bob"]}}

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
        assert listed["receipt"].data["trust_registry"]["issuers"] == docs["/ok.json"]["issuers"]
    finally:
        server.shutdown()
        server.server_close()


def test_eudi_subscribe_delivers():
    p = setup_eudi()
    r = p.prove("z", FactType.SENSOR_READING)
    h = p.watch(r.state_ref, ["attest"])
    events = [e for e in p.adapter_log("eudi").log if e.get("op") == "event"]
    assert [e["handle"] for e in events] == [h]


def _signed(p, network, alg, key, fact):
    import pytest
    from plug import suites
    try:
        k = key()
        issuer = suites.sign(alg, k, "00" * 32)["verification_method"]
    except PlugError:
        pytest.skip(f"{alg} library not installed")
    att = Attestation(subject_hash=sha256_hex(fact), fact_type=FactType.DOC_SHA256, issuer=issuer,
                      issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    att.proof = suites.sign(alg, k, statement_hash(att))
    assert p.attest(network, att).status == Status.OK
    return att, k


def test_eudi_verifies_es256_did_key_issuer():
    from plug import suites
    p = setup_eudi()
    att, _ = _signed(p, "eudi", "ecdsa-p256", lambda: suites.generate_key("ecdsa-p256"), "pid-credential")
    v = p.check(att, network="eudi", trust_registry={"issuers": [att.issuer]})
    assert v["valid"] is True, v["receipt"].error
    assert v["receipt"].data["verification_method"] == att.issuer


def test_oracle_verifies_sm2_and_rejects_impersonation():
    from plug import suites
    p = setup_oracle()
    att, key = _signed(p, "oracle", "sm2-sm3", lambda: suites.generate_key("sm2-sm3"), "cold-chain 4.1C")
    assert p.check(att, network="oracle")["valid"] is True
    other = suites.sign("sm2-sm3", suites.generate_key("sm2-sm3"), "00" * 32)["verification_method"]
    relabeled = Attestation(att.subject_hash, att.fact_type, other, att.issued_at, proof=att.proof)
    assert p.check(relabeled, network="oracle")["receipt"].error == "proof_invalid: statement does not match the anchor"
    forged = Attestation(att.subject_hash, att.fact_type, other, att.issued_at)
    forged.proof = suites.sign("sm2-sm3", key, statement_hash(forged))  # signed, but by a key `other` does not name
    p.attest("oracle", forged)
    v = p.check(forged, network="oracle")
    assert v["valid"] is False
    assert v["receipt"].error == "proof_invalid: issuer is not bound to the signing key"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
    print("ALL PASSED")
