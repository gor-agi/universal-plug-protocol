# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Permission layer: closed by default, opened only by explicit, logged operator consent."""
import logging
from dataclasses import replace

import pytest

from upp import ANY, Attestation, LocalLedger, Plug, PlugError, sha256_hex, statement_hash
from upp.suites import KeySigner, generate_key

NET = "local"
ALICE, BOB = generate_key("ed25519"), generate_key("ed25519")


def chain(**trust):
    p = Plug(**({"trust": trust} if trust else {}))
    p.register(NET, LocalLedger())
    alice = p.open(NET, {"key": ALICE, "alg": "ed25519"})
    alice_did = p.active().subject
    r_alice = p.prove(b"alice's fact", "doc.sha256")
    p.open(NET, {"key": BOB, "alg": "ed25519"})
    bob_did = p.active().subject
    r_bob = p.prove(b"bob's fact", "doc.sha256")
    p.use(alice)
    return p, (alice_did, Attestation.from_receipt(r_alice)), (bob_did, Attestation.from_receipt(r_bob))


def test_closed_by_default():
    p, (_, alice), _ = chain()
    v = p.check(alice)
    assert v["valid"] is False
    assert v["receipt"].error == f"not_authorized: no trust policy for {NET} (closed by default)"


def test_policy_is_per_network():
    p, (_, alice), _ = chain(othernet=ANY)
    assert "closed by default" in p.check(alice)["receipt"].error


def test_operator_policy_admits_only_listed_issuers():
    p, (alice_did, alice), (_, bob) = chain()
    p.trust(NET, {"issuers": [alice_did]})
    assert p.check(alice)["valid"] is True
    assert p.check(bob)["receipt"].error == "not_authorized: issuer not in trust registry"


def test_operator_policy_can_be_replaced():
    p, (alice_did, alice), (bob_did, bob) = chain()
    p.trust(NET, {"issuers": [alice_did]})
    p.trust(NET, {"issuers": [bob_did]})
    assert p.check(alice)["valid"] is False and p.check(bob)["valid"] is True


def test_caller_registry_narrows_but_never_widens():
    p, (alice_did, alice), (bob_did, bob) = chain()
    p.trust(NET, {"issuers": [alice_did]})
    assert p.check(bob, trust_registry={"issuers": [bob_did]})["valid"] is False, "cannot widen"
    assert p.check(alice, trust_registry={"issuers": [bob_did]})["valid"] is False, "can narrow"
    assert p.check(alice, trust_registry={"issuers": [alice_did, bob_did]})["valid"] is True


def test_caller_registry_narrows_an_open_operator():
    p, (alice_did, alice), (_, bob) = chain(**{NET: ANY})
    assert p.check(bob)["valid"] is True
    v = p.check(bob, trust_registry={"issuers": [alice_did]})
    assert v["receipt"].error == "not_authorized: issuer not in trust registry"
    assert p.check(alice, trust_registry={"issuers": [alice_did]})["valid"] is True


def test_a_registry_given_at_the_call_is_explicit_consent():
    p, (alice_did, alice), (_, bob) = chain()
    assert p.check(alice, trust_registry={"issuers": [alice_did]})["valid"] is True
    assert p.check(bob, trust_registry={"issuers": [alice_did]})["valid"] is False


def test_a_malformed_caller_registry_fails_closed():
    p, (_, alice), _ = chain(**{NET: ANY})
    for bad in ({"issuers": []}, {"keys": {}}, "file:///etc/registry.json", 7, ["did:key:x"]):
        assert p.check(alice, trust_registry=bad)["valid"] is False, bad


def test_opening_is_explicit_and_logged(caplog):
    with caplog.at_level(logging.WARNING, logger="upp.policy"):
        p, (_, alice), (_, bob) = chain(**{NET: ANY})
    assert "opened to ANY" in caplog.text
    assert any(rec.name == "upp.policy" for rec in caplog.records)
    assert p.check(alice)["valid"] is True and p.check(bob)["valid"] is True
    forged = Attestation.from_receipt(p.prove(b"x", "doc.sha256"))
    forged.fact_type = "agent.action"
    assert p.check(forged)["valid"] is False, "open trust still demands authenticity"


def test_registry_policy_is_not_logged_as_open(caplog):
    with caplog.at_level(logging.WARNING, logger="upp.policy"):
        Plug(trust={NET: {"issuers": ["did:key:zAlice"]}})
    assert "opened to ANY" not in caplog.text


@pytest.mark.parametrize("policy", [None, "", "*", "any", "file:///etc/registry.json", 7, ["did:key:x"], True])
def test_misconfiguration_fails_closed(policy):
    with pytest.raises((ValueError, TypeError)):
        Plug(trust={NET: policy})
    p = Plug()
    with pytest.raises((ValueError, TypeError)):
        p.trust(NET, policy)


def test_batches_are_closed_too():
    p = Plug()
    p.register("a", LocalLedger())
    p.open("a", {"key": ALICE, "alg": "ed25519"})
    member = p.prove_batch(["x", "y"], "doc.sha256")[0]
    assert "closed by default" in p.check(Attestation.from_receipt(member), network="a")["receipt"].error
    p.trust("a", ANY)
    assert p.check(Attestation.from_receipt(member), network="a")["valid"] is True


def test_only_the_open_session_signs_whatever_issuer_a_caller_names():
    pytest.importorskip("eth_account")
    p = Plug(trust={NET: ANY})
    ledger = LocalLedger()
    p.register(NET, ledger)
    alice_signer = KeySigner("ecdsa-secp256k1", generate_key("ecdsa-secp256k1"))
    alice_session = p.open(NET, {"signer": alice_signer})
    alice = p.active().subject
    p.close(alice_session)  # the ledger still holds the key, but nobody's session is open

    def attest(issuer, fact="resume a1"):
        return p.attest(Attestation(sha256_hex(fact + issuer), "control.resume", issuer, "2026-10-11T00:00:00Z"), NET)

    for issuer in (alice, alice.replace("eip155:1:", "eip155:11155111:")):
        with pytest.raises(PlugError) as e:
            attest(issuer)  # no session: a loaded key is not anyone's to use
        assert e.value.code == "auth_failed"
    bob_session = p.open(NET, {"key": generate_key("ecdsa-secp256k1"), "alg": "ecdsa-secp256k1"})
    bob = p.active().subject
    assert bob.startswith("did:pkh:eip155:1:0x")
    with pytest.raises(PlugError) as e:
        attest(alice)  # another loaded key, while Bob's session is the one open
    assert e.value.code == "auth_failed"
    assert attest(bob).status.value == "ok"
    other_chain = bob.replace("eip155:1:", "eip155:11155111:")
    r = attest(other_chain)
    assert r.status.value == "ok", "the session's own key, any DID form"
    assert p.check(Attestation.from_receipt(r))["valid"] is True
    assert attest(bob.lower()).status.value == "ok"
    p.close(bob_session)
    with pytest.raises(PlugError):
        attest(bob, "a new statement")  # a closed session signs nothing


def test_forged_issuer_with_own_signature_is_rejected():
    p, (alice_did, alice), (_, _bob) = chain(**{NET: ANY})
    mallory = KeySigner("ed25519", generate_key("ed25519"))
    forged = replace(alice, proof=mallory.sign(bytes.fromhex(statement_hash(alice))))
    v = p.check(forged)
    assert v["valid"] is False and v["receipt"].error == "proof_invalid: issuer is not bound to the signing key"
    v = p.check(forged, trust_registry={"issuers": [alice_did]})
    assert v["valid"] is False, "a listed issuer does not make a foreign key authentic"
