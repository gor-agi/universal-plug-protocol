# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Permission layer: closed by default, opened only by explicit, logged operator consent."""
import logging

import pytest

pytest.importorskip("web3")

from eth_account import Account

from plug import ANY, Attestation, Plug
from plug.adapters.live import LiveAdapter
from test_live_adapter import _FakeW3

ALICE, BOB = Account.create().key.hex(), Account.create().key.hex()


def chain(**trust):
    p = Plug(**({"trust": trust} if trust else {}))
    p.register_adapter("sepolia", LiveAdapter(w3=_FakeW3()))
    alice = p.open("sepolia", {"scheme": "raw", "material": ALICE})
    alice_did = p.active().credential_subject
    r_alice = p.prove(b"alice's fact", "doc.sha256")
    p.open("sepolia", {"scheme": "raw", "material": BOB})
    bob_did = p.active().credential_subject
    r_bob = p.prove(b"bob's fact", "doc.sha256")
    p.use(alice)
    return p, (alice_did, Attestation.from_receipt(r_alice)), (bob_did, Attestation.from_receipt(r_bob))


def test_closed_by_default():
    p, (_, alice), _ = chain()
    v = p.check(alice)
    assert v["valid"] is False and v["receipt"].error == "not_authorized: no trust policy for sepolia (closed by default)"


def test_operator_policy_admits_only_listed_issuers():
    p, (alice_did, alice), (_, bob) = chain()
    p.trust("sepolia", {"issuers": [alice_did]})
    assert p.check(alice)["valid"] is True
    assert p.check(bob)["receipt"].error == "not_authorized: issuer not in trust registry"


def test_caller_registry_narrows_but_never_widens():
    p, (alice_did, alice), (bob_did, bob) = chain()
    p.trust("sepolia", {"issuers": [alice_did]})
    assert p.check(bob, trust_registry={"issuers": [bob_did]})["valid"] is False, "cannot widen"
    assert p.check(alice, trust_registry={"issuers": [bob_did]})["valid"] is False, "can narrow"
    assert p.check(alice, trust_registry={"issuers": [alice_did, bob_did]})["valid"] is True


def test_a_registry_given_at_the_call_is_explicit_consent():
    p, (alice_did, alice), (_, bob) = chain()
    assert p.check(alice, trust_registry={"issuers": [alice_did]})["valid"] is True
    assert p.check(bob, trust_registry={"issuers": [alice_did]})["valid"] is False


def test_opening_is_explicit_and_logged(caplog):
    with caplog.at_level(logging.WARNING, logger="plug.policy"):
        p, (_, alice), (_, bob) = chain(sepolia=ANY)
    assert "opened to ANY" in caplog.text
    assert p.check(alice)["valid"] is True and p.check(bob)["valid"] is True
    forged = Attestation.from_receipt(p.prove(b"x", "doc.sha256"))
    forged.fact_type = "agent.action"
    assert p.check(forged)["valid"] is False, "open trust still demands authenticity"


@pytest.mark.parametrize("policy", [None, "", "*", "any", "file:///etc/registry.json", 7])
def test_misconfiguration_fails_closed(policy):
    with pytest.raises((ValueError, TypeError)):
        Plug(trust={"sepolia": policy})


def test_batches_and_bridges_are_closed_too():
    p = Plug()
    p.register_adapter("a", LiveAdapter(w3=_FakeW3()))
    p.register_adapter("b", LiveAdapter(w3=_FakeW3()))
    p.open("a", {"scheme": "raw", "material": ALICE})
    member = p.prove_batch(["x", "y"], "doc.sha256")[0]
    assert "closed by default" in p.check(Attestation.from_receipt(member), network="a")["receipt"].error
    p.open("b", {"scheme": "raw", "material": BOB})
    bridged = p.bridge(member.state_ref, "b")
    assert "closed by default" in p.check(bridged)["receipt"].error
    p.trust("a", ANY)
    p.trust("b", ANY)
    assert p.check(Attestation.from_receipt(member), network="a")["valid"] is True
    assert p.check(bridged)["valid"] is True


def test_only_the_open_session_signs_whatever_issuer_a_caller_names():
    from plug import PlugError
    from plug.core import sha256_hex
    p = Plug(trust={"sepolia": ANY})
    adapter = LiveAdapter(w3=_FakeW3(), private_key=ALICE)
    p.register_adapter("sepolia", adapter)
    operator = f"did:plug:eip155:11155111:{adapter.address}"

    def attest(issuer, fact="resume a1"):
        return p.attest("sepolia", Attestation(sha256_hex(fact + issuer), "control.resume", issuer,
                                               "2026-10-11T00:00:00Z"))

    for issuer in (operator, f"did:pkh:eip155:11155111:{adapter.address}"):
        with pytest.raises(PlugError) as e:
            attest(issuer)  # no session: the configured key is not anyone's to use
        assert e.value.code == "auth_failed"
    bob_session = p.open("sepolia", {"scheme": "raw", "material": BOB})
    bob = p.active().credential_subject
    with pytest.raises(PlugError):
        attest(operator)  # another loaded key, while Bob's session is the one open
    assert attest(bob).status.value == "ok"
    assert attest(bob.replace("did:plug:", "did:pkh:")).status.value == "ok", "the session's own key, any DID form"
    p.close(bob_session)
    with pytest.raises(PlugError):
        attest(bob, "a new statement")  # a closed session signs nothing (a repeat returns the existing receipt)
