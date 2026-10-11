# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Agent oversight profile: harness-signed evidence, registry-gated containment. Real signatures, no network."""
import time

import pytest

pytest.importorskip("cryptography")

from plug import suites
from plug.adapters.oracle import OracleAdapter
from plug.core import Attestation, FactType, Plug, sha256_hex, statement_hash

NET = "evidence"


class Party:
    def __init__(self, alg="ed25519"):
        self.alg, self.key = alg, suites.generate_key(alg)
        self.did = suites.sign(alg, self.key, "00" * 32)["verification_method"]

    def attest(self, p, fact, fact_type, meta=None, issuer=None, issued_at=None):
        subject = sha256_hex(str(fact))
        att = Attestation(subject_hash=subject, fact_type=fact_type, issuer=issuer or self.did,
                          issued_at=issued_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), meta=meta or {})
        att.proof = suites.sign(self.alg, self.key, statement_hash(att))
        p.attest(NET, att)
        return att


def plug():
    p = Plug()
    p.register_adapter(NET, OracleAdapter(max_jump=10.0))
    return p


def halted(p, signals, controllers):
    """Containment rule: the most recent valid signal from a registered controller decides."""
    valid = [s for s in signals if p.check(s, network=NET, trust_registry={"issuers": controllers})["valid"]]
    return bool(valid) and valid[-1].fact_type == FactType.CONTROL_HALT


def test_only_harness_signed_actions_count_as_evidence():
    p, harness, model = plug(), Party(), Party()
    harnesses = {"issuers": [harness.did]}
    record = {"actor": "did:plug:agents:a1", "tool": "email.send", "inputs": sha256_hex("draft-42")}
    good = harness.attest(p, record, FactType.AGENT_ACTION, {"model_family": "family-a", "model_id": "m-7"})
    assert p.check(good, network=NET, trust_registry=harnesses)["valid"] is True
    self_reported = model.attest(p, record, FactType.AGENT_ACTION, {"model_family": "family-a"})
    v = p.check(self_reported, network=NET, trust_registry=harnesses)
    assert v["valid"] is False and v["receipt"].error == "not_authorized: issuer not in trust registry"
    spoofed = model.attest(p, {"x": 1}, FactType.AGENT_ACTION, issuer=harness.did)
    assert p.check(spoofed, network=NET, trust_registry=harnesses)["receipt"].error == \
        "proof_invalid: issuer is not bound to the signing key"


def test_emergency_brake_is_registry_gated_and_latest_signal_wins():
    p, controller, intruder = plug(), Party("ecdsa-p256"), Party()
    controllers = [controller.did]
    signals = [controller.attest(p, {"actor": "a1", "n": 1}, FactType.CONTROL_HALT)]
    assert halted(p, signals, controllers) is True
    signals.append(intruder.attest(p, {"actor": "a1", "n": 2}, FactType.CONTROL_RESUME))
    assert halted(p, signals, controllers) is True, "an unregistered resume must not release the brake"
    signals.append(controller.attest(p, {"actor": "a1", "n": 3}, FactType.CONTROL_RESUME))
    assert halted(p, signals, controllers) is False
    signals.append(intruder.attest(p, {"actor": "a1", "n": 4}, FactType.CONTROL_HALT, issuer=controller.did))
    assert halted(p, signals, controllers) is False, "a forged halt must not count"


def test_independent_review_comes_from_another_model_family():
    p, harness, reviewer = plug(), Party(), Party()
    action = harness.attest(p, {"tool": "wire.transfer"}, FactType.AGENT_ACTION, {"model_family": "family-a"})
    review = reviewer.attest(p, {"verdict": "ok", "of": action.subject_hash}, FactType.AGENT_REVIEW,
                             {"model_family": "family-b", "reviews": action.subject_hash})
    assert p.check(review, network=NET)["valid"] is True
    assert review.meta["model_family"] != action.meta["model_family"]


def test_signed_labels_cannot_be_relabeled():
    """A proof covers the statement: subject, type, issuer, times, role, meta. Changing any label voids it."""
    from dataclasses import replace
    p, controller, harness, reviewer = plug(), Party("ecdsa-p256"), Party(), Party()
    controllers = {"issuers": [controller.did]}
    halt = controller.attest(p, {"actor": "a1", "n": 1}, FactType.CONTROL_HALT)
    as_resume = replace(halt, fact_type=FactType.CONTROL_RESUME)
    assert p.check(as_resume, network=NET, trust_registry=controllers)["valid"] is False
    assert halted(p, [halt, as_resume], [controller.did]) is True, "a relabeled halt cannot release the agent"

    doc = harness.attest(p, {"note": "routine"}, FactType.DOC_SHA256)
    as_action = replace(doc, fact_type=FactType.AGENT_ACTION)
    assert p.check(as_action, network=NET, trust_registry={"issuers": [harness.did]})["valid"] is False

    review = reviewer.attest(p, {"verdict": "ok"}, FactType.AGENT_REVIEW, {"model_family": "family-a"})
    for changed in (replace(review, meta={"model_family": "family-b"}),
                    replace(review, expires_at="2999-01-01T00:00:00Z"),
                    replace(review, issued_at="2020-01-01T00:00:00Z")):
        v = p.check(changed, network=NET)
        assert v["valid"] is False and v["receipt"].error == "proof_invalid: statement does not match the anchor"
    assert p.check(review, network=NET)["valid"] is True


def test_reissued_signal_is_anchored_not_served_from_cache():
    """The same halt content signed again at a later time is a new statement and must be anchored."""
    p, controller = plug(), Party("ecdsa-p256")
    signal = {"actor": "a1"}
    at = lambda ago: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - ago))
    halt = controller.attest(p, signal, FactType.CONTROL_HALT, issued_at=at(600))
    resume = controller.attest(p, signal, FactType.CONTROL_RESUME, issued_at=at(300))
    halt_again = controller.attest(p, signal, FactType.CONTROL_HALT, issued_at=at(0))
    signals = [halt, resume, halt_again]
    assert all(p.check(s, network=NET)["valid"] for s in signals)
    assert halted(p, signals, [controller.did]) is True
