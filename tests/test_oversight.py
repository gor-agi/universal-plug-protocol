# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Agent oversight profile: harness-signed evidence, registry-gated containment. Real signatures, no network."""
import time

import pytest

pytest.importorskip("Crypto")

from plug import suites
from plug.adapters.oracle import OracleAdapter
from plug.core import Attestation, FactType, Plug, sha256_hex

NET = "evidence"


class Party:
    def __init__(self, alg="ed25519"):
        self.alg, self.key = alg, suites.generate_key(alg)
        self.did = suites.sign(alg, self.key, "00" * 32)["verification_method"]

    def attest(self, p, fact, fact_type, meta=None, issuer=None):
        subject = sha256_hex(str(fact))
        att = Attestation(subject_hash=subject, fact_type=fact_type, issuer=issuer or self.did,
                          issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          proof=suites.sign(self.alg, self.key, subject), meta=meta or {})
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
