# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Agent oversight: harness-signed evidence, registry-gated containment, and signed action sequences.

The oversight vocabulary (agent.action, agent.review, control.halt, control.resume, incident.report) is ordinary
fact types; ordering is signed meta.refs.prev, checked with upp.grants.check_sequence. Real signatures, no network.
"""
import time
from dataclasses import replace

import pytest

from upp import ANY, Attestation, FactType, LocalLedger, Plug, PlugError, sha256_hex, statement_hash
from upp.grants import check_sequence, refs
from upp.suites import KeySigner, generate_key

NET = "evidence"


def now(ago=0):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - ago))


class Party:
    """Someone with a key who signs only through their own session on the plug."""

    def __init__(self, p, alg="ed25519"):
        if alg != "ed25519":
            pytest.importorskip("cryptography")
        self.p, self.signer = p, KeySigner(alg, generate_key(alg))
        self.session = p.open(NET, {"signer": self.signer})
        self.did = p.active().subject

    def attest(self, fact, fact_type, meta=None, issued_at=None):
        self.p.use(self.session)
        att = Attestation(sha256_hex(str(fact)), fact_type, self.did, issued_at or now(), meta=dict(meta or {}))
        self.p.attest(att, NET)
        return att

    def forge(self, fact, fact_type, issuer, meta=None):
        """A statement naming someone else as issuer, signed with this party's key. No session will anchor it."""
        att = Attestation(sha256_hex(str(fact)), fact_type, issuer, now(), meta=dict(meta or {}))
        att.proof = self.signer.sign(bytes.fromhex(statement_hash(att)))
        return att


def plug():
    p = Plug(trust={NET: ANY})
    p.register(NET, LocalLedger())
    return p


def halted(p, signals, controllers):
    """Containment rule: the most recent valid signal from a registered controller decides."""
    valid = [s for s in signals if p.check(s, network=NET, trust_registry={"issuers": controllers})["valid"]]
    return bool(valid) and valid[-1].fact_type == FactType.CONTROL_HALT


def test_oversight_vocabulary_is_plain_fact_types():
    assert (FactType.AGENT_ACTION, FactType.AGENT_REVIEW, FactType.CONTROL_HALT, FactType.CONTROL_RESUME,
            FactType.INCIDENT_REPORT) == ("agent.action", "agent.review", "control.halt", "control.resume",
                                          "incident.report")
    p = plug()
    harness = Party(p)
    for ft in ("agent.action", "Control_Halt", "incident report", "agent.tool.call"):
        att = harness.attest({"ft": ft}, ft)
        assert p.check(att, network=NET)["valid"] is True, ft


def test_only_harness_signed_actions_count_as_evidence():
    p = plug()
    harness, model = Party(p), Party(p)
    harnesses = {"issuers": [harness.did]}
    record = {"actor": "did:web:agents.example:a1", "tool": "email.send", "inputs": sha256_hex("draft-42")}
    good = harness.attest(record, FactType.AGENT_ACTION, {"model_family": "Family-A", "model_id": "m-7"})
    assert good.meta["model_family"] == "family-a"
    assert p.check(good, network=NET, trust_registry=harnesses)["valid"] is True
    self_reported = model.attest(record, FactType.AGENT_ACTION, {"model_family": "family-a"})
    v = p.check(self_reported, network=NET, trust_registry=harnesses)
    assert v["valid"] is False and v["receipt"].error == "not_authorized: issuer not in trust registry"

    p.use(model.session)
    with pytest.raises(PlugError) as e:  # the model's session cannot anchor a statement in the harness's name
        p.attest(Attestation(sha256_hex("x"), FactType.AGENT_ACTION, harness.did, now()), NET)
    assert e.value.code == "auth_failed"
    spoofed = replace(good, proof=model.signer.sign(bytes.fromhex(statement_hash(good))))
    assert p.check(spoofed, network=NET, trust_registry=harnesses)["receipt"].error == \
        "proof_invalid: issuer is not bound to the signing key"


def test_emergency_brake_is_registry_gated_and_latest_signal_wins():
    p = plug()
    controller, intruder = Party(p, "ecdsa-p256"), Party(p)
    controllers = [controller.did]
    signals = [controller.attest({"actor": "a1", "n": 1}, FactType.CONTROL_HALT)]
    assert halted(p, signals, controllers) is True
    signals.append(intruder.attest({"actor": "a1", "n": 2}, FactType.CONTROL_RESUME))
    assert halted(p, signals, controllers) is True, "an unregistered resume must not release the brake"
    signals.append(controller.attest({"actor": "a1", "n": 3}, FactType.CONTROL_RESUME))
    assert halted(p, signals, controllers) is False
    signals.append(intruder.forge({"actor": "a1", "n": 4}, FactType.CONTROL_HALT, controller.did))
    assert halted(p, signals, controllers) is False, "a forged halt must not count"
    assert halted(p, [], controllers) is False


def test_independent_review_comes_from_another_model_family():
    p = plug()
    harness, reviewer = Party(p), Party(p)
    action = harness.attest({"tool": "wire.transfer"}, FactType.AGENT_ACTION, {"model_family": "family-a"})
    review = reviewer.attest({"verdict": "ok", "of": action.subject_hash}, FactType.AGENT_REVIEW,
                             {"model_family": "family-b", "refs": {"reviews": statement_hash(action)}})
    assert p.check(review, network=NET)["valid"] is True
    assert review.meta["model_family"] != action.meta["model_family"]
    assert refs(review)["reviews"] == statement_hash(action)


def test_signed_labels_cannot_be_relabeled():
    """A proof covers the statement: subject, type, issuer, times, meta. Changing any label voids it."""
    p = plug()
    controller, harness, reviewer = Party(p, "ecdsa-p256"), Party(p), Party(p)
    controllers = {"issuers": [controller.did]}
    halt = controller.attest({"actor": "a1", "n": 1}, FactType.CONTROL_HALT)
    as_resume = replace(halt, fact_type=FactType.CONTROL_RESUME)
    assert p.check(as_resume, network=NET, trust_registry=controllers)["valid"] is False
    assert halted(p, [halt, as_resume], [controller.did]) is True, "a relabeled halt cannot release the agent"

    doc = harness.attest({"note": "routine"}, FactType.DOC_SHA256)
    as_action = replace(doc, fact_type=FactType.AGENT_ACTION)
    assert p.check(as_action, network=NET, trust_registry={"issuers": [harness.did]})["valid"] is False

    review = reviewer.attest({"verdict": "ok"}, FactType.AGENT_REVIEW, {"model_family": "family-a"})
    for changed in (replace(review, meta={"model_family": "family-b"}),
                    replace(review, expires_at="2999-01-01T00:00:00Z"),
                    replace(review, issued_at="2020-01-01T00:00:00Z")):
        v = p.check(changed, network=NET)
        assert v["valid"] is False and v["receipt"].error == "proof_invalid: statement does not match the anchor"
    assert p.check(review, network=NET)["valid"] is True


def test_reissued_signal_is_a_new_anchored_statement():
    """The same halt content signed again at a later time is a new statement and must be anchored."""
    p = plug()
    controller = Party(p, "ecdsa-p256")
    signal = {"actor": "a1"}
    halt = controller.attest(signal, FactType.CONTROL_HALT, issued_at=now(600))
    resume = controller.attest(signal, FactType.CONTROL_RESUME, issued_at=now(300))
    halt_again = controller.attest(signal, FactType.CONTROL_HALT, issued_at=now(0))
    signals = [halt, resume, halt_again]
    assert len({s.anchor.address for s in signals}) == 3
    assert all(p.check(s, network=NET)["valid"] for s in signals)
    assert halted(p, signals, [controller.did]) is True


def test_expired_halt_no_longer_counts():
    p = plug()
    controller = Party(p)
    halt = controller.attest({"actor": "a1"}, FactType.CONTROL_HALT)
    lapsed = Attestation(sha256_hex("lapsed"), FactType.CONTROL_HALT, controller.did, now(),
                         expires_at="2000-01-01T00:00:00Z")
    p.use(controller.session)
    p.attest(lapsed, NET)
    assert p.check(lapsed, network=NET)["receipt"].error == "proof_invalid: expired"
    assert halted(p, [halt, lapsed], [controller.did]) is True, "the earlier, unexpired halt still decides"


def chained_actions(harness, n, start_prev=None):
    actions, prev = [], start_prev
    for i in range(n):
        meta = {"model_family": "family-a", **({"refs": {"prev": prev}} if prev else {})}
        att = harness.attest({"step": i, "tool": "db.query"}, FactType.AGENT_ACTION, meta)
        actions.append(att)
        prev = statement_hash(att)
    return actions


def test_signed_action_sequence_is_complete_and_ordered():
    p = plug()
    harness = Party(p)
    actions = chained_actions(harness, 4)
    assert all(p.check(a, network=NET)["valid"] for a in actions)
    assert check_sequence(actions) == []
    assert check_sequence(actions[:1]) == [] and check_sequence([]) == []

    skipped = [actions[0], actions[2], actions[3]]
    assert check_sequence(skipped) == ["action 1: does not follow action 0"]
    reordered = [actions[0], actions[2], actions[1], actions[3]]
    assert "action 1: does not follow action 0" in check_sequence(reordered)
    assert check_sequence(actions[1:]) == [], "a window into the chain is consistent on its own"


def test_forked_sequence_is_detected():
    p = plug()
    harness = Party(p)
    actions = chained_actions(harness, 2)
    fork = harness.attest({"step": "fork"}, FactType.AGENT_ACTION, {"refs": {"prev": statement_hash(actions[0])}})
    problems = check_sequence(actions + [fork])
    assert "action 2: does not follow action 1" in problems and "action 2: forks from an earlier action" in problems


def test_sequence_from_another_actor_is_flagged():
    p = plug()
    harness, other = Party(p), Party(p)
    actions = chained_actions(harness, 2)
    p.use(other.session)
    intruder = other.attest({"step": 2}, FactType.AGENT_ACTION, {"refs": {"prev": statement_hash(actions[1])}})
    assert check_sequence(actions + [intruder]) == ["action 2: another actor"]
    assert p.check(intruder, network=NET, trust_registry={"issuers": [harness.did]})["valid"] is False


def test_sequence_links_are_signed():
    p = plug()
    harness = Party(p)
    actions = chained_actions(harness, 3)
    rewired = replace(actions[2], meta=dict(actions[2].meta, refs={"prev": statement_hash(actions[0])}))
    assert p.check(rewired, network=NET)["receipt"].error == "proof_invalid: statement does not match the anchor"
    upper = replace(actions[1], meta=dict(actions[1].meta, refs={"prev": statement_hash(actions[0]).upper()}))
    assert check_sequence([actions[0], upper]) == [], "a reference is a hash, compared case-insensitively"
    with pytest.raises(PlugError):
        check_sequence([replace(actions[0], meta={"refs": ["not", "an", "object"]})])


def test_incident_report_references_the_actions():
    p = plug()
    harness, auditor = Party(p), Party(p)
    actions = chained_actions(harness, 2)
    report = auditor.attest({"summary": "unexpected transfer"}, FactType.INCIDENT_REPORT,
                            {"refs": {"actions": [statement_hash(a) for a in actions]}})
    assert p.check(report, network=NET, trust_registry={"issuers": [auditor.did]})["valid"] is True
    assert refs(report)["actions"] == [statement_hash(a) for a in actions]
