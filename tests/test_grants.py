# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Grants profile: consent, mandates, and approvals as one primitive; signed references; action sequences."""
import time

import pytest

pytest.importorskip("cryptography")

from upp import ANY, Attestation, LocalLedger, Plug, suites
from upp.core import PlugError, sha256_hex, statement_hash
from upp.grants import check_authority, check_sequence, make_grant, make_revocation, narrows, within

NET = "evidence"


def iso(offset=0):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset))


class Party:
    def __init__(self):
        self.signer = suites.KeySigner("ed25519", suites.generate_key("ed25519"))
        self.did = self.signer.verification_method

        self.sessions = {}

    def put(self, p, att, network=NET):
        """Sign and anchor `att` from this party's own session (the ledger signs as the session's did:key)."""
        key = (id(p), network)
        if key not in self.sessions:
            self.sessions[key] = p.open(network, {"signer": self.signer})
        p.use(self.sessions[key])
        p.attest(att, network)
        return att

    def act(self, p, fact, fact_type="agent.action", grant=None, **meta):
        refs = dict(meta.pop("refs", {}), **({"grant": statement_hash(grant)} if grant is not None else {}))
        att = Attestation(sha256_hex(fact), fact_type, self.did, iso(), meta=dict(meta, **({"refs": refs} if refs else {})))
        return self.put(p, att)


@pytest.fixture
def world():
    principal, agent, sub, stranger = Party(), Party(), Party(), Party()
    p = Plug(trust={NET: {"issuers": [principal.did]}})  # only the principal is trusted; agents are not
    p.register(NET, LocalLedger())
    return p, principal, agent, sub, stranger


def test_a_mandate_authorizes_its_agent_within_scope(world):
    p, principal, agent, _, _ = world
    mandate = principal.put(p, make_grant(principal.did, agent.did, {"fact_type": ["agent.action"]}, iso(3600),
                                          kind="mandate"))
    action = agent.act(p, "send invoice 7", grant=mandate)
    v = check_authority(p, action, [mandate], network=NET)
    assert v["valid"] is True and v["principal"] == principal.did, v["error"]
    assert p.check(action, network=NET)["valid"] is False, "the agent itself is still untrusted by plain check"


def test_authority_is_closed_by_default(world):
    p, principal, agent, _, stranger = world
    mandate = principal.put(p, make_grant(principal.did, agent.did, {"fact_type": ["agent.action"]}, iso(3600)))
    cases = {
        "names no grant": (agent.act(p, "no refs"), [mandate]),
        "that was presented": (agent.act(p, "missing", grant=mandate), []),
        "not to the party": (stranger.act(p, "borrowed", grant=mandate), [mandate]),
        "outside the grant's fact_type": (agent.act(p, "review", "agent.review", grant=mandate), [mandate]),
    }
    for reason, (action, grants) in cases.items():
        v = check_authority(p, action, grants, network=NET)
        assert v["valid"] is False and reason in v["error"], (reason, v["error"])
    rogue = stranger.put(p, make_grant(stranger.did, agent.did, {"fact_type": ["agent.action"]}, iso(3600)))
    v = check_authority(p, agent.act(p, "rogue", grant=rogue), [rogue], network=NET)
    assert v["valid"] is False and v["error"].startswith("root grant: not_authorized")


def test_expired_and_relabeled_grants_fail(world):
    p, principal, agent, _, _ = world
    expired = principal.put(p, make_grant(principal.did, agent.did, {"fact_type": ["agent.action"]}, iso(-1)))
    v = check_authority(p, agent.act(p, "late", grant=expired), [expired], network=NET)
    assert "expired" in v["error"]
    narrow = principal.put(p, make_grant(principal.did, agent.did, {"fact_type": ["agent.review"]}, iso(3600)))
    widened = Attestation(narrow.subject_hash, narrow.fact_type, narrow.issuer, narrow.issued_at,
                          expires_at=narrow.expires_at, proof=narrow.proof,
                          meta=dict(narrow.meta, scope={"fact_type": ["agent.action"]}))
    action = agent.act(p, "widened", grant=widened)
    assert check_authority(p, action, [widened], network=NET)["valid"] is False, "scope is signed"


def test_delegation_only_narrows(world):
    p, principal, agent, sub, _ = world
    parent = principal.put(p, make_grant(principal.did, agent.did, {"fact_type": ["agent.action", "agent.review"]},
                                         iso(3600), kind="mandate"))
    child = agent.put(p, make_grant(agent.did, sub.did, {"fact_type": ["agent.action"]}, iso(1800), parent=parent))
    action = sub.act(p, "delegated work", grant=child)
    v = check_authority(p, action, [child, parent], network=NET)
    assert v["valid"] is True and v["principal"] == principal.did and len(v["chain"]) == 2, v["error"]
    for reason, grant in {
        "widens its parent's scope": make_grant(agent.did, sub.did, {"fact_type": ["agent.action", "control.halt"]},
                                                iso(1800), parent=parent),
        "outlives its parent": make_grant(agent.did, sub.did, {"fact_type": ["agent.action"]}, iso(7200), parent=parent),
    }.items():
        agent.put(p, grant)
        v = check_authority(p, sub.act(p, reason, grant=grant), [grant, parent], network=NET)
        assert v["valid"] is False and reason in v["error"], (reason, v["error"])
    assert "parent grant was not presented" in check_authority(p, action, [child], network=NET)["error"]


def test_revocation_by_grantor_or_ancestor_only(world):
    p, principal, agent, sub, stranger = world
    parent = principal.put(p, make_grant(principal.did, agent.did, {"fact_type": ["agent.action"]}, iso(3600)))
    child = agent.put(p, make_grant(agent.did, sub.did, {"fact_type": ["agent.action"]}, iso(1800), parent=parent))
    ignored = stranger.put(p, make_revocation(stranger.did, child))
    earlier = sub.act(p, "work", grant=child)
    assert check_authority(p, earlier, [child, parent], [ignored], network=NET)["valid"] is True
    for n, revoker in enumerate((agent, principal)):  # the grantor, or an ancestor's grantor
        revocation = revoker.put(p, make_revocation(revoker.did, child, issued_at=iso(n)))
        later = sub.act(p, f"work after revocation {n}", grant=child)
        v = check_authority(p, later, [child, parent], [revocation], network=NET)
        assert v["valid"] is False and v["error"] == "not_authorized: grant revoked"
        assert check_authority(p, earlier, [child, parent], [revocation], network=NET)["valid"] is True, \
            "a revocation anchored after an action does not undo it"


def test_consent_by_purpose_and_channel_and_single_action_approval(world):
    p, principal, agent, _, _ = world
    consent = principal.put(p, make_grant(principal.did, agent.did,
                                          {"purpose": ["appointment.reminder"], "channel": ["sms"]}, iso(86400),
                                          kind="consent", contact="human-or-ai"))
    ok = agent.act(p, "reminder 1", "message.sent", grant=consent, purpose="appointment.reminder", channel="sms")
    assert check_authority(p, ok, [consent], network=NET)["valid"] is True
    for meta in ({"purpose": "marketing", "channel": "sms"}, {"purpose": "appointment.reminder", "channel": "whatsapp"},
                 {"channel": "sms"}):
        v = check_authority(p, agent.act(p, f"m {meta}", "message.sent", grant=consent, **meta), [consent], network=NET)
        assert v["valid"] is False and "outside the grant" in v["error"], meta
    proposed = sha256_hex("wire 5000 EUR to supplier 12")
    approval = principal.put(p, make_grant(principal.did, agent.did, {"subject_hash": [proposed],
                                                                       "network": [NET]}, iso(600), kind="approval"))
    action = agent.put(p, Attestation(proposed, "agent.action", agent.did, iso(),
                                      meta={"refs": {"grant": statement_hash(approval)}}))
    assert check_authority(p, action, [approval], network=NET)["valid"] is True
    other = agent.act(p, "wire 9000 EUR elsewhere", grant=approval)
    assert "outside the grant's subject_hash" in check_authority(p, other, [approval], network=NET)["error"]


def test_action_sequences_reveal_skipped_and_forked_records(world):
    p, _, agent, _, stranger = world
    first = agent.act(p, "step 1")
    second = agent.act(p, "step 2", refs={"prev": statement_hash(first)})
    third = agent.act(p, "step 3", refs={"prev": statement_hash(second)})
    assert check_sequence([first, second, third]) == []
    assert check_sequence([first, third]) == ["action 1: does not follow action 0"]
    fork = agent.act(p, "step 2 again", refs={"prev": statement_hash(first)})
    assert "action 2: forks from an earlier action" in check_sequence([first, second, fork])
    assert "action 1: another actor" in check_sequence([first, stranger.act(p, "x", refs={"prev": statement_hash(first)})])


def test_withdrawal_does_not_undo_earlier_actions_on_a_ledger(world):
    """GDPR Art. 7(3): withdrawing consent does not affect processing before it. Order is the anchored time,
    never a time the parties claim."""
    p, subject, processor, _, _ = world
    consent = subject.put(p, make_grant(subject.did, processor.did, {"purpose": ["newsletter"]}, iso(86400),
                                        kind="consent"))

    def send(n, claimed):
        return processor.put(p, Attestation(sha256_hex(f"newsletter {n}"), "message.sent", processor.did, claimed,
                                            meta={"purpose": "newsletter", "refs": {"grant": statement_hash(consent)}}))
    before = send(1, iso(3600))  # a claimed issued_at after the withdrawal changes nothing
    withdrawal = subject.put(p, make_revocation(subject.did, consent))
    after = send(2, iso(-3600))  # nor does one claimed before it
    assert check_authority(p, before, [consent], [withdrawal], network=NET)["valid"] is True
    v = check_authority(p, after, [consent], [withdrawal], network=NET)
    assert v["valid"] is False and v["error"] == "not_authorized: grant revoked"
    unanchored = make_revocation(subject.did, consent, issued_at=iso(-7200))
    suites.sign_attestation(subject.signer, unanchored)
    assert check_authority(p, after, [consent], [unanchored], network=NET)["valid"] is True, \
        "a revocation counts only once a ledger has anchored it"


def test_a_grant_is_judged_at_the_anchored_time_of_the_action(world):
    p, principal, agent, _, _ = world
    deadline = time.time() // 1 + 1
    grant = principal.put(p, make_grant(principal.did, agent.did, {"fact_type": ["agent.action"]},
                                        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(deadline))))
    time.sleep(max(0.0, deadline - time.time()) + 0.01)
    late = agent.put(p, Attestation(sha256_hex("after expiry"), "agent.action", agent.did, iso(-60),
                                    meta={"refs": {"grant": statement_hash(grant)}}))
    v = check_authority(p, late, [grant], network=NET)
    assert v["valid"] is False and "expired before the action" in v["error"], "the claimed issued_at is not proof"


def test_scope_helpers_and_malformed_grants():
    assert narrows({"fact_type": ["a"], "purpose": ["x"]}, {"fact_type": ["a", "b"]})
    assert not narrows({"purpose": ["x"]}, {"fact_type": ["a"]}), "dropping a key widens the scope"
    assert not narrows({"fact_type": ["a", "c"]}, {"fact_type": ["a", "b"]})
    action = Attestation(sha256_hex("x"), "agent.action", "did:key:z", iso(), meta={"purpose": "billing"})
    assert within({"fact_type": ["agent.action"], "network": [NET], "purpose": ["billing"]}, action, NET) is None
    assert within({"network": [NET]}, action, "other") == "network"
    assert within({"channel": ["sms"]}, action, NET) == "channel", "a missing value is out of scope"
    for scope in ({}, {"fact_type": []}, {"fact_type": "agent.action"}, {"fact_type": [1]}, []):
        with pytest.raises(PlugError):
            make_grant("did:key:a", "did:key:b", scope, iso(60))
    with pytest.raises(ValueError):
        make_grant("did:key:a", "did:key:b", {"fact_type": ["x"]}, "")
    with pytest.raises(ValueError):
        make_grant("did:key:a", "did:key:b", {"fact_type": ["x"]}, iso(60), kind="power-of-attorney")


def test_a_chain_is_judged_on_the_verifiers_network_only(world):
    p, principal, agent, _, _ = world
    p.trust("scratch", ANY)  # a second, open network must not lend its trust to the strict one
    p.register("scratch", LocalLedger())
    self_granted = agent.put(p, make_grant(agent.did, agent.did, {"fact_type": ["agent.action"]}, iso(3600)),
                             network="scratch")
    assert self_granted.anchor.network == "scratch"
    assert p.check(self_granted, network="scratch")["valid"] is True
    action = agent.act(p, "self-authorized", grant=self_granted)
    v = check_authority(p, action, [self_granted], network=NET)
    assert v["valid"] is False and "spans networks" in v["error"]
    self_granted.anchor = None  # without the anchor it is judged on the strict network, where the agent is untrusted
    assert check_authority(p, action, [self_granted], network=NET)["error"].startswith("root grant: not_authorized")


def test_every_spelling_of_the_grantors_key_can_revoke(world):
    p, principal, agent, _, _ = world
    grant = principal.put(p, make_grant(principal.did, agent.did, {"fact_type": ["agent.action"]}, iso(3600)))
    fragment = make_revocation(principal.did + "#" + principal.did.split(":")[-1], grant)
    upper = make_revocation(principal.did, grant, issued_at=iso(1))
    upper.meta["refs"]["revokes"] = statement_hash(grant).upper()
    for n, revocation in enumerate((fragment, upper)):
        principal.put(p, revocation)
        action = agent.act(p, f"work {n}", grant=grant)
        v = check_authority(p, action, [grant], [revocation], network=NET)
        assert v["valid"] is False and v["error"] == "not_authorized: grant revoked"
    malformed = agent.act(p, "bad ref", refs={"grant": "not-a-hash"})
    assert check_authority(p, malformed, [grant], network=NET)["valid"] is False


def test_parties_are_compared_by_key_not_spelling(world):
    p, principal, agent, _, _ = world
    grant = principal.put(p, make_grant(principal.did, agent.did + "#key-1", {"fact_type": ["agent.action"]},
                                        iso(3600)))
    v = check_authority(p, agent.act(p, "fragment grantee", grant=grant), [grant], network=NET)
    assert v["valid"] is True, v["error"]
