# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Grants profile: consent, mandates, and approvals as one primitive; signed references; action sequences."""
import time

import pytest

pytest.importorskip("cryptography")

from plug import Attestation, Plug, suites
from plug.adapters.oracle import OracleAdapter
from plug.core import sha256_hex, statement_hash
from plug.grants import check_authority, check_sequence, make_grant, make_revocation

NET = "evidence"


def iso(offset=0):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset))


class Party:
    def __init__(self):
        self.signer = suites.KeySigner("ed25519", suites.generate_key("ed25519"))
        self.did = self.signer.verification_method

    def put(self, p, att):
        suites.sign_attestation(self.signer, att)
        p.attest(NET, att)
        return att

    def act(self, p, fact, fact_type="agent.action", grant=None, **meta):
        refs = dict(meta.pop("refs", {}), **({"grant": statement_hash(grant)} if grant is not None else {}))
        att = Attestation(sha256_hex(fact), fact_type, self.did, iso(), meta=dict(meta, **({"refs": refs} if refs else {})))
        return self.put(p, att)


@pytest.fixture
def world():
    principal, agent, sub, stranger = Party(), Party(), Party(), Party()
    p = Plug(trust={NET: {"issuers": [principal.did]}})  # only the principal is trusted; agents are not
    p.register_adapter(NET, OracleAdapter(max_jump=10.0))
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
    action = sub.act(p, "work", grant=child)
    ignored = stranger.put(p, make_revocation(stranger.did, child))
    assert check_authority(p, action, [child, parent], [ignored], network=NET)["valid"] is True
    for revoker in (agent, principal):  # the grantor, or an ancestor's grantor
        revocation = revoker.put(p, make_revocation(revoker.did, child))
        v = check_authority(p, action, [child, parent], [revocation], network=NET)
        assert v["valid"] is False and v["error"] == "not_authorized: grant revoked"


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


def test_withdrawal_does_not_undo_earlier_actions_on_a_ledger():
    """GDPR Art. 7(3): withdrawing consent does not affect processing before it. Order is the anchored time."""
    pytest.importorskip("web3")
    from eth_account import Account
    from plug.adapters.live import LiveAdapter
    from test_live_adapter import _FakeW3
    subject_key, processor_key = Account.create().key.hex(), Account.create().key.hex()
    p = Plug()
    p.register_adapter("sepolia", LiveAdapter(w3=_FakeW3()))
    subject_session = p.open("sepolia", {"scheme": "raw", "material": subject_key})
    subject = p.active().credential_subject
    processor_session = p.open("sepolia", {"scheme": "raw", "material": processor_key})
    processor = p.active().credential_subject
    p.trust("sepolia", {"issuers": [subject]})

    def anchored(session, att):
        p.use(session)
        return Attestation.from_receipt(p.attest("sepolia", att))

    consent = anchored(subject_session, make_grant(subject, processor, {"purpose": ["newsletter"]}, iso(86400),
                                                   kind="consent"))

    def send(n):
        return anchored(processor_session, Attestation(sha256_hex(f"newsletter {n}"), "message.sent", processor, iso(),
                                                       meta={"purpose": "newsletter",
                                                             "refs": {"grant": statement_hash(consent)}}))
    before = send(1)
    withdrawal = anchored(subject_session, make_revocation(subject, consent))
    after = send(2)
    assert check_authority(p, before, [consent], [withdrawal], network="sepolia")["valid"] is True
    v = check_authority(p, after, [consent], [withdrawal], network="sepolia")
    assert v["valid"] is False and v["error"] == "not_authorized: grant revoked"


def test_a_chain_is_judged_on_the_verifiers_network_only(world):
    from plug import ANY
    p, principal, agent, _, _ = world
    p.trust("scratch", ANY)  # a second, open network must not lend its trust to the strict one
    p.register_adapter("scratch", OracleAdapter(max_jump=10.0))
    self_granted = make_grant(agent.did, agent.did, {"fact_type": ["agent.action"]}, iso(3600))
    suites.sign_attestation(agent.signer, self_granted)
    self_granted = Attestation.from_receipt(p.attest("scratch", self_granted))
    action = agent.act(p, "self-authorized", grant=self_granted)
    v = check_authority(p, action, [self_granted], network=NET)
    assert v["valid"] is False and "spans networks" in v["error"]
    self_granted.anchor = None  # without the anchor it is judged on the strict network, where the agent is untrusted
    assert check_authority(p, action, [self_granted], network=NET)["error"].startswith("root grant: not_authorized")


def test_every_spelling_of_the_grantors_key_can_revoke(world):
    p, principal, agent, _, _ = world
    grant = principal.put(p, make_grant(principal.did, agent.did, {"fact_type": ["agent.action"]}, iso(3600)))
    action = agent.act(p, "work", grant=grant)
    fragment = make_revocation(principal.did + "#" + principal.did.split(":")[-1], grant)
    upper = make_revocation(principal.did, grant)
    upper.meta["refs"]["revokes"] = statement_hash(grant).upper()
    for revocation in (fragment, upper):
        principal.put(p, revocation)
        v = check_authority(p, action, [grant], [revocation], network=NET)
        assert v["valid"] is False and v["error"] == "not_authorized: grant revoked"
    malformed = agent.act(p, "bad ref", refs={"grant": "not-a-hash"})
    assert check_authority(p, malformed, [grant], network=NET)["valid"] is False
