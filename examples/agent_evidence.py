# SPDX-License-Identifier: Apache-2.0
"""An AI agent acts on someone's behalf; anyone can later check it was allowed to.

Alice gives her agent a mandate: it may send invoice reminders by email. The agent records each action, citing
the mandate. An auditor who trusts only Alice checks every action: authorized, in scope, not revoked, unaltered.
Then Alice revokes the mandate, and the agent's next action no longer checks out.

Run:  python examples/agent_evidence.py
"""
import os
import tempfile

from upp import Attestation, LocalLedger, Plug, statement_hash
from upp.grants import check_authority, make_grant, make_revocation

log = os.path.join(tempfile.mkdtemp(), "evidence.jsonl")  # a shared, append-only evidence log

# Alice and her agent each hold their own key.
alice, agent = Plug(), Plug()
for party in (alice, agent):
    party.register("log", LocalLedger(log))
    party.open("log")
alice_id, agent_id = alice.active().subject, agent.active().subject

# 1. Alice signs a mandate for the agent: what it may do, for what purpose, until when.
mandate = make_grant(alice_id, agent_id, kind="mandate", expires_at="2099-12-31T00:00:00Z",
                     scope={"fact_type": ["agent.action"], "tool": ["email.send"], "purpose": ["invoice-reminder"]})
alice.attest(mandate, "log")


# 2. The agent records what it does, citing the mandate. The email never leaves the agent: only its hash.
def act(tool, purpose, email):
    r = agent.prove(email, "agent.action", meta={"tool": tool, "purpose": purpose,
                                                 "refs": {"grant": statement_hash(mandate)}})
    return Attestation.from_receipt(r)


reminder = act("email.send", "invoice-reminder", "To: bob@example.com. Invoice 42 is due Friday.")
marketing = act("email.send", "marketing", "To: bob@example.com. Check out our new product!")

# 3. An auditor who trusts only Alice checks the agent's actions against the shared log.
auditor = Plug(trust={"log": {"issuers": [alice_id]}})
auditor.register("log", LocalLedger(log))


def audit(label, action, revocations=()):
    result = check_authority(auditor, action, [mandate], revocations)
    print(f"{label:38} {'AUTHORIZED' if result['valid'] else 'REFUSED  ' + result['error']}")


audit("reminder email", reminder)
audit("marketing email", marketing)
relabeled = Attestation.from_receipt(agent.prove("x", "agent.action", meta={"tool": "email.send"}))
relabeled.meta = {"tool": "email.send", "purpose": "invoice-reminder", "refs": {"grant": statement_hash(mandate)}}
audit("action relabeled after the fact", relabeled)

# 4. Alice revokes the mandate. Earlier actions stay authorized; later ones do not.
revocation = make_revocation(alice_id, mandate)
alice.attest(revocation, "log")
late = act("email.send", "invoice-reminder", "To: bob@example.com. Final notice.")
audit("reminder sent before the revocation", reminder, [revocation])
audit("reminder sent after the revocation", late, [revocation])
