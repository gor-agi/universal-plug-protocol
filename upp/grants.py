# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Grants profile: consent, agent mandates, and human approvals as one primitive, plus signed references.

A grant is an ordinary attestation (fact type `grant`) whose signed meta names the grantee, a scope, and optionally
its parent grant; its signed `expires_at` is required. An action claims authority by naming its grant in its signed
`meta.refs`. Verification follows the chain to a root grantor the verifier trusts: each step must be authentic,
name the next step's issuer as grantee, stay within its parent's scope and expiry, and not be revoked by its
grantor or any ancestor. No new operations; zero dependencies.

Scope is {key: [allowed values]}. An action is within it when, for every key, the action's value is listed:
`fact_type`, `subject_hash`, and `network` are read from the action; any other key (such as `purpose` or
`channel`) from its signed meta. A missing value is out of scope.
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from .core import Attestation, PlugError, Receipt, Status, canonical, digest, now_iso, parse_time, statement_hash

GRANT, REVOKE = "grant", "grant.revoke"
KINDS = ("consent", "mandate", "approval")


def refs(att: Attestation) -> dict:
    """The signed references of an attestation: {name: statement hash or [hashes]}."""
    value = att.meta.get("refs") or {}
    if not isinstance(value, dict):
        raise PlugError("proof_invalid", "meta.refs must be an object")
    return value


_HASH = re.compile(r"[0-9a-fA-F]{64}")


def _ref(value) -> Optional[str]:
    """A reference as a canonical (lowercase) statement hash; anything else is no reference."""
    return value.lower() if isinstance(value, str) and _HASH.fullmatch(value) else None


def _party(did: str) -> str:
    """Who a DID stands for: the key or account it names, so every spelling of one key is one party."""
    from .suites import issuer_key
    base = (did or "").split("#", 1)[0]
    return issuer_key(base) or base


def make_grant(grantor: str, grantee: str, scope: dict, expires_at: str, kind: Optional[str] = None,
               parent: Optional[Attestation] = None, issued_at: Optional[str] = None, hash_alg: str = "sha-256",
               **meta: Any) -> Attestation:
    """An unsigned grant attestation; sign it (`upp.suites.sign_attestation`) or attest it from the grantor's session."""
    _check_scope(scope)
    if kind is not None and kind not in KINDS:
        raise ValueError(f"kind is one of {', '.join(KINDS)}")
    if not expires_at:
        raise ValueError("a grant needs expires_at")
    body = dict(meta, grantee=grantee, scope=scope, **({"kind": kind} if kind else {}))
    if parent is not None:
        body["refs"] = dict(body.get("refs") or {}, parent=statement_hash(parent))
    subject = digest(canonical({"grant": {"grantor": grantor, "grantee": grantee, "scope": scope}}).encode(), hash_alg)
    return Attestation(subject, GRANT, grantor, issued_at or now_iso(), expires_at=expires_at, meta=body,
                       hash_alg=hash_alg)


def make_revocation(revoker: str, grant: Attestation, issued_at: Optional[str] = None) -> Attestation:
    """An unsigned revocation of `grant`, by its grantor or any ancestor's grantor. Final: never retracted."""
    target = statement_hash(grant)
    return Attestation(digest(canonical({"revoke": target}).encode(), grant.hash_alg), REVOKE, revoker,
                       issued_at or now_iso(), meta={"refs": {"revokes": target}}, hash_alg=grant.hash_alg)


def _check_scope(scope: Any) -> None:
    if not isinstance(scope, dict) or not scope:
        raise PlugError("proof_invalid", "a grant scope is a non-empty {key: [values]} object")
    for key, values in scope.items():
        if not isinstance(key, str) or not isinstance(values, list) or not values \
                or not all(isinstance(v, str) for v in values):
            raise PlugError("proof_invalid", f"scope {key!r} must be a non-empty list of strings")


def within(scope: dict, action: Attestation, network: str) -> Optional[str]:
    """None when the action is within the scope, else the first key it falls outside."""
    for key, allowed in scope.items():
        value = {"fact_type": action.fact_type, "subject_hash": action.subject_hash.lower(),
                 "network": network}.get(key, action.meta.get(key))
        if not isinstance(value, str) or value not in allowed:
            return key
    return None


def narrows(child: dict, parent: dict) -> bool:
    """True when every key the parent restricts is restricted at least as tightly by the child."""
    return all(key in child and set(child[key]) <= set(values) for key, values in parent.items())


def _proven_time(receipt: Receipt) -> Optional[datetime]:
    stamp = receipt.data.get("anchored_at")
    return parse_time(stamp) if stamp else None


def check_authority(plug, action: Attestation, grants: Iterable[Attestation],
                    revocations: Iterable[Attestation] = (), network: Optional[str] = None) -> dict:
    """{"valid", "error", "principal", "chain"}: whether `action` is authorized by a chain of `grants`
    (in any order) rooted at a grantor the verifier's trust policy accepts, and not revoked."""
    def fail(error: str) -> dict:
        return {"valid": False, "error": error, "principal": None, "chain": []}

    net = plug._network(network)

    def where(att: Attestation) -> str:
        # One network for the whole chain: the verifier's. An anchor is not signed, so it never chooses the policy.
        if att.anchor is not None and att.anchor.network != net:
            raise PlugError("proof_invalid", "grant chain spans networks")
        return net

    def authentic(att: Attestation) -> Receipt:
        # The action and delegated grants are judged on authenticity; trust is required only of the root grantor.
        return plug._verify(att, where(att), None, require_policy=False)

    try:
        acted = authentic(action)
    except PlugError as e:
        return fail(f"{e.code}: {e.message}")
    if acted.status != Status.OK:
        return fail(f"action: {acted.error}")
    by_hash = {}
    for g in grants:
        if g.fact_type != GRANT:
            return fail("proof_invalid: not a grant")
        by_hash[statement_hash(g)] = g
    try:
        wanted = _ref(refs(action).get("grant"))
    except PlugError as e:
        return fail(f"{e.code}: {e.message}")
    if wanted is None or wanted not in by_hash:
        return fail("not_authorized: the action names no grant that was presented")
    acted_at = _proven_time(acted) or datetime.now(timezone.utc)

    chain, receipts, current, holder = [], [], by_hash[wanted], action.issuer
    while True:
        try:
            _check_scope(current.meta.get("scope"))
            parent_value = refs(current).get("parent")
            where(current)
        except PlugError as e:
            return fail(f"{e.code}: {e.message}")
        parent_hash = _ref(parent_value)
        if parent_value is not None and parent_hash is None:
            return fail("proof_invalid: refs.parent is not a statement hash")
        if not isinstance(current.meta.get("grantee"), str) or _party(current.meta["grantee"]) != _party(holder):
            return fail("not_authorized: grant is not to the party that used it")
        if not current.expires_at:
            return fail("proof_invalid: grant has no expires_at")
        if parse_time(current.expires_at) <= acted_at:
            return fail("not_authorized: grant expired before the action")
        if chain:
            child = chain[-1]
            if not narrows(child.meta["scope"], current.meta["scope"]):
                return fail("not_authorized: a delegated grant widens its parent's scope")
            if parse_time(child.expires_at) > parse_time(current.expires_at):
                return fail("not_authorized: a delegated grant outlives its parent")
        if current in chain or len(chain) > 16:
            return fail("proof_invalid: grant chain loops or is too long")
        chain.append(current)
        if parent_hash is None:
            root = plug._verify(current, where(current))  # the root grantor must be trusted (closed by default)
            if root.status != Status.OK:
                return fail(f"root grant: {root.error}")
            receipts.append(root)
            break
        r = authentic(current)
        if r.status != Status.OK:
            return fail(f"grant: {r.error}")
        receipts.append(r)
        if parent_hash not in by_hash:
            return fail("not_authorized: a parent grant was not presented")
        holder, current = current.issuer, by_hash[parent_hash]

    if within(chain[0].meta["scope"], action, where(action)) is not None:
        return fail(f"not_authorized: action is outside the grant's {within(chain[0].meta['scope'], action, where(action))}")
    for g in chain[1:]:
        if within(g.meta["scope"], action, where(action)) is not None:
            return fail("not_authorized: action is outside an ancestor grant's scope")

    hashes = [statement_hash(g) for g in chain]
    for rv in revocations:
        if rv.fact_type != REVOKE:
            continue
        try:
            target = _ref(refs(rv).get("revokes"))
            r = authentic(rv)
        except PlugError:
            continue
        if target not in hashes:
            continue
        position = hashes.index(target)
        if _party(rv.issuer) not in {_party(g.issuer) for g in chain[position:]}:
            continue  # only the grant's grantor or an ancestor's grantor can revoke it
        if r.status != Status.OK:
            continue
        revoked_at = _proven_time(r)
        if revoked_at is None or revoked_at <= acted_at:
            return fail("not_authorized: grant revoked")
    return {"valid": True, "error": None, "principal": chain[-1].issuer, "chain": chain}


def check_sequence(actions: list) -> list:
    """Problems in one actor's chain of actions linked by meta.refs.prev, in presented order: a link to anything
    but the previous action means a record was skipped, reordered, or forked."""
    problems, seen = [], set()
    for i, att in enumerate(actions):
        prev = _ref(refs(att).get("prev"))
        if i and prev != statement_hash(actions[i - 1]):
            problems.append(f"action {i}: does not follow action {i - 1}")
        if prev in seen:
            problems.append(f"action {i}: forks from an earlier action")
        if prev is not None:
            seen.add(prev)
        if i and _party(att.issuer) != _party(actions[0].issuer):
            problems.append(f"action {i}: another actor")
    return problems
