# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Oracle adapter: observation-to-attest backend.

Observes external reality — sensors, webhooks, feeds — hashes the
observation as the subject, and attests through the standard surface.
No new ops. Safety checks (freshness, jump bounds, fail-closed) live
here as recommended guidance, not core enforcement.
"""
from __future__ import annotations
import time
from typing import Any, Optional

from ..core import (
    Adapter, Attestation, Identity, PlugError, Receipt,
    StateRef, Status, SPEC_VERSION, sha256_hex, parse_time,
)
from .base import LoggingAdapter, check_signature, resolve_trust_registry

_DEFAULT_MAX_AGE = 3600        # 1 hour freshness bound
_DEFAULT_MAX_JUMP = 0.5        # 50% max deviation from last accepted value
_DEFAULT_MAX_SKEW = 300        # seconds an observation may be ahead of this clock


class OracleAdapter(LoggingAdapter, Adapter):
    """In-memory oracle adapter with recommended safety checks.

    Parameters
    ----------
    max_age : seconds; observations older than this are rejected (fail-closed)
    max_jump : max fractional deviation from the last accepted value for
               numeric observations; non-numeric observations skip this check
    authorized_issuers : optional set of DIDs allowed to attest; empty means
               any issuer is accepted (trust registry can still gate verify)
    max_skew : seconds an issued_at may lie in the future; beyond that the
               observation is rejected (fail-closed)
    """

    def __init__(self, max_age: int = _DEFAULT_MAX_AGE,
                 max_jump: float = _DEFAULT_MAX_JUMP,
                 authorized_issuers: Optional[set[str]] = None,
                 max_skew: int = _DEFAULT_MAX_SKEW):
        super().__init__()
        self._store: dict[str, dict] = {}
        self._last_value: dict[str, Any] = {}
        self._subs: dict[str, tuple] = {}
        self._emitted: set = set()
        self.max_age = max_age
        self.max_jump = max_jump
        self.max_skew = max_skew
        self.authorized_issuers = authorized_issuers or set()

    def _note(self, rec: dict) -> None:
        self.log.append(rec)
        for handle, (ref, filt) in self._subs.items():
            self._deliver(handle, ref, filt, rec)

    def _deliver(self, handle: str, ref: StateRef, filt: list, rec: dict) -> None:
        if rec.get("op") in ("event", "subscribe"):
            return
        address = rec.get("tx") or rec.get("address") or rec.get("source")
        if address != ref.address:
            return
        op = rec.get("op", "")
        if filt and op not in filt:
            return
        key = (handle, address, op, rec.get("seq"))
        if key in self._emitted:
            return
        self._emitted.add(key)
        self.log.append({"op": "event", "handle": handle, "event": op, "address": address})

    def connect(self, network: str, auth: dict) -> dict:
        subj = auth.get("subject") or sha256_hex(auth.get("material", "anon"))[:16]
        return {"scheme": auth.get("scheme", "raw"), "subject": f"did:plug:{network}:{subj}"}

    def identify(self, network: str, identity: Identity) -> Receipt:
        rec = {"op": "identify", "did": identity.did, "method": identity.method}
        self._note(rec)
        return Receipt(SPEC_VERSION, "identify", Status.OK, network, data=rec)

    def attest(self, network: Optional[str], att: Attestation) -> Receipt:
        net = network or "default"
        now = time.time()

        # Freshness: fail-closed on stale or future-dated observations
        try:
            issued = parse_time(att.issued_at).timestamp()
        except (ValueError, AttributeError):
            raise PlugError("proof_invalid", "bad issued_at")
        if now - issued > self.max_age:
            raise PlugError("proof_invalid",
                            f"observation stale: age {now - issued:.0f}s > max {self.max_age}s")
        if issued - now > self.max_skew:
            raise PlugError("proof_invalid",
                            f"observation from the future: {issued - now:.0f}s > skew {self.max_skew}s")

        # Authorization: optional issuer allowlist
        if self.authorized_issuers and att.issuer not in self.authorized_issuers:
            raise PlugError("not_authorized", f"issuer {att.issuer} not in oracle allowlist")

        # Jump bound: numeric observations only
        val = None
        if isinstance(att.meta.get("value"), (int, float)):
            val = att.meta["value"]
            prev = self._last_value.get(att.fact_type)
            if prev is not None and prev != 0:
                if abs(val - prev) / abs(prev) > self.max_jump:
                    raise PlugError("proof_invalid",
                                    f"jump {abs(val - prev) / abs(prev):.2%} exceeds max {self.max_jump:.0%}")
            self._last_value[att.fact_type] = val

        seq = att.meta.get("_seq", 0)
        tx = "oracle:0x" + sha256_hex(f"{net}:{att.subject_hash}:{att.issuer}:{seq}")
        rec = {"op": "attest", "tx": tx, "block": 9000000 + len(self._store),
               "subject_hash": att.subject_hash, "fact_type": att.fact_type, "issuer": att.issuer,
               "role": att.role.value if att.role else None, "seq": seq,
               "issued_at": att.issued_at, "value": val, "network": net}
        self._store[tx] = rec
        self._note(rec)
        ref = StateRef(net, tx, "event")
        return Receipt(SPEC_VERSION, "attest", Status.OK, net, ref, rec, seq=seq)

    def query(self, ref: StateRef, fields: Optional[list] = None) -> Receipt:
        rec = self._store.get(ref.address)
        if rec is None:
            raise PlugError("not_found", ref.address)
        data = {k: rec[k] for k in fields if k in rec} if fields else dict(rec)
        return Receipt(SPEC_VERSION, "query", Status.OK, ref.network, ref, data)

    def verify(self, att: Attestation, network: str, trust_registry=None) -> Receipt:
        net = network or "default"
        trust = resolve_trust_registry(self.query, trust_registry, net, att.issuer)
        if isinstance(trust, Receipt):
            return trust
        data = dict(trust or {})
        if not any(r["network"] == net and r["subject_hash"] == att.subject_hash for r in self._store.values()):
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data, error="not_found")
        return check_signature(att, net, data)

    def settle(self, network: str, op: str, payload: dict) -> Receipt:
        net = network or "default"
        tx = "oracle:0x" + sha256_hex(f"settle:{net}:{op}:{sha256_hex(str(payload))}")
        rec = {"op": "settle", "tx": tx}
        self._note(rec)
        return Receipt(SPEC_VERSION, "settle", Status.PENDING, net,
                       StateRef(net, tx, "event"), {"op": op, "tx": tx})

    def bridge(self, src: StateRef, target_network: str) -> Receipt:
        tx = "oracle:0x" + sha256_hex(f"bridge:{src.address}:{target_network}")
        rec = {"op": "bridge", "tx": tx, "source": src.address}
        self._note(rec)
        return Receipt(SPEC_VERSION, "bridge", Status.PENDING, target_network,
                       StateRef(target_network, tx, src.kind), rec)

    def subscribe(self, ref: StateRef, callback_id: str, filt: Optional[list] = None) -> str:
        handle = f"stream:{ref.network}:{ref.address}:{callback_id}"
        selected = list(filt or [])
        self._subs[handle] = (ref, selected)
        self.log.append({"op": "subscribe", "handle": handle, "filter": selected, "address": ref.address})
        for rec in list(self.log):
            self._deliver(handle, ref, selected, rec)
        return handle
