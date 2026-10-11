# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""
In-memory stub adapter.
Validates plug logic without network access. Swap for real network calls when credentials are available.
"""
from __future__ import annotations
import hashlib
from typing import Optional
from ..core import Adapter, Attestation, Identity, Receipt, StateRef, Status, sha256_hex, PlugError, SPEC_VERSION
from .base import LoggingAdapter, resolve_trust_registry

class StubAdapter(LoggingAdapter, Adapter):
    def __init__(self):
        super().__init__()
        self._store: dict[str, dict] = {}
        self._subs: dict[str, tuple] = {}
        self._emitted: set = set()

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
        key = f"{net}:{att.subject_hash}"
        seq = att.meta.get("_seq", 0)
        tx = "stub:0x" + sha256_hex(f"{key}:{att.issuer}:{seq}")
        rec = {"op": "attest", "tx": tx, "block": 9000000 + len(self._store), "subject_hash": att.subject_hash,
               "fact_type": att.fact_type, "issuer": att.issuer,
               "role": att.role.value if att.role else None, "seq": seq, "network": net}
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
        alg = att.proof.get("alg", "")
        if alg not in ("ecdsa-secp256k1", "signature"):
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data,
                           error="proof_invalid: unsupported alg")
        # The stub holds no keys, so it cannot check a signature. An allowlist of
        # algorithm names would mark an unchecked proof as valid.
        data["alg"] = alg
        return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data,
                       error="proof_invalid: unverifiable")

    def settle(self, network: str, op: str, payload: dict) -> Receipt:
        net = network or "default"
        tx = "stub:0x" + sha256_hex(f"settle:{net}:{op}:{sha256_hex(str(payload))}")
        rec = {"op": "settle", "tx": tx}
        self._note(rec)
        return Receipt(SPEC_VERSION, "settle", Status.PENDING, net,
                       StateRef(net, tx, "event"), {"op": op, "tx": tx})

    def bridge(self, src: StateRef, target_network: str) -> Receipt:
        tx = "stub:0x" + sha256_hex(f"bridge:{src.address}:{target_network}")
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
