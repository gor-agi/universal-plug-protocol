# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""EUDI Wallet adapter: OpenID4VCI issuance, SD-JWT VC / mdoc mapping,
ETSI trusted-list resolution, Token Status List polling.

Jurisdiction profile, not a core feature. The plug stays neutral;
this adapter satisfies eIDAS 2.0 / ARF 3.0 mandates through
configuration and adapter-owned resolution.
"""
from __future__ import annotations
import time
from typing import Any, Optional

from ..core import (
    Adapter, Attestation, Identity, PlugError, Receipt,
    StateRef, Status, SPEC_VERSION, sha256_hex,
)
from .base import LoggingAdapter, check_signature, resolve_trust_registry, fetch_registry

_DEFAULT_STATUS_LIST_POLL = 300  # 5 minutes


class EudiAdapter(LoggingAdapter, Adapter):
    """EUDI-compliant adapter over the standard eight ops.

    Parameters
    ----------
    trusted_lists : list of ETSI TS 119 612 trusted-list URLs
    status_list_poll : seconds between Token Status List polls
    credential_formats : accepted formats (sd-jwt-vc, mso-mdoc)
    """

    def __init__(self, trusted_lists: Optional[list[str]] = None,
                 status_list_poll: int = _DEFAULT_STATUS_LIST_POLL,
                 credential_formats: Optional[list[str]] = None):
        super().__init__()
        self.trusted_lists = trusted_lists or []
        self.status_list_poll = status_list_poll
        self.credential_formats = credential_formats or ["sd-jwt-vc", "mso-mdoc"]
        self._store: dict[str, dict] = {}
        self._subs: dict[str, tuple] = {}
        self._emitted: set = set()
        self._status_lists: dict[str, dict] = {}
        self._last_poll: dict[str, float] = {}

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

    def _poll_status_list(self, url: str) -> dict:
        now = time.time()
        if url in self._last_poll and now - self._last_poll[url] < self.status_list_poll:
            return self._status_lists.get(url, {})
        try:
            doc = fetch_registry(url)  # reuses http(s)-only, timeout, cap guards
        except PlugError:
            return self._status_lists.get(url, {})
        self._status_lists[url] = doc
        self._last_poll[url] = now
        return doc

    def connect(self, network: str, auth: dict) -> dict:
        subj = auth.get("subject") or sha256_hex(auth.get("material", "anon"))[:16]
        return {"scheme": auth.get("scheme", "raw"), "subject": f"did:eudi:{network}:{subj}"}

    def identify(self, network: str, identity: Identity) -> Receipt:
        rec = {"op": "identify", "did": identity.did, "method": identity.method}
        self._note(rec)
        return Receipt(SPEC_VERSION, "identify", Status.OK, network, data=rec)

    def attest(self, network: Optional[str], att: Attestation) -> Receipt:
        net = network or "default"
        fmt = att.meta.get("credential_format")
        if fmt and fmt not in self.credential_formats:
            raise PlugError("unsupported_op", f"credential format {fmt} not accepted")
        seq = att.meta.get("_seq", 0)
        tx = "eudi:0x" + sha256_hex(f"{net}:{att.subject_hash}:{att.issuer}:{seq}")
        rec = {"op": "attest", "tx": tx, "block": 9000000 + len(self._store),
               "subject_hash": att.subject_hash, "fact_type": att.fact_type,
               "role": att.role.value if att.role else None, "seq": seq,
               "credential_format": fmt, "issuer": att.issuer, "network": net}
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
        # EUDI: resolve ETSI trusted lists first if configured and no explicit registry
        if self.trusted_lists and not trust_registry:
            all_issuers, all_keys = [], {}
            for url in self.trusted_lists:
                try:
                    doc = fetch_registry(url)
                    all_issuers.extend(doc["issuers"])
                    for did, entries in doc.get("keys", {}).items():
                        all_keys.setdefault(did, []).extend(entries)
                except PlugError as e:
                    return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net,
                                   error=f"{e.code}: trusted list {url}: {e.message}")
            if all_issuers:
                trust_registry = {"issuers": list(dict.fromkeys(all_issuers)),
                                  **({"keys": all_keys} if all_keys else {})}
        trust = resolve_trust_registry(self.query, trust_registry, net, att.issuer)
        if isinstance(trust, Receipt):
            return trust
        data = dict(trust or {})
        if not any(r["network"] == net and r["subject_hash"] == att.subject_hash for r in self._store.values()):
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data, error="not_found")
        # Token Status List check if a status list URL is in meta
        sl_url = att.meta.get("status_list_url")
        if sl_url:
            sl = self._poll_status_list(sl_url)
            idx = att.meta.get("status_list_index")
            if idx is not None and isinstance(sl.get("bits"), str):
                if idx < len(sl["bits"]) and sl["bits"][idx] == "1":
                    return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data,
                                   error="proof_invalid: revoked via status list")
        return check_signature(att, net, data)

    def settle(self, network: str, op: str, payload: dict) -> Receipt:
        net = network or "default"
        tx = "eudi:0x" + sha256_hex(f"settle:{net}:{op}:{sha256_hex(str(payload))}")
        rec = {"op": "settle", "tx": tx}
        self._note(rec)
        return Receipt(SPEC_VERSION, "settle", Status.PENDING, net,
                       StateRef(net, tx, "event"), {"op": op, "tx": tx})

    def bridge(self, src: StateRef, target_network: str) -> Receipt:
        tx = "eudi:0x" + sha256_hex(f"bridge:{src.address}:{target_network}")
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
