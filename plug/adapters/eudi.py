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
    Attestation, PlugError, Receipt, StateRef, Status, SPEC_VERSION,
)
from .base import InMemoryAdapter, anchor_error, check_signature, fetch_registry, resolve_trust_registry

_DEFAULT_STATUS_LIST_POLL = 300  # 5 minutes


class EudiAdapter(InMemoryAdapter):
    """EUDI-compliant adapter over the standard eight ops.

    Parameters
    ----------
    trusted_lists : list of ETSI TS 119 612 trusted-list URLs
    status_list_poll : seconds between Token Status List polls
    credential_formats : accepted formats (sd-jwt-vc, mso-mdoc)
    """

    tx_prefix = "eudi"
    did_prefix = "did:eudi"

    def __init__(self, trusted_lists: Optional[list[str]] = None,
                 status_list_poll: int = _DEFAULT_STATUS_LIST_POLL,
                 credential_formats: Optional[list[str]] = None):
        super().__init__()
        self.trusted_lists = trusted_lists or []
        self.status_list_poll = status_list_poll
        self.credential_formats = credential_formats or ["sd-jwt-vc", "mso-mdoc"]
        self._status_lists: dict[str, dict] = {}
        self._last_poll: dict[str, float] = {}

    def attest(self, network: Optional[str], att: Attestation) -> Receipt:
        fmt = att.meta.get("credential_format")
        if fmt and fmt not in self.credential_formats:
            raise PlugError("unsupported_op", f"credential format {fmt} not accepted")
        return super().attest(network, att)

    def _poll_status_list(self, url: str) -> dict:
        """FAIL-CLOSED: if the list is unreachable and no cached copy exists, raise."""
        now = time.time()
        if url in self._last_poll and now - self._last_poll[url] < self.status_list_poll:
            return self._status_lists.get(url, {})
        try:
            doc = fetch_registry(url)  # reuses http(s)-only, timeout, cap guards
        except PlugError:
            if url in self._status_lists:
                return self._status_lists[url]  # serve stale cache
            raise  # no cache -> fail closed
        self._status_lists[url] = doc
        self._last_poll[url] = now
        return doc

    def verify(self, att: Attestation, network: str, trust_registry=None) -> Receipt:
        net = network or "default"
        # EUDI: resolve ETSI trusted lists first if configured and no explicit registry
        if self.trusted_lists and not trust_registry:
            all_issuers: list = []
            all_keys: dict[str, list] = {}
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
        err = anchor_error(self._store, net, att)
        if err:
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data, error=err)
        # Token Status List check if a status list URL is in meta
        sl_url = att.meta.get("status_list_url")
        if sl_url:
            try:
                sl = self._poll_status_list(sl_url)
            except PlugError as e:
                return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data,
                               error=f"{e.code}: status list unreachable: {e.message}")
            idx = att.meta.get("status_list_index")
            if idx is not None and isinstance(sl.get("bits"), str):
                if idx < len(sl["bits"]) and sl["bits"][idx] == "1":
                    return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data,
                                   error="proof_invalid: revoked via status list")
        return check_signature(att, net, data)
