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
    Attestation, PlugError, Receipt, StateRef, Status, SPEC_VERSION, parse_time,
)
from .base import InMemoryAdapter

_DEFAULT_MAX_AGE = 3600        # 1 hour freshness bound
_DEFAULT_MAX_JUMP = 0.5        # 50% max deviation from last accepted value
_DEFAULT_MAX_SKEW = 300        # seconds an observation may be ahead of this clock


class OracleAdapter(InMemoryAdapter):
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

    tx_prefix = "oracle"

    def __init__(self, max_age: int = _DEFAULT_MAX_AGE,
                 max_jump: float = _DEFAULT_MAX_JUMP,
                 authorized_issuers: Optional[set[str]] = None,
                 max_skew: int = _DEFAULT_MAX_SKEW):
        super().__init__()
        self.max_age = max_age
        self.max_jump = max_jump
        self.max_skew = max_skew
        self.authorized_issuers = authorized_issuers or set()
        self._last_value: dict[str, Any] = {}

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

        r = super().attest(net, att)
        # attach oracle-specific fields to the stored record
        tx = r.ref.address
        self._store[tx]["value"] = val
        self._store[tx]["issued_at"] = att.issued_at
        return r
