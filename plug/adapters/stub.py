# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""
In-memory stub adapter.
Validates plug logic without network access. Swap for real network calls when credentials are available.
"""
from __future__ import annotations
from typing import Optional
from ..core import Attestation, Receipt, StateRef, Status, SPEC_VERSION
from .base import InMemoryAdapter, anchor_error, resolve_trust_registry


class StubAdapter(InMemoryAdapter):
    """Deterministic in-memory stub. Holds no keys; verify is unverifiable."""

    tx_prefix = "stub"

    def verify(self, att: Attestation, network: str, trust_registry=None) -> Receipt:
        net = network or "default"
        trust = resolve_trust_registry(self.query, trust_registry, net, att.issuer)
        if isinstance(trust, Receipt):
            return trust
        data = dict(trust or {})
        err = anchor_error(self._store, net, att)
        if err:
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data, error=err)
        alg = att.proof.get("alg", "")
        if alg not in ("ecdsa-secp256k1", "signature"):
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data,
                           error="proof_invalid: unsupported alg")
        # The stub holds no keys, so it cannot check a signature. An allowlist of
        # algorithm names would mark an unchecked proof as valid.
        data["alg"] = alg
        return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data,
                       error="proof_invalid: unverifiable")
