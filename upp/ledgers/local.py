# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""A ledger you run yourself: an append-only log in memory or in a JSONL file.

The anchoring time is this process's clock, so a local anchor proves order and integrity to whoever trusts the
log's keeper. Use a public ledger (EthereumLedger) when a third party must not have to trust you.
"""
from __future__ import annotations
import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional

from ..core import Attestation, Ledger, PlugError, Receipt, StateRef, Status, parse_time, rejected, statement_hash
from ..registry import check_signature, resolve_registry
from ..suites import KeySigner, binds, generate_key, issuer_key


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class LocalLedger(Ledger):
    """connect(auth): {"key": hex, "alg": suite} or {"signer": KeySigner | Pkcs11Signer}; with neither, a fresh
    Ed25519 key. The session subject is the signer's did:key (secp256k1 signers sign as their 0x address)."""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        self._signers: dict[str, object] = {}
        self._bound: Optional[str] = None
        self._records: dict[tuple[str, str], dict] = {}  # (network, statement hash) -> record
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        """Read records others appended to the shared log file."""
        if self.path and os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        rec = json.loads(line)
                        self._records.setdefault((rec["network"], rec["statement_hash"]), rec)

    def connect(self, network: str, auth: dict) -> dict:
        signer = auth.get("signer")
        if signer is None:
            alg = auth.get("alg", "ed25519")
            signer = KeySigner(alg, auth.get("key") or generate_key(alg))
        method = signer.verification_method
        subject = method if method.startswith("did:") else f"did:pkh:eip155:1:{method}"
        self._signers[subject] = signer
        return {"subject": subject}

    def bind(self, subject: Optional[str]) -> None:
        self._bound = subject

    def attest(self, network: str, att: Attestation) -> Receipt:
        signer = self._signers.get(self._bound or "")
        if signer is None:
            raise PlugError("auth_failed", "signing needs an open session on this ledger")
        if att.issuer != self._bound and not binds(att.issuer, issuer_key(self._bound) or ""):
            raise PlugError("auth_failed", f"{att.issuer} is not the open session's identity")
        sh = statement_hash(att)
        att.proof = signer.sign(bytes.fromhex(sh))
        with self._lock:
            rec = self._records.get((network, sh))
            if rec is None:
                rec = {"network": network, "statement_hash": sh, "subject_hash": att.subject_hash.lower(),
                       "issuer": att.issuer, "anchored_at": _now(), "seq": len(self._records)}
                self._records[(network, sh)] = rec
                if self.path:
                    with open(self.path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(rec, sort_keys=True) + "\n")
        att.anchor = StateRef(network, "local:" + sh)
        return Receipt("attest", Status.OK, network, att.anchor,
                       {"proof": att.proof, "statement_hash": sh, "anchored_at": rec["anchored_at"]})

    def verify(self, att: Attestation, network: str, trust_registry=None) -> Receipt:
        trust = resolve_registry(trust_registry, network, att.issuer)
        if isinstance(trust, Receipt):
            return trust
        data = dict(trust or {})
        if att.anchor is not None and att.anchor.network != network:
            return rejected(network, "proof_invalid: anchor is on another network", data)
        sh = statement_hash(att)
        if (network, sh) not in self._records:
            with self._lock:
                self._load()
        rec = self._records.get((network, sh))
        if rec is None:
            same_subject = any(r["subject_hash"] == att.subject_hash.lower() and r["network"] == network
                               for r in self._records.values())
            return rejected(network, "proof_invalid: statement does not match the anchor" if same_subject
                            else "not_found", data)
        anchored = parse_time(rec["anchored_at"])
        data.update({"anchor": "local:" + sh, "anchored_at": rec["anchored_at"]})
        r = check_signature(att, network, data, at=min(anchored, datetime.now(timezone.utc)))
        r.state_ref = StateRef(network, "local:" + sh)
        return r
