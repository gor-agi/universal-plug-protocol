# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""A ledger you run yourself: an append-only, hash-chained log in memory or in a JSONL file.

Each record names the hash of the one before it and is never older than it, so an inserted, edited, reordered, or
backdated line breaks the chain, and nothing after a break is trusted. Writers lock the file, so several processes
can share one log. The anchoring time is the writers' clock: a local anchor proves order and integrity to whoever
trusts the log's keeper. Publish `head()` somewhere the keeper cannot rewrite (for example, prove it on a public
ledger) to pin the history up to that point; use a public ledger (EthereumLedger) when a third party must not have to
trust you at all.
"""
from __future__ import annotations
import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows: one writing process per log file
    fcntl = None

from ..core import (Attestation, Ledger, PlugError, Receipt, StateRef, Status, canonical, parse_time, rejected,
                    sha256_hex, statement_hash)
from ..registry import check_signature, resolve_registry
from ..suites import KeySigner, binds, generate_key, issuer_key

GENESIS = "00" * 32
_FIELDS = {"network", "statement_hash", "subject_hash", "issuer", "anchored_at", "seq", "prev"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(t: datetime) -> str:
    return t.isoformat(timespec="microseconds").replace("+00:00", "Z")


class LocalLedger(Ledger):
    """connect(auth): {"key": hex, "alg": suite} or {"signer": KeySigner | Pkcs11Signer}; with neither, a fresh
    Ed25519 key. The session subject is the signer's did:key (secp256k1 signers sign as their 0x address).

    keeper: who vouches for the log's order and times. A signer (KeySigner, Pkcs11Signer with a did:key) makes this
    ledger sign every record it appends; a did:key makes it accept only records that key signed, and refuse to
    append. Without a keeper, records are unsigned and anyone who can write the log file is effectively its keeper.
    """

    def __init__(self, path: Optional[str] = None, keeper=None):
        self.path = path
        self._keeper_signer = None if keeper is None or isinstance(keeper, str) else keeper
        self.keeper = keeper if isinstance(keeper, str) or keeper is None else keeper.verification_method
        if self.keeper is not None:
            self.keeper = self.keeper.split("#", 1)[0]
            if not self.keeper.startswith("did:key:"):
                raise ValueError("a log keeper is a did:key, or a signer whose verification method is one")
        self._signers: dict[str, object] = {}
        self._bound: Optional[str] = None
        self._records: dict[tuple[str, str], dict] = {}  # (network, statement hash) -> record
        self._seq, self._head, self._last = 0, GENESIS, None  # next seq, hash of the last record, its time
        self._offset = 0          # bytes of the file already read
        self._broken: Optional[str] = None
        self._lock = threading.Lock()
        with self._lock:
            self._load()

    def head(self) -> dict:
        """{"seq", "hash"} of the latest record: publish it to pin the log's history up to here."""
        with self._lock:
            self._load()
            return {"seq": self._seq - 1, "hash": self._head}

    def _accept(self, rec) -> Optional[str]:
        """Add the next record of the chain, or say why it does not follow. Nothing changes unless it follows."""
        fields = set(rec) if isinstance(rec, dict) else set()
        if fields not in (_FIELDS, _FIELDS | {"keeper_proof"}) or type(rec["seq"]) is not int \
                or not all(isinstance(rec[k], str) for k in _FIELDS - {"seq"}):
            return "malformed record"
        try:
            at = parse_time(rec["anchored_at"])
            record_hash = sha256_hex(canonical(rec))
            body_hash = sha256_hex(canonical({k: v for k, v in rec.items() if k != "keeper_proof"}))
        except Exception:  # anything canonical form refuses (lone surrogates, huge numbers) is no record
            return "malformed record"
        if rec["seq"] != self._seq or rec["prev"] != self._head:
            return "record does not follow the previous one"
        if self._last is not None and at < self._last:
            return "record is older than the previous one"
        if self.keeper is not None:
            from ..suites import verify
            ok, method = verify(body_hash, rec.get("keeper_proof") or {})
            if not (ok and method == self.keeper):
                return "record is not signed by the log keeper"
        self._records.setdefault((rec["network"], rec["statement_hash"]), rec)
        self._seq, self._head, self._last = self._seq + 1, record_hash, at
        return None

    def _load(self, f=None) -> None:
        """Read records appended to the log file since the last read. Call with self._lock held."""
        if not self.path or self._broken:
            return
        if f is None:
            if not os.path.exists(self.path):
                return
            with open(self.path, "rb") as g:
                return self._load(g)
        f.seek(self._offset)
        for line in f.read().splitlines(keepends=True):
            if not line.endswith(b"\n"):
                break  # a line still being written
            try:
                rec = json.loads(line)
                err = self._accept(rec)
            except Exception:  # deep nesting and the like: fail closed, never skip
                rec, err = None, "malformed record"
            if err:
                self._broken = f"after record {self._seq - 1}: {err}"
                return
            self._offset += len(line)

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
            rec = self._append(network, sh, att)
        att.anchor = StateRef(network, "local:" + sh)
        return Receipt("attest", Status.OK, network, att.anchor,
                       {"proof": att.proof, "statement_hash": sh, "anchored_at": rec["anchored_at"]})

    def _append(self, network: str, sh: str, att: Attestation) -> dict:
        """The record anchoring this statement on this network, appending it if new. Call with self._lock held."""
        f = open(self.path, "ab+") if self.path else None
        try:
            if f is not None:
                if fcntl:
                    fcntl.flock(f, fcntl.LOCK_EX)  # one writer at a time across processes
                self._load(f)
            if self._broken:
                raise PlugError("proof_invalid", f"the log's chain is broken ({self._broken}); not appending")
            if self.keeper is not None and self._keeper_signer is None:
                raise PlugError("auth_failed", "only the log keeper appends to this log")
            rec = self._records.get((network, sh))
            if rec is not None:
                return rec
            at = max(_now(), self._last) if self._last else _now()
            rec = {"network": network, "statement_hash": sh, "subject_hash": att.subject_hash.lower(),
                   "issuer": att.issuer, "anchored_at": _stamp(at), "seq": self._seq, "prev": self._head}
            if self._keeper_signer is not None:
                rec["keeper_proof"] = self._keeper_signer.sign(bytes.fromhex(sha256_hex(canonical(rec))))
            line = (canonical(rec) + "\n").encode("utf-8")
            if f is not None:
                f.seek(0, os.SEEK_END)
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
                self._offset += len(line)
            err = self._accept(rec)
            if err:
                raise PlugError("proof_invalid", f"refusing to append: {err}")
            return rec
        finally:
            if f is not None:
                f.close()  # closing releases the lock

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
        if rec is None and self._broken:
            return rejected(network, f"proof_invalid: not found before the log's chain breaks ({self._broken})", data)
        if rec is None:
            same_subject = any(r["subject_hash"] == att.subject_hash.lower() and r["network"] == network
                               for r in self._records.values())
            return rejected(network, "proof_invalid: statement does not match the anchor" if same_subject
                            else "not_found", data)
        anchored = parse_time(rec["anchored_at"])
        data.update({"anchor": "local:" + sh, "anchored_at": rec["anchored_at"], "log_seq": rec["seq"]})
        r = check_signature(att, network, data, at=min(anchored, datetime.now(timezone.utc)))
        r.state_ref = StateRef(network, "local:" + sh)
        return r
