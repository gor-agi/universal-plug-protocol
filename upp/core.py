# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Universal Plug Protocol core: signed statements, anchored on any ledger, checked closed by default.

Zero dependencies. Ledgers (upp.ledgers) anchor and sign; this module never imports a network SDK.
"""
from __future__ import annotations
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Optional

SPEC_VERSION = "0.6.1"

# The one explicit way to open a permission (trust any authentic issuer, fetch from any public host, let a model
# prove any non-reserved fact type). Never a default; every use is logged on "upp.policy".
ANY = "ANY"
POLICY_LOG = logging.getLogger("upp.policy")


class Status(str, Enum):
    OK, REJECTED = "ok", "rejected"


class FactType:
    """Recommended fact types (the vocabulary is open). See SPEC, Agent oversight and Grants."""
    DOC_SHA256 = "doc.sha256"
    AGENT_ACTION = "agent.action"
    AGENT_REVIEW = "agent.review"
    CONTROL_HALT = "control.halt"
    CONTROL_RESUME = "control.resume"
    INCIDENT_REPORT = "incident.report"
    GRANT = "grant"
    GRANT_REVOKE = "grant.revoke"


ERROR_CODES = {"auth_failed": False, "not_found": False, "not_authorized": False, "unsupported_op": False,
               "proof_invalid": False, "timeout": True, "rate_limited": True}


class PlugError(Exception):
    def __init__(self, code: str, message: str = ""):
        if code not in ERROR_CODES:
            raise ValueError(f"unknown error code: {code}")
        self.code, self.message, self.retries = code, message, ERROR_CODES[code]
        super().__init__(f"{code}: {message}")


# ---- canonical form and digests ----

_MAX_SAFE_INT = 2**53


def _jcs_string(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValueError("lone surrogate: not valid Unicode (RFC 8785 requires I-JSON)") from e
    return json.dumps(s, ensure_ascii=False)


def _jcs_number(f: float) -> str:
    """ECMAScript Number.prototype.toString for a finite double, as RFC 8785 requires."""
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity are not JSON numbers")
    if f == 0:
        return "0"
    t = Decimal(repr(abs(f))).normalize().as_tuple()
    digits = "".join(map(str, t.digits))
    k, n = len(digits), t.exponent + len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * -n + digits
    else:
        e = n - 1
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return ("-" if f < 0 else "") + out


def canonical(obj: Any) -> str:
    """RFC 8785 JSON Canonicalization Scheme. Integers beyond 2**53 must be passed as strings."""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        if abs(obj) > _MAX_SAFE_INT:
            raise ValueError(f"integer {obj} exceeds 2**53; encode it as a string")
        return str(obj)
    if isinstance(obj, float):
        return _jcs_number(obj)
    if isinstance(obj, str):
        return _jcs_string(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonical(v) for v in obj) + "]"
    if isinstance(obj, dict):
        if not all(isinstance(k, str) for k in obj):
            raise TypeError("object keys must be strings")
        items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + canonical(v) for k, v in items) + "}"
    raise TypeError(f"not JSON-serializable: {type(obj).__name__}")


HASH_ALGS = {"sha-256": "sha256", "sha3-256": "sha3_256", "sm3": "sm3"}


def digest(data: str | bytes, alg: str = "sha-256") -> str:
    """Hex digest under a named algorithm. Every supported algorithm gives 32 bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    name = HASH_ALGS.get(alg)
    if name is None:
        raise PlugError("unsupported_op", f"hash algorithm {alg}")
    try:
        return hashlib.new(name, data).hexdigest()
    except ValueError:
        pass
    if alg == "sm3":
        try:
            from gmssl import func, sm3
        except ImportError:
            pass
        else:
            return sm3.sm3_hash(func.bytes_to_list(data))
    raise PlugError("unsupported_op", f"{alg} is not available in this Python build")


def sha256_hex(data: str | bytes) -> str:
    return digest(data, "sha-256")


def canon_fact_type(ft: str) -> str:
    return ft.strip().lower().replace(" ", ".").replace("_", ".")


def parse_time(value: str) -> datetime:
    """An ISO-8601 timestamp; a missing offset means UTC. Raises ValueError."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fact_bytes(fact: Any) -> bytes:
    """The bytes a fact is hashed as: bytes as-is, text as UTF-8, any other JSON value as RFC 8785."""
    if isinstance(fact, (bytes, bytearray)):
        return bytes(fact)
    if isinstance(fact, str):
        return fact.encode("utf-8")
    if fact is None or isinstance(fact, (bool, int, float, list, tuple, dict)):
        try:
            return canonical(fact).encode("utf-8")
        except (ValueError, TypeError, RecursionError) as e:
            raise PlugError("unsupported_op", f"fact is not I-JSON: {e}") from e
    raise PlugError("unsupported_op", f"a fact is bytes, text, or a JSON value, not {type(fact).__name__}")


def commitment(fact: Any, salt: str, hash_alg: str = "sha-256") -> str:
    """Salted subject hash H(salt || fact): whoever holds fact and salt can open it; nobody else can link it."""
    return digest(bytes.fromhex(salt) + fact_bytes(fact), hash_alg)


def batch_commitment(root: str, size: int, hash_alg: str = "sha-256") -> str:
    """The subject anchored for a batch: the RFC 9162 root and tree size under the upp.batch domain."""
    return digest(canonical({"upp.batch": {"root": root, "size": size}}).encode("utf-8"), hash_alg)


_RESERVED = b'{"upp.'


# ---- types ----

@dataclass
class StateRef:
    network: str
    address: str


@dataclass
class Attestation:
    subject_hash: str          # hex digest of the fact (or its salted commitment)
    fact_type: str             # open vocabulary, lowercase dotted
    issuer: str                # DID
    issued_at: str             # ISO-8601, the issuer's claim
    expires_at: Optional[str] = None
    proof: dict = field(default_factory=dict)       # {alg, sig, verification_method}
    meta: dict = field(default_factory=dict)        # signed labels; keys starting with "_" are internal, unsigned
    anchor: Optional[StateRef] = None               # where the statement was recorded (set by the ledger)
    hash_alg: str = "sha-256"
    inclusion: Optional[dict] = None                # batch member: {tree, index, size, path, root}

    def __post_init__(self):
        self.fact_type = canon_fact_type(self.fact_type)
        if self.meta.get("model_family"):
            self.meta["model_family"] = str(self.meta["model_family"]).strip().lower()

    @classmethod
    def from_receipt(cls, r: "Receipt") -> "Attestation":
        """The attestation an attest receipt stands for, with every signed label, ready for check."""
        d = r.data
        try:
            return cls(subject_hash=d["subject_hash"], fact_type=d["fact_type"], issuer=d["issuer"],
                       issued_at=d.get("issued_at", ""), expires_at=d.get("expires_at"),
                       proof=dict(d.get("proof") or {}), meta=dict(d.get("meta") or {}), anchor=r.state_ref,
                       hash_alg=d.get("hash_alg", "sha-256"), inclusion=d.get("inclusion"))
        except (KeyError, TypeError, ValueError) as e:
            raise PlugError("proof_invalid", f"not an attest receipt: {e}") from e


@dataclass
class Receipt:
    op: str
    status: Status
    network: str
    state_ref: Optional[StateRef] = None
    data: dict = field(default_factory=dict)
    error: Optional[str] = None


def rejected(network: str, error: str, data: Optional[dict] = None) -> Receipt:
    return Receipt("verify", Status.REJECTED, network, data=dict(data or {}), error=error)


def statement(att: Attestation) -> dict:
    """What a proof signs and a ledger anchors: the subject hash with every label a verifier acts on."""
    return {"upp.statement": {
        "subject_hash": att.subject_hash.lower(), "hash_alg": att.hash_alg, "fact_type": att.fact_type,
        "issuer": att.issuer, "issued_at": att.issued_at, "expires_at": att.expires_at,
        "meta": {k: v for k, v in att.meta.items() if not str(k).startswith("_")}}}


def statement_hash(att: Attestation) -> str:
    return digest(canonical(statement(att)).encode("utf-8"), att.hash_alg)


# ---- batch trees (RFC 9162) ----

def _h(data: bytes, alg: str) -> bytes:
    return bytes.fromhex(digest(data, alg))


def merkle_leaf_hash(leaf: bytes, hash_alg: str = "sha-256") -> bytes:
    return _h(b"\x00" + leaf, hash_alg)


def merkle_levels(leaves: list, hash_alg: str = "sha-256") -> list[list[bytes]]:
    """Every level of the RFC 9162 tree, leaves first. Pairing bottom-up and carrying an unpaired last node up a
    level gives the same left-balanced tree as MTH (section 2.1.1), in O(n)."""
    level = [merkle_leaf_hash(leaf, hash_alg) for leaf in leaves]
    levels = [level]
    while len(level) > 1:
        level = [_h(b"\x01" + level[i] + level[i + 1], hash_alg) for i in range(0, len(level) - 1, 2)] \
            + ([level[-1]] if len(level) % 2 else [])
        levels.append(level)
    return levels


def merkle_root(leaves: list, hash_alg: str = "sha-256") -> bytes:
    return merkle_levels(leaves, hash_alg)[-1][0] if leaves else _h(b"", hash_alg)


def merkle_path_from_levels(index: int, levels: list[list[bytes]]) -> list:
    """PATH(m, D[n]) of RFC 9162 section 2.1.3.1 from precomputed levels."""
    path = []
    for level in levels[:-1]:
        if index ^ 1 < len(level):
            path.append(level[index ^ 1])
        index //= 2
    return path


def merkle_path(index: int, leaves: list, hash_alg: str = "sha-256") -> list:
    return merkle_path_from_levels(index, merkle_levels(leaves, hash_alg))


def merkle_verify_inclusion(leaf_hash: bytes, index: int, size: int, path: list, root: bytes,
                            hash_alg: str = "sha-256") -> bool:
    """Inclusion proof verification, RFC 9162 section 2.1.3.2."""
    width = len(_h(b"", hash_alg))
    if index < 0 or index >= size or any(len(x) != width for x in (leaf_hash, root, *path)):
        return False
    fn, sn, r = index, size - 1, leaf_hash
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _h(b"\x01" + p + r, hash_alg)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _h(b"\x01" + r + p, hash_alg)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def _inclusion_root(att: Attestation) -> tuple[Optional[str], Optional[str]]:
    inc = att.inclusion
    try:
        if inc.get("tree") != "rfc9162":
            return None, "proof_invalid: unsupported batch tree"
        index, size, root = int(inc["index"]), int(inc["size"]), bytes.fromhex(inc["root"])
        path = [bytes.fromhex(p) for p in inc["path"]]
        leaf = merkle_leaf_hash(bytes.fromhex(att.subject_hash), att.hash_alg)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None, "proof_invalid: bad inclusion proof"
    if not merkle_verify_inclusion(leaf, index, size, path, root, att.hash_alg):
        return None, "proof_invalid: subject is not in the batch"
    return root.hex(), None


# ---- ledgers and the plug ----

class Ledger:
    """What a ledger implements. It signs each statement for the session bound to the call, anchors it, and
    verifies attestations against its own records. `trust_policy` is True when it carries operator trust."""
    trust_policy = False

    def connect(self, network: str, auth: dict) -> dict: raise NotImplementedError   # returns {"subject": DID}
    def bind(self, subject: Optional[str]) -> None: raise NotImplementedError
    def attest(self, network: str, att: Attestation) -> Receipt: raise NotImplementedError
    def verify(self, att: Attestation, network: str, trust_registry=None) -> Receipt: raise NotImplementedError


@dataclass
class Session:
    id: str
    network: str
    subject: str


class Plug:
    """Prove facts, check attestations, closed by default.

    trust maps a network to the operator's trust policy: a registry ({"issuers": [...], "keys": {...}} or an
    http(s) URL to one) or ANY. Without a policy, check on that network is rejected.
    commitment="salted" anchors H(salt || fact) under a fresh salt returned only to the caller (personal data).
    """

    def __init__(self, trust: Optional[dict] = None, hash_alg: str = "sha-256", commitment: str = "plain"):
        digest(b"", hash_alg)
        if commitment not in ("plain", "salted"):
            raise ValueError("commitment is 'plain' or 'salted'")
        self.hash_alg, self.commitment = hash_alg, commitment
        self._ledgers: dict[str, Ledger] = {}
        self._sessions: dict[str, Session] = {}
        self._active: Optional[str] = None
        self._trust: dict[str, Any] = {}
        for network, policy in (trust or {}).items():
            self.trust(network, policy)

    def register(self, network: str, ledger: Ledger) -> None:
        self._ledgers[network] = ledger

    def trust(self, network: str, policy: Any) -> None:
        """The operator's trust policy for a network: a registry, or ANY to accept any authentic issuer."""
        url = isinstance(policy, str) and policy.startswith(("http://", "https://"))
        if not (policy == ANY or url or isinstance(policy, dict)):
            raise ValueError("trust policy is a registry (dict or http(s) URL) or ANY")
        if policy == ANY:
            POLICY_LOG.warning("trust on %s opened to ANY authentic issuer", network)
        self._trust[network] = policy

    def _ledger(self, network: str) -> Ledger:
        ledger = self._ledgers.get(network)
        if ledger is None:
            raise PlugError("not_found", f"no ledger for network {network}")
        return ledger

    # ---- sessions ----
    def open(self, network: str, credential: Optional[dict] = None) -> str:
        """Open a session; the ledger signs as its subject. Returns the session id and makes it active."""
        info = self._ledger(network).connect(network, dict(credential or {}))
        sid = secrets.token_hex(8)
        self._sessions[sid] = Session(sid, network, info["subject"])
        self._active = sid
        return sid

    def use(self, session_id: str) -> None:
        if session_id not in self._sessions:
            raise PlugError("not_found", session_id)
        self._active = session_id

    def close(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        if self._active == session_id:
            self._active = next(iter(self._sessions), None)

    def active(self) -> Optional[Session]:
        return self._sessions.get(self._active) if self._active else None

    def _network(self, network: Optional[str]) -> str:
        """The network named, else the active session's, else the only one registered."""
        if network:
            return network
        s = self.active()
        if s:
            return s.network
        if len(self._ledgers) == 1:
            return next(iter(self._ledgers))
        raise PlugError("auth_failed", "no network given, no active session, and more than one network")

    # ---- prove ----
    def attest(self, att: Attestation, network: Optional[str] = None, salt: Optional[str] = None) -> Receipt:
        """Sign and anchor an attestation as the session open on its network."""
        net = self._network(network)
        ledger = self._ledger(net)
        s = self.active()
        ledger.bind(s.subject if s and s.network == net else None)  # only the open session signs
        r = ledger.attest(net, att)
        r.data = dict(r.data)
        public_meta = {k: v for k, v in att.meta.items() if not str(k).startswith("_")}
        for key, value in (("subject_hash", att.subject_hash), ("fact_type", att.fact_type),
                           ("issuer", att.issuer), ("issued_at", att.issued_at), ("hash_alg", att.hash_alg),
                           ("meta", json.loads(json.dumps(public_meta)))):
            r.data.setdefault(key, value)
        if att.expires_at:
            r.data.setdefault("expires_at", att.expires_at)
        if salt:
            r.data["salt"] = salt
        return r

    def _issuer(self, network: str) -> str:
        s = self.active()
        if not s or s.network != network:
            raise PlugError("auth_failed", f"proving on {network} needs an open session there")
        return s.subject

    def prove(self, fact: Any, fact_type: str, network: Optional[str] = None, meta: Optional[dict] = None,
              expires_at: Optional[str] = None) -> Receipt:
        """Hash a fact (salted if configured), then sign and anchor it as the open session."""
        raw = fact_bytes(fact)
        if raw.startswith(_RESERVED):
            raise PlugError("unsupported_op", "facts in the reserved upp.* domain cannot be proven")
        net = self._network(network)
        salt = secrets.token_bytes(32).hex() if self.commitment == "salted" else None
        subject = commitment(fact, salt, self.hash_alg) if salt else digest(raw, self.hash_alg)
        att = Attestation(subject, fact_type, self._issuer(net), now_iso(), expires_at=expires_at,
                          meta=dict(meta or {}), hash_alg=self.hash_alg)
        return self.attest(att, net, salt)

    def prove_batch(self, facts: list, fact_type: str, network: Optional[str] = None,
                    meta: Optional[dict] = None) -> list[Receipt]:
        """prove for many facts under one anchor: the RFC 9162 root is signed once; each receipt carries its
        inclusion proof."""
        if not facts:
            raise ValueError("prove_batch needs at least one fact")
        raws = [fact_bytes(f) for f in facts]
        if any(raw.startswith(_RESERVED) for raw in raws):
            raise PlugError("unsupported_op", "facts in the reserved upp.* domain cannot be proven")
        if {"batch_size", "batch_fact_type"} & set(meta or {}):
            raise PlugError("unsupported_op", "batch_size and batch_fact_type are set by prove_batch, not the caller")
        meta = {k: v for k, v in (meta or {}).items() if not str(k).startswith("_")}
        net = self._network(network)
        ft = canon_fact_type(fact_type)
        salts = [secrets.token_bytes(32).hex() if self.commitment == "salted" else None for _ in facts]
        subjects = [commitment(f, s, self.hash_alg) if s else digest(raw, self.hash_alg)
                    for f, s, raw in zip(facts, salts, raws)]
        levels = merkle_levels([bytes.fromhex(s) for s in subjects], self.hash_alg)
        root = levels[-1][0].hex()
        batch = Attestation(batch_commitment(root, len(subjects), self.hash_alg), "upp.batch", self._issuer(net),
                            now_iso(), meta=dict(meta, batch_size=len(facts), batch_fact_type=ft),
                            hash_alg=self.hash_alg)
        r = self.attest(batch, net)
        receipts = []
        for i, subject in enumerate(subjects):
            data = {"subject_hash": subject, "fact_type": ft, "issuer": batch.issuer, "hash_alg": self.hash_alg,
                    "issued_at": batch.issued_at, "meta": json.loads(json.dumps(meta)),
                    "proof": dict(r.data.get("proof") or {}), "batch_root": root,
                    "inclusion": {"tree": "rfc9162", "index": i, "size": len(subjects), "root": root,
                                  "path": [p.hex() for p in merkle_path_from_levels(i, levels)]}}
            if salts[i]:
                data["salt"] = salts[i]
            receipts.append(Receipt("attest", r.status, r.network, r.state_ref, data, r.error))
        return receipts

    # ---- check ----
    def check(self, att: Attestation, network: Optional[str] = None, trust_registry=None) -> dict:
        """{"valid": bool, "receipt": Receipt}. Valid only if the issuer signed exactly this statement, the ledger
        anchored it, and the issuer passes the trust policy (the operator's, narrowed by trust_registry)."""
        r = self._verify(att, self._network(network), trust_registry)
        return {"valid": r.status == Status.OK, "receipt": r}

    def _verify(self, att: Attestation, net: str, trust_registry=None, require_policy: bool = True) -> Receipt:
        """require_policy=False checks authenticity only, for profiles (grants) that require trust of a root."""
        self._ledger(net)
        if att.expires_at:
            try:
                if datetime.now(timezone.utc) >= parse_time(att.expires_at):
                    return rejected(net, "proof_invalid: expired")
            except ValueError:
                return rejected(net, "proof_invalid: bad expires_at")
        check = self._verify_trusted if require_policy else (lambda a, n, _r: self._ledger(n).verify(a, n, None))
        if att.inclusion is None:
            return check(att, net, trust_registry)
        root, err = _inclusion_root(att)
        if err:
            return rejected(net, err)
        if {"batch_size", "batch_fact_type"} & set(att.meta):
            return rejected(net, "proof_invalid: batch member meta may not carry batch_size or batch_fact_type")
        size = int(att.inclusion["size"])
        batch = replace(att, subject_hash=batch_commitment(root, size, att.hash_alg), fact_type="upp.batch",
                        inclusion=None, meta=dict(att.meta, batch_size=size, batch_fact_type=att.fact_type))
        r = check(batch, net, trust_registry)
        return Receipt("verify", r.status, r.network, r.state_ref,
                       dict(r.data, subject_hash=att.subject_hash, batch_root=root), r.error)

    def _verify_trusted(self, att: Attestation, net: str, trust_registry=None) -> Receipt:
        """The ledger's verdict under every policy that applies: the operator's, then the caller's, which only
        narrows. With neither, and no trust of the ledger's own, verification is closed."""
        ledger = self._ledger(net)
        operator = self._trust.get(net)
        registries = [r for r in (None if operator == ANY else operator, trust_registry) if r is not None]
        if not registries and operator != ANY and not ledger.trust_policy:
            return rejected(net, f"not_authorized: no trust policy for {net} (closed by default)")
        result = None
        for registry in registries or [None]:
            result = ledger.verify(att, net, registry)
            if result.status != Status.OK:
                return result
        return result
