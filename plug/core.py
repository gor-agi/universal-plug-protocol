# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Universal Plug Protocol core v0.3.0 - network-agnostic attestation and identity interface.
All network-specific logic lives in adapters. This module never imports
network SDKs or references any specific backend.
"""
from __future__ import annotations
import copy, hashlib, json, time, secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Optional

SPEC_VERSION = "0.3.0"

class Status(str, Enum):
    OK, PENDING, REJECTED, ERROR = "ok", "pending", "rejected", "error"

class Role(str, Enum):
    EXECUTION, PREFERENCE, IDENTITY, ASSET = "execution", "preference", "identity", "asset"

class FactType:
    """Open vocabulary. Recommended values only."""
    SENSOR_READING = "sensor.reading"
    DOC_SHA256 = "doc.sha256"
    GPS_FIX = "gps.fix"
    EVENT_LOG = "event.log"
    OWNERSHIP_CLAIM = "ownership.claim"
    PREDICTION_MARKET = "prediction.market"
    MONOCULTURE_WARNING = "prediction.monoculture"
    AGENT_ACTION = "agent.action"
    AGENT_REVIEW = "agent.review"
    CONTROL_HALT = "control.halt"
    CONTROL_RESUME = "control.resume"
    INCIDENT_REPORT = "incident.report"

ERROR_CODES = {
    "auth_failed": False, "not_found": False, "not_authorized": False,
    "unsupported_op": False, "proof_invalid": False, "timeout": True,
    "rate_limited": True, "bridge_unsupported": False, "finality_unknown": True,
}

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
        out = (digits[0] + ("." + digits[1:] if k > 1 else "")
               + "e" + ("+" if e >= 0 else "-") + str(abs(e)))
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

def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

HASH_ALGS = {"sha-256": "sha256", "sha3-256": "sha3_256", "sm3": "sm3"}

def digest(data: str | bytes, alg: str = "sha-256") -> str:
    """Hex digest under a named algorithm. All supported algorithms give 32 bytes."""
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

def canon_fact_type(ft: str) -> str:
    return ft.strip().lower().replace(" ", ".").replace("_", ".")

@dataclass
class Identity:
    did: str
    method: str  # key, web, ...

@dataclass
class Credential:
    """W3C-shaped credential. Adapters map this; core does not interpret claims."""
    issuer: str
    subject: str
    hash: str
    claims: dict = field(default_factory=dict)
    proof: dict = field(default_factory=dict)

@dataclass
class Attestation:
    subject_hash: str          # hex sha-256 of the real-world fact
    fact_type: str             # open vocabulary, canonicalized
    issuer: str                # DID
    issued_at: str             # ISO-8601
    expires_at: Optional[str] = None
    proof: dict = field(default_factory=dict)   # {alg, sig, verification_method}
    role: Optional[Role] = None
    meta: dict = field(default_factory=dict)    # model_family, model_id, diversity_signal; _seq is internal
    disclosure: list = field(default_factory=list)  # [{salt, hash}, ...] selective disclosure
    anchor: Optional[StateRef] = None  # where the subject hash was recorded; ledger adapters require it
    hash_alg: str = "sha-256"  # algorithm that produced subject_hash: sha-256, sha3-256, sm3
    inclusion: Optional[dict] = None  # batch membership: {tree, index, size, path, root}; proof and anchor cover root

    def __post_init__(self):
        self.fact_type = canon_fact_type(self.fact_type)
        if isinstance(self.role, str) and not isinstance(self.role, Role):
            self.role = Role(self.role)
        if self.meta.get("model_family"):
            self.meta["model_family"] = str(self.meta["model_family"]).strip().lower()
        if self.disclosure is None:
            self.disclosure = []

    @classmethod
    def from_receipt(cls, r: "Receipt") -> "Attestation":
        """The attestation an attest receipt stands for, with every signed label, ready for check."""
        d = r.data
        try:
            return cls(subject_hash=d["subject_hash"], fact_type=d["fact_type"], issuer=d["issuer"],
                       issued_at=d.get("issued_at", ""), expires_at=d.get("expires_at"),
                       proof=dict(d.get("proof") or {}), role=d.get("role"), meta=dict(d.get("meta") or {}),
                       disclosure=list(d.get("disclosure") or []), anchor=r.state_ref,
                       hash_alg=d.get("hash_alg", "sha-256"), inclusion=d.get("inclusion"))
        except (KeyError, TypeError, ValueError) as e:
            raise PlugError("proof_invalid", f"not an attest receipt: {e}") from e

@dataclass
class StateRef:
    network: str
    address: str
    kind: str  # asset, ownership, event, market

@dataclass
class Receipt:
    spec_version: str
    op: str
    status: Status
    network: str
    state_ref: Optional[StateRef] = None
    data: dict = field(default_factory=dict)
    error: Optional[str] = None
    seq: int = 0

    def receipt_hash(self) -> str:
        """Hash inputs: spec_version, op, network, subject_hash, fact_type, issuer, role. NO seq."""
        payload = {
            "spec_version": self.spec_version,
            "op": self.op,
            "network": self.network,
            "subject_hash": self.data.get("subject_hash", ""),
            "fact_type": self.data.get("fact_type"),
            "issuer": self.data.get("issuer"),
            "role": self.data.get("role"),
        }
        return sha256_hex(canonical(payload))

class PlugError(Exception):
    def __init__(self, code: str, message: str = ""):
        if code not in ERROR_CODES:
            raise ValueError(f"unknown error code: {code}")
        self.code = code
        self.message = message
        self.retries = ERROR_CODES[code]
        super().__init__(f"{code}: {message}")

class AdapterLogView:
    """Read-only log. The adapter object, including any key material, stays private."""

    def __init__(self, log):
        self.log = log

    def last(self):
        return self.log.last()

    def filter(self, **kwargs):
        return self.log.filter(**kwargs)

    def __len__(self):
        return len(self.log)

    def __iter__(self):
        return iter(self.log)


def parse_time(value: str) -> datetime:
    """Parse an ISO-8601 timestamp. A missing offset means UTC. Raises ValueError."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def fact_bytes(fact: Any) -> bytes:
    """The bytes a fact is hashed as: raw bytes as-is, text as UTF-8, any other JSON value as RFC 8785."""
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
    """Salted subject hash H(salt || fact). Whoever holds the fact and the salt can open it; nobody else can."""
    return digest(bytes.fromhex(salt) + fact_bytes(fact), hash_alg)


def bridge_commitment(src: "StateRef", hash_alg: str = "sha-256") -> str:
    """Subject hash a target network anchors to reference a proof on another network."""
    return digest(canonical({"plug.bridge": {"network": src.network, "address": src.address,
                                             "kind": src.kind}}).encode("utf-8"), hash_alg)


def batch_commitment(root: str, size: int, hash_alg: str = "sha-256") -> str:
    """Subject hash anchored for a batch: binds the RFC 9162 root and tree size under the plug.batch domain,
    so no single-fact subject can be presented as a batch root."""
    return digest(canonical({"plug.batch": {"root": root, "size": size}}).encode("utf-8"), hash_alg)


def statement(att: "Attestation") -> dict:
    """What a proof signs and a ledger anchors: the subject hash together with every label a verifier acts on.
    Meta keys beginning with "_" are implementation-internal and excluded."""
    return {"plug.statement": {
        "subject_hash": att.subject_hash.lower(), "hash_alg": att.hash_alg, "fact_type": att.fact_type,
        "issuer": att.issuer, "issued_at": att.issued_at, "expires_at": att.expires_at,
        "role": att.role.value if isinstance(att.role, Role) else att.role,
        "meta": {k: v for k, v in att.meta.items() if not str(k).startswith("_")},
        "disclosure": list(att.disclosure or [])}}


def statement_hash(att: "Attestation") -> str:
    """32-byte digest of the statement under the attestation's hash_alg; signed by the proof, carried by the anchor."""
    return digest(canonical(statement(att)).encode("utf-8"), att.hash_alg)


_RESERVED_FACT_PREFIX = b'{"plug.'


def _check_not_reserved(data: bytes) -> None:
    """Facts whose bytes open like a plug.* commitment are refused, keeping that domain to the plug itself."""
    if data.startswith(_RESERVED_FACT_PREFIX):
        raise PlugError("unsupported_op", "facts in the reserved plug.* commitment domain cannot be proven")


# ---- batch anchoring: RFC 9162 Merkle tree hash and inclusion proofs ----

def _h(data: bytes, alg: str) -> bytes:
    return bytes.fromhex(digest(data, alg))


def merkle_leaf_hash(leaf: bytes, hash_alg: str = "sha-256") -> bytes:
    return _h(b"\x00" + leaf, hash_alg)


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list, hash_alg: str = "sha-256") -> bytes:
    """MTH(D[n]) of RFC 9162 section 2.1.1 over raw leaf inputs."""
    if not leaves:
        return _h(b"", hash_alg)
    if len(leaves) == 1:
        return merkle_leaf_hash(leaves[0], hash_alg)
    k = _split(len(leaves))
    return _h(b"\x01" + merkle_root(leaves[:k], hash_alg) + merkle_root(leaves[k:], hash_alg), hash_alg)


def merkle_path(index: int, leaves: list, hash_alg: str = "sha-256") -> list:
    """PATH(m, D[n]) of RFC 9162 section 2.1.3.1: sibling hashes from the leaf up."""
    if len(leaves) <= 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return merkle_path(index, leaves[:k], hash_alg) + [merkle_root(leaves[k:], hash_alg)]
    return merkle_path(index - k, leaves[k:], hash_alg) + [merkle_root(leaves[:k], hash_alg)]


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
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _h(b"\x01" + r + p, hash_alg)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def _inclusion_root(att: "Attestation") -> tuple[Optional[str], Optional[str]]:
    """(batch root hex, None) when att.inclusion proves its subject is in the batch, else (None, error)."""
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


def _expiry_error(expires_at: Optional[str]) -> Optional[str]:
    if not expires_at:
        return None
    try:
        exp = parse_time(expires_at)
    except ValueError:
        return "proof_invalid: bad expires_at"
    if datetime.now(timezone.utc) >= exp:
        return "proof_invalid: expired"
    return None


def _disclosure_error(pairs) -> Optional[str]:
    """Each pair is {salt, hash}. The hash is a commitment; the disclosed value is not in the pair."""
    if not pairs:
        return None
    if not isinstance(pairs, list):
        return "proof_invalid: bad disclosure"
    for pair in pairs:
        if not isinstance(pair, dict):
            return "proof_invalid: bad disclosure"
        salt, digest = pair.get("salt"), pair.get("hash")
        if not isinstance(salt, str) or not salt or not isinstance(digest, str):
            return "proof_invalid: bad disclosure"
        try:
            if len(digest) != 64 or int(digest, 16) < 0:
                return "proof_invalid: bad disclosure"
        except ValueError:
            return "proof_invalid: bad disclosure"
    return None


class Adapter:
    """Interface every network adapter implements. Core never sees network internals."""
    def bind(self, subject: Optional[str]) -> None:
        """Core names the active session's subject before settle and bridge. Keyless adapters ignore it."""
        return None
    def connect(self, network: str, auth: dict) -> dict: raise NotImplementedError
    def identify(self, network: str, identity: Identity) -> Receipt: raise NotImplementedError
    def attest(self, network: str, att: Attestation) -> Receipt: raise NotImplementedError
    def query(self, ref: StateRef, fields: Optional[list] = None) -> Receipt: raise NotImplementedError
    def verify(self, att: Attestation, network: str, trust_registry=None) -> Receipt: raise NotImplementedError
    def settle(self, network: str, op: str, payload: dict) -> Receipt: raise NotImplementedError
    def bridge(self, src: StateRef, target_network: str) -> Receipt: raise NotImplementedError
    def subscribe(self, ref: StateRef, callback_id: str, filt: Optional[list] = None) -> str: raise NotImplementedError

class Session:
    def __init__(self, session_id: str, network: str, credential_scheme: str, credential_subject: str):
        self.session_id = session_id
        self.network = network
        self.credential_scheme = credential_scheme
        self.credential_subject = credential_subject
        self.meta: dict = {}  # e.g. {"node_hint": "local"}

class Plug:
    """Core. Eight ops + five session ops. Delegates everything to the active adapter.

    hash_alg is deployment configuration: a profile that mandates SM3 or SHA3 sets it here, not in core.
    commitment="salted" anchors H(salt || fact) with a fresh salt returned only to the caller; use it for personal data.
    """
    def __init__(self, hash_alg: str = "sha-256", commitment: str = "plain"):
        digest(b"", hash_alg)  # fail at construction if the profile's algorithm is unavailable
        if commitment not in ("plain", "salted"):
            raise ValueError("commitment must be 'plain' or 'salted'")
        self.hash_alg = hash_alg
        self.commitment = commitment
        self._adapters: dict[str, Adapter] = {}
        self._sessions: dict[str, Session] = {} 
        self._active: Optional[str] = None
        self._seq = 0                      # monotonic ordering signal; stamped into state-ref addresses by adapters
        self._idempotency: dict[str, tuple] = {}  # hash -> (receipt, timestamp)
        self._batch_salts: dict[str, tuple] = {}  # salted batch key -> (salts, timestamp); memory only
        self._pred_window: dict[str, list] = {}    # market -> [(family, ts)]
        self._mono_warned: dict[str, float] = {}  # market -> last warning timestamp (24h cooldown)

    def register_adapter(self, name: str, adapter: Adapter):
        self._adapters[name] = adapter

    def _adapter(self, name: str) -> Adapter:
        adapter = self._adapters.get(name)
        if adapter is None:
            raise PlugError("not_found", f"no adapter named {name}")
        return adapter

    def adapter_log(self, name: str) -> AdapterLogView:
        """Read-only view of an adapter log. Exposes .log, .last(), .filter(), and len()."""
        log = getattr(self._adapter(name), "log", None)
        if log is None or not hasattr(log, "last"):
            raise PlugError("unsupported_op", f"adapter {name} has no log")
        return AdapterLogView(log)

    # ---- session ops ----
    def open(self, network: str, credential: dict) -> str:
        if network not in self._adapters:
            raise PlugError("not_found", f"no adapter for network {network}")
        info = self._adapters[network].connect(network, credential)
        sid = secrets.token_hex(8)
        self._sessions[sid] = Session(sid, network, credential.get("scheme",""), info.get("subject",""))
        self._active = sid
        return sid

    def use(self, session_id: str):
        if session_id not in self._sessions:
            raise PlugError("not_found", session_id)
        self._active = session_id

    def close(self, session_id: str):
        self._sessions.pop(session_id, None)
        if self._active == session_id:
            self._active = next(iter(self._sessions), None)

    def active(self) -> Optional[Session]:
        return self._sessions.get(self._active) if self._active else None

    def list_sessions(self) -> list[Session]:
        return list(self._sessions.values())

    def _resolve_network(self, network: Optional[str]) -> str:
        if network:
            return network
        s = self.active()
        if not s:
            raise PlugError("auth_failed", "no network given and no active session")
        return s.network

    def _evict_idempotency(self):
        now = time.time()
        self._idempotency = {k: v for k, v in self._idempotency.items() if now - v[1] < 86400}
        self._batch_salts = {k: v for k, v in self._batch_salts.items() if now - v[1] < 86400}

    def idempotency_keys(self) -> list[str]:
        """Public read-only view of the idempotency cache for tests and diagnostics."""
        self._evict_idempotency()
        return list(self._idempotency.keys())

    # ---- core ops ----
    def connect(self, network: str, auth: dict) -> Session:
        self.open(network, auth)
        return self.active()

    def identify(self, network: Optional[str], identity: Identity) -> Receipt:
        net = self._resolve_network(network)
        return self._adapter(net).identify(net, identity)

    def attest(self, network: Optional[str], att: Attestation) -> Receipt:
        return self._attest(network, att)

    @staticmethod
    def _idempotency_key(net: str, att: Attestation, idem_subject: Optional[str], plug_time: bool) -> str:
        """The statement as the cache sees it. A salted prove keys on the unsalted digest (memory only), and
        when the plug chose issued_at itself the time is left out, so a retry returns the first receipt."""
        keyed = replace(att, subject_hash=idem_subject or att.subject_hash,
                        issued_at="" if plug_time else att.issued_at, meta=dict(att.meta))
        return sha256_hex(canonical({"spec_version": SPEC_VERSION, "op": "attest", "network": net,
                                     "statement": statement(keyed)}))

    def _attest(self, network: Optional[str], att: Attestation, idem_subject: Optional[str] = None,
                salt: Optional[str] = None, plug_time: bool = False) -> Receipt:
        # Explicit network beats the active session. Neither one is an error.
        net = self._resolve_network(network)
        self._adapter(net)
        self._evict_idempotency()
        seq = self._seq
        self._seq += 1
        # Stamp seq as internal meta for the adapter (state-ref address ordering).
        # Internal meta is outside the statement and the cache key.
        att.meta["_seq"] = seq
        try:
            role = att.role.value if att.role else None
            h = self._idempotency_key(net, att, idem_subject, plug_time)
            if h in self._idempotency:
                # Clone cached receipt and stamp this call's fresh seq; seq is outside every hash.
                cached = self._idempotency[h][0]
                return Receipt(cached.spec_version, cached.op, cached.status, cached.network,
                               cached.state_ref, copy.deepcopy(cached.data), cached.error, seq=seq)
            r = self._adapter(net).attest(net, att)
            r.seq = seq
            r.data = dict(r.data)  # adapters may log the same dict; caller-only fields must not reach it
            # Hash inputs travel on the receipt so receipt_hash() can be computed for any adapter.
            r.data.setdefault("fact_type", att.fact_type)
            r.data.setdefault("issuer", att.issuer)
            r.data.setdefault("hash_alg", att.hash_alg)
            r.data.setdefault("issued_at", att.issued_at)
            # The rest of the signed statement, so Attestation.from_receipt can rebuild it exactly.
            r.data.setdefault("meta", copy.deepcopy({k: v for k, v in att.meta.items() if not str(k).startswith("_")}))
            r.data.setdefault("role", role)
            if att.expires_at:
                r.data.setdefault("expires_at", att.expires_at)
            if att.disclosure:
                r.data.setdefault("disclosure", copy.deepcopy(list(att.disclosure)))
            if salt:
                r.data["salt"] = salt
            if r.status in (Status.OK, Status.PENDING):
                # The cache keeps its own copy: nothing the caller does to r can change a later hit.
                self._idempotency[h] = (copy.deepcopy(r), time.time())
            # diversity tracking for prediction.market — last 20, no age cutoff.
            # The 24h gate applies only to how often the warning itself is emitted.
            if att.fact_type == FactType.PREDICTION_MARKET and att.meta.get("model_family"):
                market = att.meta.get("market_id", net or "default")
                window = self._pred_window.setdefault(market, [])
                window.append((att.meta["model_family"], time.time()))
                self._pred_window[market] = window[-20:]
                families = {f for f, _ in self._pred_window[market]}
                if len(self._pred_window[market]) >= 20 and len(families) / len(self._pred_window[market]) < 0.3:
                    last = self._mono_warned.get(market, 0.0)
                    if time.time() - last >= 86400:
                        self._mono_warned[market] = time.time()
                        warn = Attestation(subject_hash=sha256_hex(f"monoculture:{market}:{time.time()}"),
                                           fact_type=FactType.MONOCULTURE_WARNING, issuer=att.issuer,
                                           issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                           meta={"market_id": market, "distinct_families": len(families),
                                                 "window": len(self._pred_window[market])})
                        self.attest(net, warn)  # recursive but safe: different subject_hash
            return r
        finally:
            att.meta.pop("_seq", None)

    def query(self, ref: StateRef, fields: Optional[list] = None) -> Receipt:
        return self._adapter(ref.network).query(ref, fields)

    def verify(self, att: Attestation, network: Optional[str] = None, trust_registry=None) -> Receipt:
        net = self._resolve_network(network)
        self._adapter(net)
        for err in (_expiry_error(att.expires_at), _disclosure_error(att.disclosure)):
            if err:
                return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, error=err)
        if att.inclusion is None:
            return self._adapter(net).verify(att, net, trust_registry)
        root, err = _inclusion_root(att)
        if err:
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, error=err)
        if {"batch_size", "batch_fact_type"} & set(att.meta):
            # The verifier derives these for the batch statement; a member that carries its own is unsigned.
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net,
                           error="proof_invalid: batch member meta may not carry batch_size or batch_fact_type")
        size = int(att.inclusion["size"])
        anchored = batch_commitment(root, size, att.hash_alg)
        # The signed batch statement: same issuer, time, and meta, typed plug.batch, naming the member type.
        batch = replace(att, subject_hash=anchored, fact_type="plug.batch", inclusion=None,
                        meta=dict(att.meta, batch_size=size, batch_fact_type=att.fact_type))
        r = self._adapter(net).verify(batch, net, trust_registry)
        data = dict(r.data, subject_hash=att.subject_hash, batch_root=root, batch_commitment=anchored,
                    leaf_index=int(att.inclusion["index"]), batch_size=size)
        return Receipt(r.spec_version, r.op, r.status, r.network, r.state_ref, data, r.error, r.seq)

    def _bind(self, adapter: Adapter, network: str) -> Adapter:
        s = self.active()
        bind = getattr(adapter, "bind", None)
        if bind:
            bind(s.credential_subject if s and s.network == network else None)
        return adapter

    def settle(self, network: Optional[str], op: str, payload: dict) -> Receipt:
        net = self._resolve_network(network)
        return self._bind(self._adapter(net), net).settle(net, op, payload)

    def bridge(self, src: StateRef, target_network: str) -> Receipt:
        """Reference a proof from another network. With both adapters registered, no relayer is trusted:
        the source is queried, and a commitment to it is attested on the target like any other fact."""
        if target_network not in self._adapters:
            return self._bind(self._adapter(src.network), src.network).bridge(src, target_network)
        ref = {"network": src.network, "address": src.address, "kind": src.kind}
        source = self.query(src)
        if source.status != Status.OK:
            return Receipt(SPEC_VERSION, "bridge", Status.REJECTED, target_network, None,
                           {"source": ref}, "proof_invalid: source proof is not ok")
        s = self.active()
        att = Attestation(subject_hash=bridge_commitment(src, self.hash_alg), fact_type="plug.bridge",
                          issuer=s.credential_subject if s and s.network == target_network else "did:plug:anon",
                          issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          meta={"bridge_source": ref}, hash_alg=self.hash_alg)
        r = self.attest(target_network, att)
        data = {"source": ref, "commitment": att.subject_hash,
                "attestation": {"subject_hash": att.subject_hash, "fact_type": att.fact_type,
                                "issuer": att.issuer, "issued_at": r.data.get("issued_at", att.issued_at),
                                "hash_alg": att.hash_alg, "meta": copy.deepcopy(r.data.get("meta", att.meta)),
                                "proof": r.data.get("proof", {}),
                                "anchor": {"network": r.state_ref.network, "address": r.state_ref.address,
                                           "kind": r.state_ref.kind} if r.state_ref else None}}
        return Receipt(SPEC_VERSION, "bridge", r.status, target_network, r.state_ref, data, r.error, seq=r.seq)

    def subscribe(self, ref: StateRef, callback_id: str, filt: Optional[list] = None) -> str:
        return self._adapter(ref.network).subscribe(ref, callback_id, filt)

    # ---- user-facing verbs ----
    def prove(self, fact: Any, fact_type: str, network: Optional[str] = None, meta: Optional[dict] = None) -> Receipt:
        raw = fact_bytes(fact)
        _check_not_reserved(raw)
        plain = digest(raw, self.hash_alg)
        salt = secrets.token_bytes(32).hex() if self.commitment == "salted" else None
        subject = commitment(fact, salt, self.hash_alg) if salt else plain
        att = Attestation(subject_hash=subject, fact_type=fact_type,
                          issuer=self.active().credential_subject if self.active() else "did:plug:anon",
                          issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), meta=meta or {},
                          hash_alg=self.hash_alg)
        return self._attest(network, att, idem_subject=plain if salt else None, salt=salt, plug_time=True)

    def prove_batch(self, facts: list, fact_type: str, network: Optional[str] = None,
                    meta: Optional[dict] = None) -> list[Receipt]:
        """prove for many facts with one anchor: a commitment to the RFC 9162 root is attested and signed
        once, and each fact's receipt carries its inclusion proof. Not a new operation."""
        if not facts:
            raise ValueError("prove_batch needs at least one fact")
        raws = [fact_bytes(f) for f in facts]
        for raw in raws:
            _check_not_reserved(raw)
        plains = [digest(raw, self.hash_alg) for raw in raws]
        issuer = self.active().credential_subject if self.active() else "did:plug:anon"
        ft = canon_fact_type(fact_type)
        net = self._resolve_network(network)
        salts = [None] * len(facts)
        batch_key = None
        if self.commitment == "salted":
            # A retry reuses the first call's salts (memory only), so it reproduces the anchored root.
            plain_root = merkle_root([bytes.fromhex(p) for p in plains], self.hash_alg).hex()
            batch_key = sha256_hex(canonical({"network": net, "issuer": issuer, "fact_type": ft,
                                              "plain_root": plain_root, "hash_alg": self.hash_alg}))
            self._evict_idempotency()
            cached = self._batch_salts.get(batch_key)
            salts = list(cached[0]) if cached else [secrets.token_bytes(32).hex() for _ in facts]
        subjects = [commitment(f, s, self.hash_alg) if s else p for f, s, p in zip(facts, salts, plains)]
        leaves = [bytes.fromhex(s) for s in subjects]
        root = merkle_root(leaves, self.hash_alg).hex()
        batch = Attestation(subject_hash=batch_commitment(root, len(leaves), self.hash_alg),
                            fact_type="plug.batch", issuer=issuer,
                            issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            meta=dict(meta or {}, batch_size=len(facts), batch_fact_type=ft), hash_alg=self.hash_alg)
        r = self._attest(net, batch, plug_time=True)
        if batch_key and r.status in (Status.OK, Status.PENDING):
            self._batch_salts[batch_key] = (salts, time.time())
        receipts = []
        for i, subject in enumerate(subjects):
            signed_meta = copy.deepcopy({k: v for k, v in r.data.get("meta", batch.meta).items()
                                         if k not in ("batch_size", "batch_fact_type") and not str(k).startswith("_")})
            data = {"subject_hash": subject, "fact_type": ft, "issuer": issuer, "hash_alg": self.hash_alg,
                    "issued_at": r.data.get("issued_at", batch.issued_at), "meta": signed_meta,
                    "proof": dict(r.data.get("proof") or {}), "batch_root": root,
                    "batch_commitment": batch.subject_hash,
                    "inclusion": {"tree": "rfc9162", "index": i, "size": len(subjects), "root": root,
                                  "path": [p.hex() for p in merkle_path(i, leaves, self.hash_alg)]}}
            if salts[i]:
                data["salt"] = salts[i]
            receipts.append(Receipt(SPEC_VERSION, "attest", r.status, r.network, r.state_ref, data, r.error, r.seq))
        return receipts

    def check(self, target: Any, network: Optional[str] = None, trust_registry=None) -> dict:
        if isinstance(target, Receipt) and target.op == "bridge":
            return self._check_bridge(target, trust_registry)
        if isinstance(target, Attestation):
            r = self.verify(target, network, trust_registry)
            return {"valid": r.status == Status.OK, "receipt": r}
        if isinstance(target, StateRef):
            r = self.query(target)
            return {"valid": r.status == Status.OK, "receipt": r}
        if isinstance(target, str) and target.startswith("did:"):
            parts = target.split(":")
            r = self.identify(network, Identity(target, parts[1] if len(parts) > 1 else ""))
            return {"valid": r.status == Status.OK, "receipt": r}
        raise PlugError("unsupported_op", "check target must be Attestation, StateRef, DID string, or bridge Receipt")

    def _check_bridge(self, r: Receipt, trust_registry=None) -> dict:
        """Both sides, independently: the source proof holds, and the target anchors a commitment to exactly it."""
        def verdict(error: Optional[str], data: dict) -> dict:
            status = Status.REJECTED if error else Status.OK
            return {"valid": error is None, "receipt": Receipt(SPEC_VERSION, "verify", status, r.network,
                                                               r.state_ref, data, error)}
        try:
            ref = r.data["source"]
            src = StateRef(ref["network"], ref["address"], ref["kind"])
            a = r.data["attestation"]
            anchor = StateRef(**a["anchor"]) if a.get("anchor") else None
        except (KeyError, TypeError):
            return verdict("proof_invalid: not a plug bridge receipt", {})
        att = Attestation(subject_hash=a["subject_hash"], fact_type=a["fact_type"], issuer=a["issuer"],
                          issued_at=a.get("issued_at", ""), meta=dict(a.get("meta") or {}),
                          proof=dict(a.get("proof") or {}), anchor=anchor, hash_alg=a.get("hash_alg", "sha-256"))
        if att.subject_hash != bridge_commitment(src, att.hash_alg):
            return verdict("proof_invalid: target commitment does not match the source", {"source": ref})
        try:
            source = self.query(src)
        except PlugError as e:
            return verdict(f"{e.code}: source {src.address}", {"source": ref})
        if source.status != Status.OK:
            return verdict("proof_invalid: source proof is not ok", {"source": ref})
        target = self.verify(att, r.network, trust_registry)
        data = {"source": ref, "source_finality": source.data.get("finality"),
                "target": target.data}
        return verdict(None if target.status == Status.OK else f"target: {target.error}", data)

    def watch(self, target: Any, filt: Optional[list] = None) -> str:
        if isinstance(target, StateRef):
            # Content-addressed stream key: portable across runtimes, no object-id coupling.
            key = sha256_hex(canonical({"network": target.network, "address": target.address, "kind": target.kind}))[:16]
            return self.subscribe(target, f"watch-{key}", filt)
        raise PlugError("unsupported_op", "watch target must be a StateRef")
