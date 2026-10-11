# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Minimal adapter test surface.

Adapters expose a read-only log of completed operations so tests and
diagnostics can observe behavior without reaching into private attributes.
"""
from __future__ import annotations
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from ..core import (
    Adapter, Attestation, Identity, PlugError, Receipt, SPEC_VERSION, StateRef, Status,
    parse_time, sha256_hex, statement_hash,
)

_REGISTRY_TIMEOUT = 5
_REGISTRY_MAX_BYTES = 64 * 1024


class AdapterLog:
    """Append-only record of adapter operations."""

    def __init__(self):
        self._entries: list[dict[str, Any]] = []

    def append(self, entry: dict[str, Any]) -> None:
        self._entries.append(entry)

    def __iter__(self):
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return bool(self._entries)

    def last(self) -> dict[str, Any]:
        if not self._entries:
            raise IndexError("log is empty")
        return self._entries[-1]

    def filter(self, **kwargs) -> list[dict[str, Any]]:
        return [e for e in self._entries if all(e.get(k) == v for k, v in kwargs.items())]


class LoggingAdapter:
    """Optional mixin: any adapter that composes this gets a public .log.

    last(), filter(), and len() delegate to that log so Plug.adapter_log()
    can be read without touching private attributes.
    """

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.log = AdapterLog()

    def last(self) -> dict[str, Any]:
        return self.log.last()

    def filter(self, **kwargs) -> list[dict[str, Any]]:
        return self.log.filter(**kwargs)

    def __len__(self) -> int:
        return len(self.log)


class InMemoryAdapter(LoggingAdapter, Adapter):
    """Shared substrate for in-memory adapters: store, subscription fan-out,
    dedup, and the six plumbing ops (connect, identify, query, settle,
    bridge, subscribe). Policy adapters override attest and optionally
    verify, and set tx_prefix / did_prefix class attributes.
    """

    tx_prefix = "mem"
    did_prefix = "did:plug"

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
        return {"scheme": auth.get("scheme", "raw"), "subject": f"{self.did_prefix}:{network}:{subj}"}

    def identify(self, network: str, identity: Identity) -> Receipt:
        rec = {"op": "identify", "did": identity.did, "method": identity.method}
        self._note(rec)
        return Receipt(SPEC_VERSION, "identify", Status.OK, network, data=rec)

    def attest(self, network: Optional[str], att: Attestation) -> Receipt:
        """Default: store and receipt. Policy adapters override with checks first."""
        net = network or "default"
        seq = att.meta.get("_seq", 0)
        tx = f"{self.tx_prefix}:0x" + sha256_hex(f"{net}:{att.subject_hash}:{att.issuer}:{seq}")
        rec = {"op": "attest", "tx": tx, "block": 9000000 + len(self._store),
               "subject_hash": att.subject_hash, "statement_hash": statement_hash(att), "fact_type": att.fact_type,
               "issuer": att.issuer,
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
        err = anchor_error(self._store, net, att)
        if err:
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data, error=err)
        return check_signature(att, net, data)

    def settle(self, network: str, op: str, payload: dict) -> Receipt:
        net = network or "default"
        tx = f"{self.tx_prefix}:0x" + sha256_hex(f"settle:{net}:{op}:{sha256_hex(str(payload))}")
        rec = {"op": "settle", "tx": tx}
        self._note(rec)
        return Receipt(SPEC_VERSION, "settle", Status.PENDING, net,
                       StateRef(net, tx, "event"), {"op": op, "tx": tx})

    def bridge(self, src: StateRef, target_network: str) -> Receipt:
        tx = f"{self.tx_prefix}:0x" + sha256_hex(f"bridge:{src.address}:{target_network}")
        rec = {"op": "bridge", "tx": tx, "source": src.address}
        self._note(rec)
        return Receipt(SPEC_VERSION, "bridge", Status.PENDING, target_network,
                       StateRef(target_network, tx, src.kind), rec)

    def subscribe(self, ref: StateRef, callback_id: str, filt: Optional[list] = None) -> str:
        handle = f"stream:{ref.network}:{ref.address}:{callback_id}"
        selected = list(filt or [])
        self._subs[handle] = (ref, selected)
        self.log.append({"op": "subscribe", "handle": handle, "filter": selected,
                         "address": ref.address})
        for rec in list(self.log):
            self._deliver(handle, ref, selected, rec)
        return handle


def anchor_error(store: dict, network: str, att) -> Optional[str]:
    """None when an in-memory record on this network carries exactly this attestation's statement."""
    sh = statement_hash(att)
    here = [r for r in store.values() if r.get("network") == network]
    if any(r.get("statement_hash") == sh for r in here):
        return None
    if any(r.get("subject_hash") == att.subject_hash for r in here):
        return "proof_invalid: statement does not match the anchor"
    return "not_found"


class _RegistryRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme not in ("http", "https"):
            raise PlugError("proof_invalid", "trust registry redirect left http(s)")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _issuer_list(doc) -> list[str]:
    issuers = doc.get("issuers") if isinstance(doc, dict) else None
    if not isinstance(issuers, list) or not issuers or not all(isinstance(i, str) and i for i in issuers):
        raise PlugError("proof_invalid", "trust registry issuers must be a non-empty list of strings")
    return issuers


def _registry_keys(doc) -> dict:
    """Optional {issuer DID: [{verification_method, valid_from?, valid_until?}]} of a registry document."""
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if keys is None:
        return {}
    bad = PlugError("proof_invalid", "trust registry keys must map issuers to lists of "
                                      "{verification_method, valid_from, valid_until}")
    if not isinstance(keys, dict):
        raise bad
    out = {}
    for did, entries in keys.items():
        if not isinstance(did, str) or not isinstance(entries, list) or not entries:
            raise bad
        clean = []
        for e in entries:
            if not isinstance(e, dict) or not isinstance(e.get("verification_method"), str):
                raise bad
            try:
                for f in ("valid_from", "valid_until"):
                    if e.get(f) is not None:
                        parse_time(e[f])
            except (AttributeError, ValueError) as err:
                raise bad from err
            clean.append({k: e[k] for k in ("verification_method", "valid_from", "valid_until")
                          if e.get(k) is not None})
        out[did] = clean
    return out


def _norm_method(method: str) -> str:
    base = (method or "").split("#", 1)[0]
    return base.lower() if base.lower().startswith("0x") else base


def registry_key_status(data: dict, issuer: str, method: str, at: datetime) -> tuple[bool, str | None]:
    """(applies, error) for the registry's keys of this issuer, evaluated at a proven time.

    applies is False when the registry lists no keys for the issuer. Callers pass the
    anchored time on a ledger and the current time otherwise, never a time the issuer claims.
    """
    entries = (((data or {}).get("trust_registry") or {}).get("keys") or {}).get(issuer)
    if not entries:
        return False, None
    listed = [e for e in entries if _norm_method(e["verification_method"]) == _norm_method(method)]
    if not listed:
        return True, "proof_invalid: key not listed for issuer in trust registry"
    for e in listed:
        start = parse_time(e["valid_from"]) if e.get("valid_from") else None
        end = parse_time(e["valid_until"]) if e.get("valid_until") else None
        if (start is None or start <= at) and (end is None or at < end):
            return True, None
    return True, f"proof_invalid: key not valid at {at.strftime('%Y-%m-%dT%H:%M:%SZ')}"


def fetch_document(url: str, accept: str = "application/json", max_bytes: int = _REGISTRY_MAX_BYTES,
                   what: str = "trust registry") -> bytes:
    """GET a document with the registry guards: http and https only, a timeout, a size cap, no redirect off http(s)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise PlugError("proof_invalid", f"{what} URL must be http or https")
    opener = urllib.request.build_opener(_RegistryRedirect)
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "plug-trust-registry"})
    try:
        with opener.open(req, timeout=_REGISTRY_TIMEOUT) as resp:
            raw = resp.read(max_bytes + 1)
    except PlugError:
        raise
    except TimeoutError as e:
        raise PlugError("timeout", f"{what}: {e}") from e
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, TimeoutError):
            raise PlugError("timeout", f"{what}: {reason}") from e
        raise PlugError("not_found", f"{what}: {e}") from e
    if len(raw) > max_bytes:
        raise PlugError("proof_invalid", f"{what} document is too large")
    return raw


def fetch_registry(url: str) -> dict:
    """GET a registry document: {"issuers": ["did:...", ...]}. http and https only."""
    raw = fetch_document(url)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise PlugError("proof_invalid", f"trust registry is not JSON: {e}") from e
    out = {"url": url, "issuers": _issuer_list(doc)}
    keys = _registry_keys(doc)
    if keys:
        out["keys"] = keys
    return out


def _membership(issuer: str | None, issuers: list[str], payload: dict, network: str):
    if issuer and issuer not in issuers:
        return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network,
                       data={"trust_registry": payload},
                       error="not_authorized: issuer not in trust registry")
    return {"trust_registry": payload}


def check_signature(att, network: str, data: dict) -> Receipt:
    """Signature and issuer binding through plug.suites. Issuers whose DID method cannot be resolved stay unverifiable."""
    from ..suites import SUITES, binds, issuer_key, verify
    alg = att.proof.get("alg", "")
    if alg not in SUITES and alg != "signature":
        return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network, data=data,
                       error="proof_invalid: unsupported alg")
    data["alg"] = alg
    has_keys = bool((((data.get("trust_registry") or {}).get("keys")) or {}).get(att.issuer))
    resolvable = issuer_key(att.issuer) is not None
    if alg == "signature" or not (resolvable or has_keys):
        return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network, data=data,
                       error="proof_invalid: unverifiable")
    ok, detail = verify(statement_hash(att), att.proof)
    if not ok:
        return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network, data=data, error=detail)
    if resolvable and not binds(att.issuer, detail):
        return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network, data=data,
                       error="proof_invalid: issuer is not bound to the signing key")
    # Nothing here proves when the signature was made, so registry keys are judged as of now.
    now = datetime.now(timezone.utc)
    applies, err = registry_key_status(data, att.issuer, detail, now)
    if err:
        return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network, data=data, error=err)
    data.update({"verified": True, "verification_method": detail, "hash_alg": att.hash_alg})
    if applies:
        data["key_checked_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return Receipt(SPEC_VERSION, "verify", Status.OK, network, data=data)


def resolve_trust_registry(query, trust_registry, network: str, issuer: str | None = None):
    """Resolve a registry and attach it to the verify receipt.

    A URL is fetched. A StateRef is queried. When the document lists issuers,
    the attestation issuer must be one of them. Core does not call this.
    Returns a data dict, or a rejected Receipt.
    """
    if trust_registry is None:
        return None
    if isinstance(trust_registry, dict):
        try:
            issuers = _issuer_list(trust_registry)
            keys = _registry_keys(trust_registry)
        except PlugError as e:
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network,
                           error=f"{e.code}: {e.message}")
        payload = {"issuers": issuers, **({"keys": keys} if keys else {})}
        return _membership(issuer, issuers, payload, network)
    if isinstance(trust_registry, str):
        try:
            doc = fetch_registry(trust_registry)
        except PlugError as e:
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network,
                           error=f"{e.code}: {e.message}")
        return _membership(issuer, doc["issuers"], doc, network)
    if isinstance(trust_registry, StateRef):
        try:
            found = query(trust_registry)
        except PlugError as e:
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network,
                           error=f"{e.code}: {e.message}")
        payload = {"network": trust_registry.network, "address": trust_registry.address,
                   "status": found.status.value}
        issuers = found.data.get("issuers") if isinstance(found.data, dict) else None
        try:
            keys = _registry_keys(found.data)
            if isinstance(issuers, list):
                payload["issuers"] = _issuer_list({"issuers": issuers})
        except PlugError as e:
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network,
                           error=f"{e.code}: {e.message}")
        if keys:
            payload["keys"] = keys
        if isinstance(issuers, list):
            return _membership(issuer, payload["issuers"], payload, network)
        return {"trust_registry": payload}
    return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network,
                   error="proof_invalid: bad trust_registry")
