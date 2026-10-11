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
from typing import Any
from urllib.parse import urlparse

from ..core import PlugError, Receipt, SPEC_VERSION, StateRef, Status, parse_time

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
        super().__init__(*args, **kwargs)
        self.log = AdapterLog()

    def last(self) -> dict[str, Any]:
        return self.log.last()

    def filter(self, **kwargs) -> list[dict[str, Any]]:
        return self.log.filter(**kwargs)

    def __len__(self) -> int:
        return len(self.log)


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


def fetch_registry(url: str) -> dict:
    """GET a registry document: {"issuers": ["did:...", ...]}. http and https only."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise PlugError("proof_invalid", "trust registry URL must be http or https")
    opener = urllib.request.build_opener(_RegistryRedirect)
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "plug-trust-registry"})
    try:
        with opener.open(req, timeout=_REGISTRY_TIMEOUT) as resp:
            raw = resp.read(_REGISTRY_MAX_BYTES + 1)
    except PlugError:
        raise
    except TimeoutError as e:
        raise PlugError("timeout", f"trust registry: {e}") from e
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, TimeoutError):
            raise PlugError("timeout", f"trust registry: {reason}") from e
        raise PlugError("not_found", f"trust registry: {e}") from e
    if len(raw) > _REGISTRY_MAX_BYTES:
        raise PlugError("proof_invalid", "trust registry document is too large")
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
    ok, detail = verify(att.subject_hash, att.proof)
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
