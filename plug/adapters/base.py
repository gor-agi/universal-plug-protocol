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
from typing import Any
from urllib.parse import urlparse

from ..core import PlugError, Receipt, SPEC_VERSION, StateRef, Status

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
    return {"url": url, "issuers": _issuer_list(doc)}


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
    if alg == "signature" or issuer_key(att.issuer) is None:
        return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network, data=data,
                       error="proof_invalid: unverifiable")
    ok, detail = verify(att.subject_hash, att.proof)
    if not ok:
        return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network, data=data, error=detail)
    if not binds(att.issuer, detail):
        return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network, data=data,
                       error="proof_invalid: issuer is not bound to the signing key")
    data.update({"verified": True, "verification_method": detail, "hash_alg": att.hash_alg})
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
        except PlugError as e:
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network,
                           error=f"{e.code}: {e.message}")
        return _membership(issuer, issuers, {"issuers": issuers}, network)
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
        if isinstance(issuers, list):
            try:
                payload["issuers"] = _issuer_list({"issuers": issuers})
            except PlugError as e:
                return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network,
                               error=f"{e.code}: {e.message}")
            return _membership(issuer, payload["issuers"], payload, network)
        return {"trust_registry": payload}
    return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network,
                   error="proof_invalid: bad trust_registry")
