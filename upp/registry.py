# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Trust registries, guarded fetching of remote documents, and the signature check every ledger shares.

A registry is {"issuers": [DID, ...], "keys": {DID: [{verification_method, valid_from?, valid_until?}]}},
given inline or as an http(s) URL. Fetching is closed by default: allow_hosts names the hosts it may reach.
"""
from __future__ import annotations
import http.client
import ipaddress
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from .core import ANY, POLICY_LOG, PlugError, Receipt, Status, parse_time, rejected, statement_hash

_REGISTRY_TIMEOUT = 5
_REGISTRY_MAX_BYTES = 64 * 1024


# Remote documents (registries, status lists) are attacker-influenced URLs. Closed by default: nothing is
# fetched until the operator allows its host, and only from public addresses unless private ones are allowed too.
_FETCH_POLICY: dict[str, Any] = {"allow_private": False, "hosts": set()}


def allow_hosts(*hosts: str) -> None:
    """Allow fetching remote documents from these host names, or from any host with ANY."""
    for host in hosts:
        if host == ANY:
            POLICY_LOG.warning("remote document fetching opened to ANY host")
        elif not isinstance(host, str) or not host or "/" in host or "*" in host:
            raise ValueError(f"not a host name: {host!r}")
        _FETCH_POLICY["hosts"].add(host if host == ANY else host.lower().strip("[]"))


def reset_fetch_policy() -> None:
    """Back to closed: no hosts, public addresses only."""
    _FETCH_POLICY.update(allow_private=False, hosts=set())


def _check_host(url: str) -> None:
    hosts = _FETCH_POLICY["hosts"]
    host = (urlparse(url).hostname or "").lower()
    if ANY not in hosts and host not in hosts:
        raise PlugError("not_authorized", f"remote document host {host} is not allowed (closed by default)")


def allow_private_networks(allowed: bool = True) -> None:
    """Allow or forbid fetching remote documents from loopback, private, link-local, and other non-public addresses."""
    if allowed:
        POLICY_LOG.warning("remote document fetching opened to private addresses")
    _FETCH_POLICY["allow_private"] = bool(allowed)


_NAT64 = ipaddress.ip_network("64:ff9b::/96")  # well-known prefix: the IPv4 host is the low 32 bits
# Reachable only through a translator or not at all, though the ipaddress module may report them global.
_NOT_PUBLIC = tuple(ipaddress.ip_network(n) for n in (
    "64:ff9b:1::/48",     # local-use NAT64 (RFC 8215); operator-specific embedding
    "::/96",              # IPv4-compatible (deprecated)
    "::ffff:0:0:0/96",    # SIIT IPv4-translated
    "5f00::/16",          # SRv6 SIDs (RFC 9602)
))


def is_public_address(address) -> bool:
    """True for a unicast address on the public internet, judging embedded IPv4 hosts by themselves."""
    address = ipaddress.ip_address(address)
    target = address
    if address.version == 6:
        if address.ipv4_mapped is not None:
            target = address.ipv4_mapped
        elif address in _NAT64:
            target = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        elif any(address in n for n in _NOT_PUBLIC):
            return False
    return target.is_global and not target.is_multicast and not any(
        target in n for n in _NOT_PUBLIC if n.version == target.version)


def _check_peer(sock) -> None:
    if _FETCH_POLICY["allow_private"]:
        return
    if not is_public_address(sock.getpeername()[0].split("%", 1)[0]):
        sock.close()
        raise PlugError("not_authorized", "remote document host is not a public address")


class _GuardedHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        super().connect()
        _check_peer(self.sock)  # the address actually connected to, after DNS, on every hop


class _GuardedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        super().connect()
        _check_peer(self.sock)


class _GuardedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_GuardedHTTPConnection, req)


class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_GuardedHTTPSConnection, req, context=self._context)


class _RegistryRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme not in ("http", "https"):
            raise PlugError("proof_invalid", "trust registry redirect left http(s)")
        _check_host(newurl)
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
    _check_host(url)
    # No environment proxy: the guard must see the target host, not a proxy in front of it.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RegistryRedirect,
                                         _GuardedHTTPHandler, _GuardedHTTPSHandler)
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "upp"})
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


def resolve_registry(registry, network: str, issuer: Optional[str] = None):
    """{"trust_registry": {...}} when the issuer is listed in the registry (a dict or an http(s) URL), else a
    rejected Receipt. None for no registry."""
    if registry is None:
        return None
    try:
        if isinstance(registry, dict):
            payload = {"issuers": _issuer_list(registry)}
            keys = _registry_keys(registry)
            if keys:
                payload["keys"] = keys
        elif isinstance(registry, str):
            payload = fetch_registry(registry)
        else:
            return rejected(network, "proof_invalid: a trust registry is a dict or an http(s) URL")
    except PlugError as e:
        return rejected(network, f"{e.code}: {e.message}")
    if issuer and issuer not in payload["issuers"]:
        return rejected(network, "not_authorized: issuer not in trust registry", {"trust_registry": payload})
    return {"trust_registry": payload}


def check_signature(att, network: str, data: dict, at: Optional[datetime] = None) -> Receipt:
    """The issuer signed this exact statement with a key its DID names (or the registry lists), valid at `at`:
    the proven anchoring time, or now when nothing proves when the signature was made."""
    from .suites import SUITES, binds, issuer_key, verify
    data = dict(data)
    alg = att.proof.get("alg", "")
    if alg not in SUITES:
        return rejected(network, "proof_invalid: unsupported alg", data)
    data["alg"] = alg
    has_keys = bool((((data.get("trust_registry") or {}).get("keys")) or {}).get(att.issuer))
    resolvable = issuer_key(att.issuer) is not None
    if not (resolvable or has_keys):
        return rejected(network, "proof_invalid: unverifiable issuer", data)
    ok, detail = verify(statement_hash(att), att.proof)
    if not ok:
        return rejected(network, detail, data)
    if resolvable and not binds(att.issuer, detail):
        return rejected(network, "proof_invalid: issuer is not bound to the signing key", data)
    when = at or datetime.now(timezone.utc)
    applies, err = registry_key_status(data, att.issuer, detail, when)
    if err:
        return rejected(network, err, data)
    data.update({"verified": True, "verification_method": detail, "hash_alg": att.hash_alg})
    if applies:
        data["key_checked_at"] = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    return Receipt("verify", Status.OK, network, att.anchor, data)
