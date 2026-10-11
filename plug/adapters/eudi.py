# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""EUDI Wallet adapter: OpenID4VCI issuance, SD-JWT VC / mdoc mapping,
ETSI trusted-list resolution, Token Status List polling.

Jurisdiction profile, not a core feature. The plug stays neutral;
this adapter satisfies eIDAS 2.0 / ARF 3.0 mandates through
configuration and adapter-owned resolution.
"""
from __future__ import annotations
import base64
import json
import time
import zlib
from datetime import datetime, timezone
from typing import Optional

from ..core import Attestation, PlugError, Receipt, Status, SPEC_VERSION
from .base import (
    InMemoryAdapter, anchor_error, check_signature, fetch_document, fetch_registry, registry_key_status,
    resolve_trust_registry,
)

_DEFAULT_STATUS_LIST_POLL = 300  # 5 minutes
_DEFAULT_STATUS_LIST_MAX_STALE = 3600  # longest a cached token stands in while the list cannot be fetched
_STATUS_LIST_MAX_BYTES = 1 << 20          # fetched Status List Token
_STATUS_LIST_MAX_DECODED = 16 << 20       # decompressed status byte array
_STATUS_NAMES = {1: "revoked", 2: "suspended"}


def _b64url(text: str) -> bytes:
    if not isinstance(text, str):
        raise PlugError("proof_invalid", "status list: expected base64url text")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as e:
        raise PlugError("proof_invalid", f"status list: bad base64url: {e}") from e


def decode_status_list(status_list) -> tuple[int, bytes]:
    """(bits, byte array) of a Token Status List: {"bits": 1|2|4|8, "lst": base64url(ZLIB(DEFLATE(bytes)))}."""
    if not isinstance(status_list, dict):
        raise PlugError("proof_invalid", "status list: status_list must be an object")
    bits = status_list.get("bits")
    if isinstance(bits, bool) or bits not in (1, 2, 4, 8):
        raise PlugError("proof_invalid", "status list: bits must be 1, 2, 4, or 8")
    inflater = zlib.decompressobj()
    try:
        array = inflater.decompress(_b64url(status_list.get("lst")), _STATUS_LIST_MAX_DECODED)
    except zlib.error as e:
        raise PlugError("proof_invalid", f"status list: lst is not ZLIB data: {e}") from e
    if inflater.unconsumed_tail:
        raise PlugError("proof_invalid", "status list: decoded list is too large")
    if not inflater.eof:
        raise PlugError("proof_invalid", "status list: lst is truncated")
    return bits, array


def status_at(bits: int, array: bytes, idx: int) -> int:
    """Status value at idx; blocks of `bits` are packed from the least significant bit of each byte."""
    if isinstance(idx, bool) or not isinstance(idx, int) or idx < 0:
        raise PlugError("proof_invalid", "status list: idx must be a non-negative integer")
    position = idx * bits
    if position // 8 >= len(array):
        raise PlugError("proof_invalid", "status list: idx is out of range")
    return (array[position // 8] >> (position % 8)) & ((1 << bits) - 1)


def parse_status_list_token(token: str) -> tuple[dict, dict, bytes, bytes]:
    """(header, claims, signing input, signature) of a compact JWS. Structure only; the signature is checked later."""
    parts = token.strip().split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise PlugError("proof_invalid", "status list: not a compact JWT")
    try:
        header, claims = json.loads(_b64url(parts[0])), json.loads(_b64url(parts[1]))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise PlugError("proof_invalid", f"status list: bad JWT JSON: {e}") from e
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise PlugError("proof_invalid", "status list: bad JWT JSON")
    return header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), _b64url(parts[2])


def _expired(claims: dict, now: float) -> bool:
    exp = claims.get("exp")
    return isinstance(exp, (int, float)) and not isinstance(exp, bool) and now >= exp


class EudiAdapter(InMemoryAdapter):
    """EUDI-compliant adapter over the standard eight ops.

    Parameters
    ----------
    trusted_lists : list of trusted-list URLs, each a registry document {"issuers": [...], "keys": {...}}
    status_list_poll : most seconds a fetched Status List Token is reused (a shorter token ttl wins)
    status_list_max_stale : most seconds a cached token stands in while a fresh one cannot be fetched or
               verified (a shorter token ttl wins); never past the token's exp
    credential_formats : accepted formats (sd-jwt-vc, mso-mdoc)

    A credential that references a status list carries meta {"status": {"status_list": {"idx", "uri"}}}
    (IETF Token Status List). The Status List Token must be a statuslist+jwt signed with ES256 or EdDSA by
    a key of the attestation's issuer: its did:key, or a key the trust registry lists for it. The status list
    is fetched only after the credential's own signature verifies, and a token older than one already seen
    is refused.
    """

    tx_prefix = "eudi"
    did_prefix = "did:eudi"

    def __init__(self, trusted_lists: Optional[list[str]] = None,
                 status_list_poll: int = _DEFAULT_STATUS_LIST_POLL,
                 credential_formats: Optional[list[str]] = None,
                 status_list_max_stale: int = _DEFAULT_STATUS_LIST_MAX_STALE):
        super().__init__()
        self.trusted_lists = trusted_lists or []
        self.status_list_poll = status_list_poll
        self.status_list_max_stale = status_list_max_stale
        self.credential_formats = credential_formats or ["sd-jwt-vc", "mso-mdoc"]
        self._status_tokens: dict[str, tuple] = {}  # uri -> (parsed token, fetched at)

    def attest(self, network: Optional[str], att: Attestation) -> Receipt:
        fmt = att.meta.get("credential_format")
        if fmt and fmt not in self.credential_formats:
            raise PlugError("unsupported_op", f"credential format {fmt} not accepted")
        return super().attest(network, att)

    @staticmethod
    def _within(claims: dict, age: float, limit: float, now: float) -> bool:
        ttl = claims.get("ttl")
        if isinstance(ttl, (int, float)) and not isinstance(ttl, bool) and ttl > 0:
            limit = min(limit, ttl)
        return age < limit and not _expired(claims, now)

    def _status_list(self, uri: str, att: Attestation, data: dict) -> dict:
        """Claims of a verified Status List Token for this credential. FAIL-CLOSED: a fresh verified token,
        else a cached verified one within ttl and status_list_max_stale and before exp, else raise."""
        now = time.time()
        cached = self._status_tokens.get(uri)
        if cached and self._within(cached[0][1], now - cached[1], self.status_list_poll, now):
            return self._validated(cached[0], uri, att, data, now)
        try:
            try:
                raw = fetch_document(uri, accept="application/statuslist+jwt", max_bytes=_STATUS_LIST_MAX_BYTES,
                                     what="status list")
            except PlugError as e:
                raise PlugError(e.code, f"status list unreachable: {e.message}") from e
            parsed = parse_status_list_token(raw.decode("ascii", "replace"))
            claims = self._validated(parsed, uri, att, data, now)
            if cached and claims["iat"] < cached[0][1]["iat"]:
                raise PlugError("proof_invalid", "status list token is older than one already seen")
        except PlugError:
            if cached and self._within(cached[0][1], now - cached[1], self.status_list_max_stale, now):
                return self._validated(cached[0], uri, att, data, now)
            raise
        self._status_tokens[uri] = (parsed, now)
        return claims

    @staticmethod
    def _validated(parsed: tuple, uri: str, att: Attestation, data: dict, now: float) -> dict:
        """The token's claims once its type, subject, times, and issuer signature hold; else raise."""
        header, claims, signing_input, signature = parsed
        if header.get("typ") != "statuslist+jwt":
            raise PlugError("proof_invalid", "status list token typ is not statuslist+jwt")
        if claims.get("sub") != uri:
            raise PlugError("proof_invalid", "status list token sub does not match the reference uri")
        if not isinstance(claims.get("iat"), (int, float)) or isinstance(claims.get("iat"), bool):
            raise PlugError("proof_invalid", "status list token has no iat")
        if _expired(claims, now):
            raise PlugError("proof_invalid", "status list token expired")
        from ..suites import issuer_key, verify_jws
        listed = (((data.get("trust_registry") or {}).get("keys") or {}).get(att.issuer)) or []
        keys = [e["verification_method"] for e in listed]
        own = issuer_key(att.issuer)
        if own and own.startswith("did:key:"):
            keys.append(own)
        kid = header.get("kid")
        named = [k for k in keys if kid in (k, k.split("#", 1)[0])]
        signer = next((k for k in (named or keys)
                       if verify_jws(signing_input, signature, header.get("alg", ""), k)), None)
        if signer is None:
            raise PlugError("proof_invalid", "status list token is not signed by a key of the issuer")
        _, err = registry_key_status(data, att.issuer, signer, datetime.fromtimestamp(now, timezone.utc))
        if err:
            raise PlugError("proof_invalid", f"{err.removeprefix('proof_invalid: ')} (status list token)")
        return claims

    @staticmethod
    def _status_reference(att: Attestation) -> Optional[tuple[int, str]]:
        if {"status_list_url", "status_list_index"} & set(att.meta):
            raise PlugError("proof_invalid", "status list reference must be meta.status.status_list {idx, uri}")
        status = att.meta.get("status")
        if status is None:
            return None
        try:
            ref = status["status_list"]
            idx, uri = ref["idx"], ref["uri"]
        except (KeyError, TypeError) as e:
            raise PlugError("proof_invalid", "status list reference must be meta.status.status_list {idx, uri}") from e
        if isinstance(idx, bool) or not isinstance(idx, int) or idx < 0 or not isinstance(uri, str):
            raise PlugError("proof_invalid", "status list: idx must be a non-negative integer and uri a string")
        return idx, uri

    def _status_error(self, att: Attestation, data: dict) -> Optional[str]:
        """None when the credential has no status reference or its status is VALID (0x00)."""
        try:
            ref = self._status_reference(att)
            if ref is None:
                return None
            idx, uri = ref
            claims = self._status_list(uri, att, data)
            bits, array = decode_status_list(claims.get("status_list"))
            value = status_at(bits, array, idx)
        except PlugError as e:
            return f"{e.code}: {e.message}"
        if value == 0:
            return None
        return f"proof_invalid: {_STATUS_NAMES.get(value, f'status 0x{value:02x}')} via status list"

    def verify(self, att: Attestation, network: str, trust_registry=None) -> Receipt:
        net = network or "default"
        # EUDI: resolve ETSI trusted lists first if configured and no explicit registry
        if self.trusted_lists and not trust_registry:
            all_issuers: list = []
            all_keys: dict[str, list] = {}
            for url in self.trusted_lists:
                try:
                    doc = fetch_registry(url)
                    all_issuers.extend(doc["issuers"])
                    for did, entries in doc.get("keys", {}).items():
                        all_keys.setdefault(did, []).extend(entries)
                except PlugError as e:
                    return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net,
                                   error=f"{e.code}: trusted list {url}: {e.message}")
            if all_issuers:
                trust_registry = {"issuers": list(dict.fromkeys(all_issuers)),
                                  **({"keys": all_keys} if all_keys else {})}
        trust = resolve_trust_registry(self.query, trust_registry, net, att.issuer)
        if isinstance(trust, Receipt):
            return trust
        data = dict(trust or {})
        err = anchor_error(self._store, net, att)
        if err:
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=data, error=err)
        # The credential's own signature first: an unverified attestation never makes the adapter fetch.
        signed = check_signature(att, net, data)
        if signed.status != Status.OK:
            return signed
        err = self._status_error(att, signed.data)
        if err:
            rejected = dict(signed.data, verified=False)
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, net, data=rejected, error=err)
        return signed
