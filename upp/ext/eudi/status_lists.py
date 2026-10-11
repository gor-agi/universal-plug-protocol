# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""IETF Token Status Lists (draft-ietf-oauth-status-list): is a credential revoked or suspended right now?

Fail closed: a status is known only from a Status List Token signed by one of the keys the caller names, fresh by
its signed iat and ttl, and never older than a token already seen for the same list.
"""
from __future__ import annotations
import base64
import json
import time
import zlib

from ...core import PlugError
from ...registry import fetch_document

_DEFAULT_STATUS_LIST_POLL = 300  # 5 minutes
_DEFAULT_STATUS_LIST_MAX_STALE = 3600  # longest a cached token stands in while the list cannot be fetched
_DEFAULT_STATUS_LIST_MAX_AGE = 86400   # oldest signed iat accepted when the token names no ttl
_CLOCK_SKEW = 300
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


class StatusLists:
    """A cache of verified Status List Tokens.

    poll: most seconds a fetched token is reused (a shorter token ttl wins).
    max_stale: most seconds a cached token stands in while a fresh one cannot be fetched or verified (never past
    its exp). max_age: oldest a token's signed iat may be; with a ttl, also refused once iat is older than
    ttl + max_stale. Fetching follows the allow_hosts policy (closed by default).
    """

    def __init__(self, poll: int = _DEFAULT_STATUS_LIST_POLL, max_stale: int = _DEFAULT_STATUS_LIST_MAX_STALE,
                 max_age: int = _DEFAULT_STATUS_LIST_MAX_AGE):
        self.poll, self.max_stale, self.max_age = poll, max_stale, max_age
        self._tokens: dict[str, tuple] = {}  # uri -> (parsed token, fetched at)

    @staticmethod
    def _within(claims: dict, age: float, limit: float, now: float) -> bool:
        ttl = claims.get("ttl")
        if isinstance(ttl, (int, float)) and not isinstance(ttl, bool) and ttl > 0:
            limit = min(limit, ttl)
        return age < limit and not _expired(claims, now)

    def _token(self, uri: str, keys: list, now: float) -> dict:
        cached = self._tokens.get(uri)
        if cached and self._within(cached[0][1], now - cached[1], self.poll, now):
            return self._validated(cached[0], uri, keys, now)
        try:
            try:
                raw = fetch_document(uri, accept="application/statuslist+jwt", max_bytes=_STATUS_LIST_MAX_BYTES,
                                     what="status list")
            except PlugError as e:
                raise PlugError(e.code, f"status list unreachable: {e.message}") from e
            parsed = parse_status_list_token(raw.decode("ascii", "replace"))
            claims = self._validated(parsed, uri, keys, now)
            if cached and claims["iat"] < cached[0][1]["iat"]:
                raise PlugError("proof_invalid", "status list token is older than one already seen")
        except PlugError:
            if cached and self._within(cached[0][1], now - cached[1], self.max_stale, now):
                return self._validated(cached[0], uri, keys, now)
            raise
        self._tokens[uri] = (parsed, now)
        return claims

    def _validated(self, parsed: tuple, uri: str, keys: list, now: float) -> dict:
        from ...suites import verify_jws
        header, claims, signing_input, signature = parsed
        if header.get("typ") != "statuslist+jwt":
            raise PlugError("proof_invalid", "status list token typ is not statuslist+jwt")
        if claims.get("sub") != uri:
            raise PlugError("proof_invalid", "status list token sub does not match the reference uri")
        iat = claims.get("iat")
        if not isinstance(iat, (int, float)) or isinstance(iat, bool):
            raise PlugError("proof_invalid", "status list token has no iat")
        if _expired(claims, now):
            raise PlugError("proof_invalid", "status list token expired")
        if iat > now + _CLOCK_SKEW:
            raise PlugError("proof_invalid", "status list token iat is in the future")
        ttl = claims.get("ttl")
        limit = self.max_age
        if isinstance(ttl, (int, float)) and not isinstance(ttl, bool) and ttl > 0:
            limit = min(limit, ttl + self.max_stale)
        if now - iat > limit:
            raise PlugError("proof_invalid", "status list token is too old")
        if not any(verify_jws(signing_input, signature, header.get("alg", ""), k) for k in keys):
            raise PlugError("proof_invalid", "status list token is not signed by a key of the issuer")
        return claims

    def status(self, reference: dict, keys: list) -> int:
        """The status value for a credential's `status` claim ({"status_list": {"idx", "uri"}}), from a token
        signed by one of `keys` (did:key verification methods). 0 is VALID. Raises when it cannot be known."""
        try:
            ref = reference["status_list"]
            idx, uri = ref["idx"], ref["uri"]
        except (KeyError, TypeError) as e:
            raise PlugError("proof_invalid", "status reference must be {status_list: {idx, uri}}") from e
        if isinstance(idx, bool) or not isinstance(idx, int) or idx < 0 or not isinstance(uri, str):
            raise PlugError("proof_invalid", "status list: idx must be a non-negative integer and uri a string")
        claims = self._token(uri, list(keys), time.time())
        bits, array = decode_status_list(claims.get("status_list"))
        return status_at(bits, array, idx)

    def check(self, reference: dict, keys: list) -> None:
        """Raise unless the status is VALID."""
        value = self.status(reference, keys)
        if value:
            raise PlugError("proof_invalid", f"{_STATUS_NAMES.get(value, f'status 0x{value:02x}')} via status list")
