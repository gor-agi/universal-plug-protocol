# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Signature suites and DID key binding. Algorithm agility lives here, not in the core ops.

Every suite signs the same message, the 32-byte subject hash, applying its own standard:

- ecdsa-secp256k1  ECDSA with the subject hash as the digest (Ethereum-compatible).
                   verification_method: 0x account address.
- ed25519          PureEdDSA, RFC 8032. verification_method: did:key.
- ecdsa-p256       ECDSA P-256 with SHA-256 (ES256), deterministic per RFC 6979.
                   sig is r||s. verification_method: did:key.
- sm2-sm3          SM2 with SM3 and the default distinguishing ID 1234567812345678
                   (GB/T 32918.2, GM/T 0009). sig is r||s. verification_method: did:key.

Each suite needs its optional library: eth-account (secp256k1), pycryptodome
(ed25519, P-256), gmssl (SM2 curve arithmetic). A missing library raises
unsupported_op; nothing is emulated.
"""
from __future__ import annotations
import re
import secrets
from typing import Optional

from .core import PlugError, digest  # noqa: F401  (digest re-exported)

SUITES = ("ecdsa-secp256k1", "ed25519", "ecdsa-p256", "sm2-sm3")

# did:plug and did:pkh account identifiers; network is CAIP-2, account is CAIP-10 (spec/did-plug.md).
_ACCOUNT_DID = re.compile(
    r"^did:(?P<method>plug|pkh):"
    r"(?:(?P<ns>[-a-z0-9]{3,8}):(?P<ref>[-_a-zA-Z0-9]{1,32})|(?P<alias>[-a-z0-9]{1,32})):"
    r"(?P<account>[-.%a-zA-Z0-9]{1,128})$")

# multicodec public-key codes (github.com/multiformats/multicodec, table.csv)
_MULTICODEC = {"ed25519": 0xED, "ecdsa-p256": 0x1200, "sm2-sm3": 0x1206}
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_SM2_ID = b"1234567812345678"


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def _b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        if ch not in _B58:
            raise ValueError("not base58btc")
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte, n = n & 0x7F, n >> 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def did_key(alg: str, public_key: bytes) -> str:
    """did:key for a raw Ed25519 key or a compressed SEC1 point."""
    return "did:key:z" + _b58encode(_varint(_MULTICODEC[alg]) + public_key)


def parse_did_key(did: str) -> tuple[str, bytes]:
    """Return (suite, public key bytes) for a did:key, ignoring any #fragment."""
    base = (did or "").split("#", 1)[0]
    if not base.startswith("did:key:z"):
        raise ValueError("not a did:key")
    raw = _b58decode(base[len("did:key:z"):])
    for alg, code in _MULTICODEC.items():
        prefix = _varint(code)
        if raw.startswith(prefix):
            return alg, raw[len(prefix):]
    raise ValueError("unsupported did:key multicodec")


def _message(subject_hash: str) -> bytes:
    try:
        msg = bytes.fromhex(subject_hash)
    except (TypeError, ValueError) as e:
        raise PlugError("proof_invalid", f"subject_hash is not hex: {e}") from e
    if len(msg) != 32:
        raise PlugError("proof_invalid", "subject_hash must be 32 bytes")
    return msg


def _require(module: str, suite: str):
    try:
        return __import__(module, fromlist=["_"])
    except ImportError as e:
        raise PlugError("unsupported_op", f"{suite} needs the {module.split('.')[0]} package") from e


# ---- secp256k1 (Ethereum) ----

def _k1_sign(key: str, msg: bytes) -> tuple[bytes, str]:
    Account = _require("eth_account", "ecdsa-secp256k1").Account
    signed = Account.unsafe_sign_hash(msg, key)
    return bytes(signed.signature), Account.from_key(key).address


def _k1_verify(msg: bytes, sig: bytes, method: str) -> tuple[bool, str]:
    keys = _require("eth_keys", "ecdsa-secp256k1").keys
    to_checksum = _require("eth_utils", "ecdsa-secp256k1").to_checksum_address
    if len(sig) != 65:
        return False, "proof_invalid: bad signature length"
    if sig[64] in (27, 28):
        sig = sig[:64] + bytes([sig[64] - 27])
    try:
        recovered = keys.Signature(sig).recover_public_key_from_msg_hash(msg).to_checksum_address()
        expected = to_checksum(method)
    except Exception as e:
        return False, f"proof_invalid: {e}"
    return recovered == expected, recovered


# ---- Ed25519 and P-256 (pycryptodome) ----

def _ed_sign(key: str, msg: bytes) -> tuple[bytes, bytes]:
    ECC = _require("Crypto.PublicKey.ECC", "ed25519")
    eddsa = _require("Crypto.Signature.eddsa", "ed25519")
    k = ECC.construct(curve="ed25519", seed=bytes.fromhex(key.removeprefix("0x")))
    return eddsa.new(k, "rfc8032").sign(msg), k.public_key().export_key(format="raw")


def _ed_verify(msg: bytes, sig: bytes, public: bytes) -> bool:
    eddsa = _require("Crypto.Signature.eddsa", "ed25519")
    try:
        eddsa.new(eddsa.import_public_key(public), "rfc8032").verify(msg, sig)
        return True
    except ValueError:
        return False


def _p256_sign(key: str, msg: bytes) -> tuple[bytes, bytes]:
    ECC = _require("Crypto.PublicKey.ECC", "ecdsa-p256")
    DSS = _require("Crypto.Signature.DSS", "ecdsa-p256")
    SHA256 = _require("Crypto.Hash.SHA256", "ecdsa-p256")
    k = ECC.construct(curve="P-256", d=int(key.removeprefix("0x"), 16))
    sig = DSS.new(k, "deterministic-rfc6979", encoding="binary").sign(SHA256.new(msg))
    return sig, k.public_key().export_key(format="SEC1", compress=True)


def _p256_verify(msg: bytes, sig: bytes, public: bytes) -> bool:
    ECC = _require("Crypto.PublicKey.ECC", "ecdsa-p256")
    DSS = _require("Crypto.Signature.DSS", "ecdsa-p256")
    SHA256 = _require("Crypto.Hash.SHA256", "ecdsa-p256")
    try:
        pub = ECC.import_key(public, curve_name="P-256")
        DSS.new(pub, "fips-186-3", encoding="binary").verify(SHA256.new(msg), sig)
        return True
    except ValueError:
        return False


# ---- SM2 (gmssl curve arithmetic; nonce and range checks here) ----

def _sm2():
    sm2 = _require("gmssl.sm2", "sm2-sm3")
    t = sm2.default_ecc_table
    return sm2, int(t["n"], 16), int(t["p"], 16), int(t["a"], 16), int(t["b"], 16)


def _sm2_engine(private_hex: Optional[str], public_xy: str):
    sm2, *_ = _sm2()
    engine = sm2.CryptSM2(private_key=private_hex, public_key="")
    engine.public_key = public_xy  # gmssl's constructor lstrip("04")s keys that begin with 0 or 4
    return engine


def _sm2_e(engine, msg: bytes) -> bytes:
    """e = SM3(Z_A || M) with Z_A over the default distinguishing ID."""
    sm2, n, p, a, b = _sm2()
    t = sm2.default_ecc_table
    za = bytes.fromhex(digest((len(_SM2_ID) * 8).to_bytes(2, "big") + _SM2_ID + bytes.fromhex(
        t["a"] + t["b"] + t["g"] + engine.public_key), "sm3"))
    return bytes.fromhex(digest(za + msg, "sm3"))


def _sm2_decompress(point: bytes) -> str:
    _, n, p, a, b = _sm2()
    if len(point) != 33 or point[0] not in (2, 3):
        raise ValueError("SM2 key must be a compressed SEC1 point")
    x = int.from_bytes(point[1:], "big")
    rhs = (pow(x, 3, p) + a * x + b) % p
    y = pow(rhs, (p + 1) // 4, p)
    if y * y % p != rhs:
        raise ValueError("point is not on the SM2 curve")
    if y % 2 != point[0] % 2:
        y = p - y
    return f"{x:064x}{y:064x}"


def _sm2_sign(key: str, msg: bytes) -> tuple[bytes, bytes]:
    sm2, n, *_ = _sm2()
    d = int(key.removeprefix("0x"), 16)
    if not 1 <= d <= n - 2:
        raise PlugError("auth_failed", "SM2 private key out of range")
    engine = _sm2_engine(f"{d:064x}", "")
    xy = engine._kg(d, sm2.default_ecc_table["g"])
    engine.public_key = xy
    e = _sm2_e(engine, msg)
    while True:
        sig = engine.sign(e, f"{secrets.randbelow(n - 1) + 1:064x}")  # CSPRNG nonce; gmssl's own uses random
        if sig:
            break
    y = int(xy[64:], 16)
    return bytes.fromhex(sig), bytes([2 + (y & 1)]) + bytes.fromhex(xy[:64])


def _sm2_verify(msg: bytes, sig: bytes, public: bytes) -> bool:
    _, n, *_ = _sm2()
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < n and 1 <= s < n):
        return False
    try:
        engine = _sm2_engine(None, _sm2_decompress(public))
    except ValueError:
        return False
    return bool(engine.verify(sig.hex(), _sm2_e(engine, msg)))


# ---- public API ----

def generate_key(alg: str) -> str:
    """A fresh private key (hex) for a suite."""
    if alg == "ecdsa-secp256k1":
        return _require("eth_account", alg).Account.create().key.hex()
    if alg == "ed25519":
        return secrets.token_bytes(32).hex()
    if alg == "ecdsa-p256":
        return f"{int(_require('Crypto.PublicKey.ECC', alg).generate(curve='P-256').d):064x}"
    if alg == "sm2-sm3":
        _, n, *_ = _sm2()
        return f"{secrets.randbelow(n - 2) + 1:064x}"
    raise PlugError("unsupported_op", f"signature suite {alg}")


def sign(alg: str, private_key: str, subject_hash: str) -> dict:
    """Proof {alg, sig, verification_method} over the 32-byte subject hash."""
    msg = _message(subject_hash)
    if alg == "ecdsa-secp256k1":
        sig, method = _k1_sign(private_key, msg)
        return {"alg": alg, "sig": "0x" + sig.hex(), "verification_method": method}
    signer = {"ed25519": _ed_sign, "ecdsa-p256": _p256_sign, "sm2-sm3": _sm2_sign}.get(alg)
    if signer is None:
        raise PlugError("unsupported_op", f"signature suite {alg}")
    sig, public = signer(private_key, msg)
    return {"alg": alg, "sig": "0x" + sig.hex(), "verification_method": did_key(alg, public)}


def verify(subject_hash: str, proof: dict) -> tuple[bool, str]:
    """(True, verification_method) or (False, reason). Never raises for a malformed proof."""
    alg = (proof or {}).get("alg", "")
    method = (proof or {}).get("verification_method") or ""
    if not method:
        return False, "proof_invalid: missing verification_method"
    try:
        msg = _message(subject_hash)
        sig = bytes.fromhex(str(proof.get("sig", "")).removeprefix("0x"))
    except (PlugError, ValueError) as e:
        return False, f"proof_invalid: {getattr(e, 'message', e)}"
    if alg == "ecdsa-secp256k1":
        try:
            ok, detail = _k1_verify(msg, sig, method)
        except PlugError as e:
            return False, f"{e.code}: {e.message}"
        return (ok, detail) if ok or detail.startswith("proof_invalid") else (False, "proof_invalid: signer mismatch")
    checker = {"ed25519": _ed_verify, "ecdsa-p256": _p256_verify, "sm2-sm3": _sm2_verify}.get(alg)
    if checker is None:
        return False, "proof_invalid: unsupported alg"
    try:
        key_alg, public = parse_did_key(method)
    except ValueError as e:
        return False, f"proof_invalid: {e}"
    if key_alg != alg:
        return False, "proof_invalid: verification_method key type does not match alg"
    try:
        good = checker(msg, sig, public)
    except PlugError as e:
        return False, f"{e.code}: {e.message}"
    return (True, method.split("#", 1)[0]) if good else (False, "proof_invalid: bad signature")


# JOSE algorithms for JWS made by did:key holders (RFC 7518 ES256, RFC 8037 EdDSA).
_JOSE = {"ES256": ("ecdsa-p256", _p256_verify), "EdDSA": ("ed25519", _ed_verify)}


def verify_jws(signing_input: bytes, signature: bytes, jose_alg: str, method: str) -> bool:
    """True when a JWS signature over signing_input verifies under the did:key `method`."""
    suite = _JOSE.get(jose_alg)
    if suite is None:
        return False
    try:
        key_alg, public = parse_did_key(method)
    except ValueError:
        return False
    return key_alg == suite[0] and suite[1](signing_input, signature, public)


def parse_account_did(did: str) -> Optional[tuple[str, str]]:
    """(network, account) for did:plug or did:pkh. network is a CAIP-2 chain ID, or a deployment-local alias."""
    m = _ACCOUNT_DID.match((did or "").split("#", 1)[0])
    if not m or (m["method"] == "pkh" and m["alias"]):
        return None
    return (m["alias"] or f"{m['ns']}:{m['ref']}"), m["account"]


def issuer_key(did: str) -> Optional[str]:
    """The verification method an issuer DID controls, when the DID itself names it; else None."""
    base = (did or "").split("#", 1)[0]
    if base.startswith("did:key:"):
        return base
    parsed = parse_account_did(base)
    if parsed is None:
        return None
    account = parsed[1]
    return account.lower() if account.lower().startswith("0x") else account


def binds(issuer: str, verification_method: str) -> bool:
    """True when the issuer DID names exactly the key that verified the proof."""
    named = issuer_key(issuer)
    method = (verification_method or "").split("#", 1)[0]
    return named is not None and named == (method.lower() if method.startswith("0x") else method)
