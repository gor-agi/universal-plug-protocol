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

Each suite needs its optional library: eth-account (secp256k1), cryptography
(ed25519, P-256; OpenSSL-backed), gmssl (SM2 curve arithmetic). A missing library raises
unsupported_op; nothing is emulated.
"""
from __future__ import annotations
import hashlib
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


_KEY_LENGTH = {"ed25519": 32, "ecdsa-p256": 33, "sm2-sm3": 33}


def parse_did_key(did: str) -> tuple[str, bytes]:
    """Return (suite, public key bytes) for a did:key, ignoring any #fragment.

    Only the canonical form is accepted: a raw 32-byte Ed25519 key or a 33-byte compressed SEC1 point,
    encoded so that re-encoding yields the same identifier. One key therefore has exactly one did:key.
    """
    base = (did or "").split("#", 1)[0]
    if not base.startswith("did:key:z"):
        raise ValueError("not a did:key")
    raw = _b58decode(base[len("did:key:z"):])
    for alg, code in _MULTICODEC.items():
        prefix = _varint(code)
        if raw.startswith(prefix):
            public = raw[len(prefix):]
            if len(public) != _KEY_LENGTH[alg] or (alg != "ed25519" and public[0] not in (2, 3)):
                raise ValueError(f"{alg} did:key must carry a {_KEY_LENGTH[alg]}-byte "
                                 + ("raw key" if alg == "ed25519" else "compressed point"))
            if did_key(alg, public) != base:
                raise ValueError("did:key is not canonically encoded")
            return alg, public
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


# ---- Ed25519 and P-256 (pyca/cryptography, OpenSSL-backed) ----

def _ec():
    hazmat = _require("cryptography.hazmat.primitives.asymmetric.ec", "ecdsa-p256")
    return hazmat, _require("cryptography.hazmat.primitives.hashes", "ecdsa-p256")


def _ed_sign(key: str, msg: bytes) -> tuple[bytes, bytes]:
    ed = _require("cryptography.hazmat.primitives.asymmetric.ed25519", "ed25519")
    ser = _require("cryptography.hazmat.primitives.serialization", "ed25519")
    k = ed.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key.removeprefix("0x")))
    return k.sign(msg), k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


_ED_P = 2**255 - 19
_ED_D = -121665 * pow(121666, -1, _ED_P) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)  # sqrt(-1)


def _ed_small_order_or_invalid(public: bytes) -> bool:
    """True unless `public` canonically encodes an Ed25519 point outside the small-order subgroup (RFC 8032 5.1.3)."""
    if len(public) != 32:
        return True
    y = int.from_bytes(public, "little") & ((1 << 255) - 1)
    sign = public[31] >> 7
    if y >= _ED_P:
        return True
    u, v = (y * y - 1) % _ED_P, (_ED_D * y * y + 1) % _ED_P
    x = (u * pow(v, 3, _ED_P) * pow(u * pow(v, 7, _ED_P), (_ED_P - 5) // 8, _ED_P)) % _ED_P
    if (v * x * x - u) % _ED_P:
        x = x * _ED_I % _ED_P
        if (v * x * x - u) % _ED_P:
            return True
    if x == 0 and sign:
        return True
    if x & 1 != sign:
        x = _ED_P - x
    X, Y, Z = x, y, 1
    for _ in range(3):  # [8]P in extended coordinates (dbl-2008-hwcd)
        A, B, C = X * X % _ED_P, Y * Y % _ED_P, 2 * Z * Z % _ED_P
        H = (A + B) % _ED_P
        E = (H - (X + Y) * (X + Y)) % _ED_P
        G = (A - B) % _ED_P
        F = (C + G) % _ED_P
        X, Y, Z = E * F % _ED_P, G * H % _ED_P, F * G % _ED_P
    return X % _ED_P == 0 and (Y - Z) % _ED_P == 0


def _ed_verify(msg: bytes, sig: bytes, public: bytes) -> bool:
    ed = _require("cryptography.hazmat.primitives.asymmetric.ed25519", "ed25519")
    exceptions = _require("cryptography.exceptions", "ed25519")
    if _ed_small_order_or_invalid(public):
        return False
    try:
        ed.Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
        return True
    except (ValueError, exceptions.InvalidSignature):
        return False


def _p256_sign(key: str, msg: bytes) -> tuple[bytes, bytes]:
    ec, hashes = _ec()
    ser = _require("cryptography.hazmat.primitives.serialization", "ecdsa-p256")
    utils = _require("cryptography.hazmat.primitives.asymmetric.utils", "ecdsa-p256")
    k = ec.derive_private_key(int(key.removeprefix("0x"), 16), ec.SECP256R1())
    r, s = utils.decode_dss_signature(k.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    public = k.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.CompressedPoint)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big"), public


def _p256_verify(msg: bytes, sig: bytes, public: bytes) -> bool:
    ec, hashes = _ec()
    utils = _require("cryptography.hazmat.primitives.asymmetric.utils", "ecdsa-p256")
    exceptions = _require("cryptography.exceptions", "ecdsa-p256")
    if len(sig) != 64 or len(public) != 33 or public[0] not in (2, 3):
        return False
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)  # validates the point
        der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, exceptions.InvalidSignature):
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
    if x >= p:
        raise ValueError("SM2 point x is not a field element")
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
        ec, _ = _ec()
        return f"{ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value:064x}"
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


# JOSE algorithms for JWS made by did:key holders: ES256 (RFC 7518), Ed25519 (RFC 9864, fully specified)
# and EdDSA (RFC 8037, deprecated by RFC 9864 but still issued).
_JOSE = {"ES256": ("ecdsa-p256", _p256_verify), "Ed25519": ("ed25519", _ed_verify),
         "EdDSA": ("ed25519", _ed_verify)}


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


# ---- signers: where a private key lives ----

class KeySigner:
    """Signs with a private key held in this process (development, tests, low-risk deployments)."""

    def __init__(self, alg: str, private_key: str):
        self.alg, self._key = alg, private_key
        self.verification_method = sign(alg, private_key, "00" * 32)["verification_method"]

    def sign(self, message: bytes) -> dict:
        return sign(self.alg, self._key, message.hex())


class Pkcs11Signer:
    """Signs with a key that never leaves a PKCS#11 token (an HSM, or SoftHSM in development).

    Supports ecdsa-p256 (CKM_ECDSA over SHA-256 of the 32-byte message) and ed25519 (CKM_EDDSA, PureEdDSA).
    The token holds a key pair under key_label; its public key gives the did:key verification method.
    """

    _ALGS = ("ecdsa-p256", "ed25519")

    def __init__(self, library: str, token_label: str, pin: str, key_label: str, alg: str):
        pkcs11 = _require("pkcs11", alg)
        if alg not in self._ALGS:
            raise PlugError("unsupported_op", f"PKCS#11 signing supports {', '.join(self._ALGS)}")
        self.alg = alg
        token = pkcs11.lib(library).get_token(token_label=token_label)
        self._session = token.open(user_pin=pin)
        self._key = self._session.get_key(object_class=pkcs11.ObjectClass.PRIVATE_KEY, label=key_label)
        point = self._session.get_key(object_class=pkcs11.ObjectClass.PUBLIC_KEY, label=key_label)[
            pkcs11.Attribute.EC_POINT]
        raw = _der_octet_string(point)
        if alg == "ecdsa-p256":
            ec, _ = _ec()
            ser = _require("cryptography.hazmat.primitives.serialization", alg)
            raw = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw).public_bytes(
                ser.Encoding.X962, ser.PublicFormat.CompressedPoint)
        self.verification_method = did_key(alg, raw)
        self._mechanism = pkcs11.Mechanism.ECDSA if alg == "ecdsa-p256" else pkcs11.Mechanism.EDDSA

    def sign(self, message: bytes) -> dict:
        _message(message.hex())
        data = hashlib.sha256(message).digest() if self.alg == "ecdsa-p256" else message
        sig = self._key.sign(data, mechanism=self._mechanism)
        return {"alg": self.alg, "sig": "0x" + bytes(sig).hex(), "verification_method": self.verification_method}

    def close(self) -> None:
        self._session.close()


def _der_octet_string(value: bytes) -> bytes:
    """CKA_EC_POINT is a DER OCTET STRING around the encoded point (some tokens omit the wrapper)."""
    value = bytes(value)
    if len(value) > 2 and value[0] == 0x04 and value[1] == len(value) - 2 and value[1] < 0x80:
        return value[2:]
    if len(value) > 3 and value[0] == 0x04 and value[1] == 0x81 and value[2] == len(value) - 3:
        return value[3:]
    return value


def sign_attestation(signer, att) -> dict:
    """Sign an attestation's statement with any signer (KeySigner, Pkcs11Signer) and set its proof."""
    from .core import statement_hash
    att.proof = signer.sign(bytes.fromhex(statement_hash(att)))
    return att.proof


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
