# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Signature suites, cross-checked against OpenSSL 3 where it is installed."""
import os
import shutil
import subprocess
import tempfile

import pytest

from upp import suites
from upp.core import PlugError, sha256_hex

pytest.importorskip("cryptography")

SUBJECT = sha256_hex(b"bill of lading 2026-0042")


def available(alg):
    try:
        suites.sign(alg, suites.generate_key(alg), SUBJECT)
        return True
    except PlugError:
        return False


@pytest.mark.parametrize("alg", suites.SUITES)
def test_sign_verify_and_tamper(alg):
    if not available(alg):
        pytest.skip(f"{alg} library not installed")
    key, other = suites.generate_key(alg), suites.generate_key(alg)
    proof = suites.sign(alg, key, SUBJECT)
    ok, method = suites.verify(SUBJECT, proof)
    assert ok and method == proof["verification_method"]
    assert suites.binds(f"did:pkh:eip155:1:{method}" if method.startswith("0x") else method, method)
    assert suites.verify(sha256_hex(b"other"), proof)[0] is False
    flipped = bytearray(bytes.fromhex(proof["sig"][2:]))
    flipped[5] ^= 1
    assert suites.verify(SUBJECT, dict(proof, sig="0x" + flipped.hex()))[0] is False
    foreign = suites.sign(alg, other, SUBJECT)["verification_method"]
    assert suites.verify(SUBJECT, dict(proof, verification_method=foreign))[0] is False


def test_did_key_prefixes_match_multicodec_registry():
    if not available("ed25519"):
        pytest.skip("cryptography missing")
    ed = suites.sign("ed25519", suites.generate_key("ed25519"), SUBJECT)["verification_method"]
    p256 = suites.sign("ecdsa-p256", suites.generate_key("ecdsa-p256"), SUBJECT)["verification_method"]
    assert ed.startswith("did:key:z6Mk") and p256.startswith("did:key:zDn")
    assert suites.parse_did_key(ed)[0] == "ed25519" and len(suites.parse_did_key(ed)[1]) == 32
    assert suites.parse_did_key(p256 + "#key-1")[0] == "ecdsa-p256"


def test_key_type_must_match_alg():
    if not available("ed25519"):
        pytest.skip("cryptography missing")
    proof = suites.sign("ed25519", suites.generate_key("ed25519"), SUBJECT)
    ok, reason = suites.verify(SUBJECT, dict(proof, alg="ecdsa-p256"))
    assert not ok and "does not match alg" in reason


def test_sm2_nonces_are_fresh_and_range_checked():
    if not available("sm2-sm3"):
        pytest.skip("gmssl missing")
    key = suites.generate_key("sm2-sm3")
    a, b = suites.sign("sm2-sm3", key, SUBJECT), suites.sign("sm2-sm3", key, SUBJECT)
    assert a["sig"] != b["sig"] and suites.verify(SUBJECT, a)[0] and suites.verify(SUBJECT, b)[0]
    _, n, *_ = suites._sm2()
    zero_r = "0x" + "00" * 32 + a["sig"][66:]
    big_s = "0x" + a["sig"][2:66] + f"{n:064x}"
    assert suites.verify(SUBJECT, dict(a, sig=zero_r))[0] is False
    assert suites.verify(SUBJECT, dict(a, sig=big_s))[0] is False


def test_sm2_keys_with_leading_0_or_4_survive():
    """gmssl's constructor lstrip('04')s public keys; the suite must not depend on it."""
    if not available("sm2-sm3"):
        pytest.skip("gmssl missing")
    seen = set()
    for _ in range(400):
        key = suites.generate_key("sm2-sm3")
        proof = suites.sign("sm2-sm3", key, SUBJECT)
        x_hex = suites.parse_did_key(proof["verification_method"])[1][1:].hex()
        if x_hex[0] in "04":
            assert suites.verify(SUBJECT, proof)[0], x_hex
            seen.add(x_hex[0])
        if seen == {"0", "4"}:
            return
    pytest.fail(f"did not hit both leading digits, saw {seen}")


def test_issuer_binding():
    assert suites.binds("did:pkh:eip155:1:0xAbC", "0xabc")
    assert suites.binds("did:pkh:eip155:11155111:0xABC", "0xAbc")
    assert not suites.binds("did:pkh:eip155:1:0xabc", "0xdef")
    assert not suites.binds("did:web:example.org", "did:key:z6Mk...")
    assert not suites.binds("did:eudi:eudi:alice", "0xabc")
    for gone in ("did:plug:sepolia:0xABC", "did:plug:eip155:11155111:0xABC"):
        assert not suites.binds(gone, "0xabc"), "did:plug is not an issuer DID"
        assert suites.issuer_key(gone) is None


def test_issuer_key_names_the_key_or_account():
    did = suites.KeySigner("ed25519", suites.generate_key("ed25519")).verification_method
    assert suites.issuer_key(did + "#key-1") == did
    assert suites.issuer_key("did:pkh:eip155:1:0xAbC") == "0xabc"
    assert suites.issuer_key("did:pkh:cosmos:cosmoshub-3:cosmos1t2uf") == "cosmos1t2uf"
    assert suites.issuer_key("did:web:example.org") is None


def test_account_did_grammar():
    p = suites.parse_account_did
    assert p("did:pkh:eip155:11155111:0xAbC") == ("eip155:11155111", "0xAbC")
    assert p("did:pkh:cosmos:cosmoshub-3:cosmos1t2uf#k") == ("cosmos:cosmoshub-3", "cosmos1t2uf")
    assert p("did:pkh:eip155:1:0xabc") == ("eip155:1", "0xabc")
    for bad in ("did:plug:eip155:11155111:0xAbC", "did:plug:chainmaker:ZXaa11", "did:plug:testnet:alice",
                "did:pkh:sepolia:0xabc", "did:pkh:EIP155:1:0xabc", "did:pkh:eip155:1:0x:abc",
                "did:pkh:ab:1:0xabc", "did:pkh:eip155:1:" + "a" * 129, "did:key:z6Mk", ""):
        assert p(bad) is None, bad


def _b64u(data):
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=")


@pytest.mark.parametrize("jose_alg,suite", [("ES256", "ecdsa-p256"), ("Ed25519", "ed25519"), ("EdDSA", "ed25519")])
def test_verify_jws(jose_alg, suite):
    if not available(suite):
        pytest.skip(f"{suite} library not installed")
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    signing_input = _b64u(b'{"alg":"' + jose_alg.encode() + b'"}') + b"." + _b64u(b'{"sub":"alice"}')
    key = suites.generate_key(suite)
    method = suites.KeySigner(suite, key).verification_method
    if suite == "ed25519":
        signature = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key)).sign(signing_input)
    else:
        from cryptography.hazmat.primitives import hashes
        der = ec.derive_private_key(int(key, 16), ec.SECP256R1()).sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert suites.verify_jws(signing_input, signature, jose_alg, method) is True
    assert suites.verify_jws(signing_input + b"x", signature, jose_alg, method) is False
    assert suites.verify_jws(signing_input, signature, "RS256", method) is False
    assert suites.verify_jws(signing_input, signature, "none", method) is False
    other = "ES256" if suite == "ed25519" else "EdDSA"
    assert suites.verify_jws(signing_input, signature, other, method) is False, "alg must match the key type"
    stranger = suites.KeySigner(suite, suites.generate_key(suite)).verification_method
    assert suites.verify_jws(signing_input, signature, jose_alg, stranger) is False
    assert suites.verify_jws(signing_input, signature, jose_alg, "did:web:example.org") is False


@pytest.mark.parametrize("alg", suites.SUITES)
def test_key_signer_signs_the_32_byte_message(alg):
    if not available(alg):
        pytest.skip(f"{alg} library not installed")
    key = suites.generate_key(alg)
    signer = suites.KeySigner(alg, key)
    proof = signer.sign(bytes.fromhex(SUBJECT))
    assert proof["verification_method"] == signer.verification_method and proof["alg"] == alg
    assert suites.verify(SUBJECT, proof) == (True, signer.verification_method)
    if alg == "ecdsa-secp256k1":
        assert signer.verification_method.startswith("0x")
    else:
        assert suites.parse_did_key(signer.verification_method)[0] == alg
    with pytest.raises(PlugError):
        signer.sign(b"short")


def test_unknown_suites_and_malformed_proofs_never_verify():
    with pytest.raises(PlugError) as e:
        suites.generate_key("rsa")
    assert e.value.code == "unsupported_op"
    with pytest.raises(PlugError):
        suites.sign("rsa", "00" * 32, SUBJECT)
    for proof in (None, {}, {"alg": "ed25519", "sig": "0x00"}, {"alg": "rsa", "sig": "0x00", "verification_method": "x"},
                  {"alg": "ed25519", "sig": "zz", "verification_method": "did:key:z6Mk"}):
        assert suites.verify(SUBJECT, proof)[0] is False, proof
    assert suites.verify("abc", {"alg": "ed25519", "sig": "0x00", "verification_method": "did:key:z6Mk"})[0] is False


# ---- OpenSSL interoperability ----

def _openssl():
    for cand in (os.environ.get("UPP_OPENSSL"), "/opt/homebrew/opt/openssl@3/bin/openssl",
                 "/usr/local/opt/openssl@3/bin/openssl", shutil.which("openssl")):
        if cand and os.path.exists(cand):
            out = subprocess.run([cand, "version"], capture_output=True, text=True).stdout
            if out.startswith("OpenSSL 3"):
                return cand
    return None


OPENSSL = _openssl()
GENKEY = {"ed25519": ["-algorithm", "ED25519"],
          "ecdsa-p256": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
          "sm2-sm3": ["-algorithm", "SM2"]}
DIGEST = {"ed25519": [], "ecdsa-p256": ["-digest", "sha256"],
          "sm2-sm3": ["-digest", "sm3", "-pkeyopt", "distid:1234567812345678"]}


def _run(*args, **kw):
    return subprocess.run([OPENSSL, *args], capture_output=True, check=True, **kw)


def _key_fields(pem):
    text = _run("pkey", "-in", pem, "-noout", "-text", text=True).stdout
    fields, current = {}, None
    for line in text.splitlines():
        if line.rstrip().endswith(":") and not line.startswith(" "):
            current = line.strip().rstrip(":")
            fields[current] = ""
        elif current and line.startswith(" "):
            fields[current] += line.strip().replace(":", "")
        else:
            current = None
    return bytes.fromhex(fields["priv"]), bytes.fromhex(fields["pub"])


def _der_to_raw(der):
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _raw_to_der(raw):
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def _compressed(pub):
    return bytes([2 + (pub[64] & 1)]) + pub[1:33] if len(pub) == 65 else pub


@pytest.mark.skipif(OPENSSL is None, reason="OpenSSL 3 not found")
@pytest.mark.parametrize("alg", ["ed25519", "ecdsa-p256", "sm2-sm3"])
def test_interop_with_openssl(alg):
    if not available(alg):
        pytest.skip(f"{alg} library not installed")
    with tempfile.TemporaryDirectory() as d:
        pem, pub_pem, msg, sig = (os.path.join(d, n) for n in ("k.pem", "pub.pem", "msg.bin", "sig.bin"))
        _run("genpkey", *GENKEY[alg], "-out", pem)
        _run("pkey", "-in", pem, "-pubout", "-out", pub_pem)
        priv, pub = _key_fields(pem)
        priv = priv[-32:]
        with open(msg, "wb") as f:
            f.write(bytes.fromhex(SUBJECT))

        # OpenSSL signs, upp verifies.
        _run("pkeyutl", "-sign", "-inkey", pem, "-rawin", *DIGEST[alg], "-in", msg, "-out", sig)
        raw = open(sig, "rb").read()
        raw = raw if alg == "ed25519" else _der_to_raw(raw)
        method = suites.did_key(alg, _compressed(pub))
        ok, why = suites.verify(SUBJECT, {"alg": alg, "sig": "0x" + raw.hex(), "verification_method": method})
        assert ok, why

        # upp signs with the same key, OpenSSL verifies.
        proof = suites.sign(alg, priv.hex(), SUBJECT)
        assert proof["verification_method"] == method
        raw = bytes.fromhex(proof["sig"][2:])
        with open(sig, "wb") as f:
            f.write(raw if alg == "ed25519" else _raw_to_der(raw))
        out = _run("pkeyutl", "-verify", "-pubin", "-inkey", pub_pem, "-rawin", *DIGEST[alg],
                   "-in", msg, "-sigfile", sig, text=True)
        assert "Signature Verified Successfully" in out.stdout


ED25519_SMALL_ORDER = [  # libsodium's blocklist of small-order encodings, with and without the sign bit
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
]


def test_ed25519_small_order_and_noncanonical_keys_never_verify():
    if not available("ed25519"):
        pytest.skip("cryptography missing")
    for key in ED25519_SMALL_ORDER:
        assert suites._ed_small_order_or_invalid(bytes.fromhex(key)), key
    assert suites._ed_small_order_or_invalid(bytes.fromhex("ed" + "ff" * 30 + "7f")), "y >= p is not canonical"
    identity = bytes.fromhex(ED25519_SMALL_ORDER[1])
    forged = {"alg": "ed25519", "sig": "0x" + (identity + bytes(32)).hex(),
              "verification_method": suites.did_key("ed25519", identity)}
    assert suites.verify(SUBJECT, forged)[0] is False, "the identity key must not sign everything"
    for _ in range(20):
        did = suites.sign("ed25519", suites.generate_key("ed25519"), SUBJECT)["verification_method"]
        assert not suites._ed_small_order_or_invalid(suites.parse_did_key(did)[1])


def test_one_key_has_exactly_one_did_key():
    if not available("ecdsa-p256"):
        pytest.skip("cryptography missing")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = suites.generate_key("ecdsa-p256")
    proof = suites.sign("ecdsa-p256", key, SUBJECT)
    public = ec.derive_private_key(int(key, 16), ec.SECP256R1()).public_key()
    aliases = [public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint),
               public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)]
    for alias in aliases:
        did = "did:key:z" + suites._b58encode(suites._varint(0x1200) + alias)
        with pytest.raises(ValueError):
            suites.parse_did_key(did)
        assert suites.verify(SUBJECT, dict(proof, verification_method=did))[0] is False
    canonical = proof["verification_method"]
    raw = suites._b58decode(canonical[len("did:key:z"):])
    with pytest.raises(ValueError):
        suites.parse_did_key("did:key:z1" + suites._b58encode(raw))  # leading zero byte: another spelling
    assert suites.verify(SUBJECT, proof)[0] is True

