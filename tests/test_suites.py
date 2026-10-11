# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Signature suites, cross-checked against OpenSSL 3 where it is installed."""
import os
import shutil
import subprocess
import tempfile

import pytest

from plug import suites
from plug.core import PlugError, sha256_hex

pytest.importorskip("Crypto")

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
    assert suites.binds(f"did:plug:net:{method}" if method.startswith("0x") else method, method)
    assert suites.verify(sha256_hex(b"other"), proof)[0] is False
    flipped = bytearray(bytes.fromhex(proof["sig"][2:]))
    flipped[5] ^= 1
    assert suites.verify(SUBJECT, dict(proof, sig="0x" + flipped.hex()))[0] is False
    foreign = suites.sign(alg, other, SUBJECT)["verification_method"]
    assert suites.verify(SUBJECT, dict(proof, verification_method=foreign))[0] is False


def test_did_key_prefixes_match_multicodec_registry():
    if not available("ed25519"):
        pytest.skip("pycryptodome missing")
    ed = suites.sign("ed25519", suites.generate_key("ed25519"), SUBJECT)["verification_method"]
    p256 = suites.sign("ecdsa-p256", suites.generate_key("ecdsa-p256"), SUBJECT)["verification_method"]
    assert ed.startswith("did:key:z6Mk") and p256.startswith("did:key:zDn")
    assert suites.parse_did_key(ed)[0] == "ed25519" and len(suites.parse_did_key(ed)[1]) == 32
    assert suites.parse_did_key(p256 + "#key-1")[0] == "ecdsa-p256"


def test_key_type_must_match_alg():
    if not available("ed25519"):
        pytest.skip("pycryptodome missing")
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
    assert suites.binds("did:plug:sepolia:0xABC", "0xAbc")
    assert suites.binds("did:plug:eip155:11155111:0xABC", "0xabc")
    assert not suites.binds("did:plug:sepolia:0xabc", "0xdef")
    assert not suites.binds("did:web:example.org", "did:key:z6Mk...")
    assert not suites.binds("did:eudi:eudi:alice", "0xabc")


def test_account_did_grammar():
    p = suites.parse_account_did
    assert p("did:plug:eip155:11155111:0xAbC") == ("eip155:11155111", "0xAbC")
    assert p("did:plug:cosmos:cosmoshub-3:cosmos1t2uf#k") == ("cosmos:cosmoshub-3", "cosmos1t2uf")
    assert p("did:plug:chainmaker:ZXaa11") == ("chainmaker", "ZXaa11")
    assert p("did:plug:testnet:alice") == ("testnet", "alice")
    assert p("did:pkh:eip155:1:0xabc") == ("eip155:1", "0xabc")
    for bad in ("did:plug:anon", "did:pkh:sepolia:0xabc", "did:plug:EIP155:1:0xabc",
                "did:plug:chainmaker:chain1:ZX", "did:plug:eip155:1:0x:abc",
                "did:plug:ab:1:0xabc", "did:plug:x:" + "a" * 129):
        assert p(bad) is None, bad


# ---- OpenSSL interoperability ----

def _openssl():
    for cand in (os.environ.get("PLUG_OPENSSL"), "/opt/homebrew/opt/openssl@3/bin/openssl",
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
    from Crypto.Util.asn1 import DerSequence
    seq = DerSequence().decode(der)
    return seq[0].to_bytes(32, "big") + seq[1].to_bytes(32, "big")


def _raw_to_der(raw):
    from Crypto.Util.asn1 import DerSequence
    return DerSequence([int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")]).encode()


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

        # OpenSSL signs, Plug verifies.
        _run("pkeyutl", "-sign", "-inkey", pem, "-rawin", *DIGEST[alg], "-in", msg, "-out", sig)
        raw = open(sig, "rb").read()
        raw = raw if alg == "ed25519" else _der_to_raw(raw)
        method = suites.did_key(alg, _compressed(pub))
        ok, why = suites.verify(SUBJECT, {"alg": alg, "sig": "0x" + raw.hex(), "verification_method": method})
        assert ok, why

        # Plug signs with the same key, OpenSSL verifies.
        proof = suites.sign(alg, priv.hex(), SUBJECT)
        assert proof["verification_method"] == method
        raw = bytes.fromhex(proof["sig"][2:])
        with open(sig, "wb") as f:
            f.write(raw if alg == "ed25519" else _raw_to_der(raw))
        out = _run("pkeyutl", "-verify", "-pubin", "-inkey", pub_pem, "-rawin", *DIGEST[alg],
                   "-in", msg, "-sigfile", sig, text=True)
        assert "Signature Verified Successfully" in out.stdout
