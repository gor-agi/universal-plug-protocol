# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Third-party test vectors and reference implementations, run against our code (see spec/vectors/README.md)."""
import json
import os
import random
import string

import pytest

from plug.core import canonical, digest

VECTORS = os.path.join(os.path.dirname(__file__), "..", "spec", "vectors")


def load(*parts):
    with open(os.path.join(VECTORS, *parts), encoding="utf-8") as f:
        return f.read()


# ---- P1: RFC 8785 reference data (cyberphone/json-canonicalization) and Trail of Bits rfc8785 ----

@pytest.mark.parametrize("name", ["arrays", "french", "structures", "unicode", "values", "weird"])
def test_jcs_reference_data(name):
    value = json.loads(load("jcs-cyberphone", f"{name}.input.json"))
    assert canonical(value) == load("jcs-cyberphone", f"{name}.output.json").rstrip("\n")


def _random_json(rng, depth=0):
    kind = rng.choice(["num", "float", "str", "bool", "null"] + (["list", "obj"] if depth < 4 else []))
    if kind == "num":
        return rng.randint(-(2**53) + 1, 2**53 - 1)
    if kind == "float":
        return rng.choice([rng.uniform(-1e30, 1e30), rng.uniform(-1, 1) * 10 ** rng.randint(-320, 300),
                           float(rng.randint(-10**6, 10**6)), 5e-324, 1.7976931348623157e308, -0.0, 0.1 + 0.2])
    if kind == "str":
        alphabet = string.printable + "\u20ac\u00f6\ufb33\U0001f600\u0080\u2028\u0000\u001f"
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
    if kind == "bool":
        return rng.choice([True, False])
    if kind == "null":
        return None
    if kind == "list":
        return [_random_json(rng, depth + 1) for _ in range(rng.randint(0, 5))]
    key = lambda: "".join(rng.choice(string.ascii_letters + "\u20ac\U0001f600\u00e9\ufb33\u0080")
                          for _ in range(rng.randint(0, 6)))
    return {key(): _random_json(rng, depth + 1) for _ in range(rng.randint(0, 5))}


def test_jcs_agrees_with_trail_of_bits_rfc8785():
    rfc8785 = pytest.importorskip("rfc8785")
    rng = random.Random(8785)
    for _ in range(3000):
        value = _random_json(rng)
        assert canonical(value).encode("utf-8") == rfc8785.dumps(value), value


# ---- P2: SM3 (GB/T 32905; GmSSL tests/sm3test.c) ----

def test_sm3_reference_digests():
    try:
        digest(b"abc", "sm3")
    except Exception:
        pytest.skip("no SM3 implementation available")
    assert digest(b"abc", "sm3") == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    assert digest(b"abcd" * 16, "sm3") == "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"


# ---- P4: Wycheproof (C2SP/wycheproof) for P-256 (r||s) and Ed25519 ----

def _wycheproof(name):
    return json.loads(load("wycheproof", name))


def test_wycheproof_ecdsa_p256_sha256_p1363():
    pytest.importorskip("cryptography")
    from plug.suites import _p256_verify
    doc = _wycheproof("ecdsa_secp256r1_sha256_p1363_test.json")
    checked = 0
    for group in doc["testGroups"]:
        point = bytes.fromhex(group["publicKey"]["uncompressed"])
        public = bytes([2 + (point[64] & 1)]) + point[1:33]  # did:key carries the compressed point
        for t in group["tests"]:
            got = _p256_verify(bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]), public)
            if t["result"] == "valid":
                assert got, t["tcId"]
            elif t["result"] == "invalid":
                assert not got, (t["tcId"], t["comment"])
            checked += 1
    assert checked == doc["numberOfTests"]


def test_wycheproof_ed25519():
    pytest.importorskip("cryptography")
    from plug.suites import _ed_verify
    doc = _wycheproof("ed25519_test.json")
    checked = 0
    for group in doc["testGroups"]:
        public = bytes.fromhex(group["publicKey"]["pk"])
        for t in group["tests"]:
            got = _ed_verify(bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]), public)
            if t["result"] == "valid":
                assert got, t["tcId"]
            elif t["result"] == "invalid":
                assert not got, (t["tcId"], t["comment"])
            checked += 1
    assert checked == doc["numberOfTests"]


# ---- P7: Token Status List encodings (draft-ietf-oauth-status-list-21, Appendix C) ----

def test_status_list_draft_appendix_c():
    from plug.adapters.eudi import decode_status_list, status_at
    for v in json.loads(load("status-list-draft21.json"))["vectors"]:
        bits, array = decode_status_list({"bits": v["bits"], "lst": v["lst"]})
        assert len(array) * 8 // bits == v["size"], v["section"]
        want = {int(k): s for k, s in v["statuses"].items()}
        nonzero = {i: status_at(bits, array, i) for i in range(v["size"]) if status_at(bits, array, i)}
        assert nonzero == {i: s for i, s in want.items() if s}, v["section"]


def test_wycheproof_ecdsa_secp256k1_through_ethereum_recovery():
    """Our secp256k1 suite recovers the signer's address; a valid signature recovers it with one recovery id, an
    invalid one with neither. Wycheproof's DER signatures are converted to r||s||v for that check."""
    pytest.importorskip("eth_keys")
    import hashlib
    from eth_keys import keys
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from plug.suites import _k1_verify
    doc = _wycheproof("ecdsa_secp256k1_sha256_test.json")
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    mismatches = []
    for group in doc["testGroups"]:
        address = keys.PublicKey(bytes.fromhex(group["publicKey"]["uncompressed"])[1:]).to_checksum_address()
        for t in group["tests"]:
            digest32 = hashlib.sha256(bytes.fromhex(t["msg"])).digest()
            try:
                r, s = decode_dss_signature(bytes.fromhex(t["sig"]))
                ok = 0 < r < n and 0 < s < n and any(
                    _k1_verify(digest32, r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v]), address)[0]
                    for v in (0, 1))
            except (ValueError, OverflowError):
                ok = False  # not DER, or r/s wider than 32 bytes: no Ethereum signature can carry it
            if (t["result"] == "valid") != ok and t["result"] != "acceptable":
                mismatches.append((t["tcId"], t["result"], t["comment"]))
    # Ethereum's v carries only the parity of R.y (recovery id 0 or 1). A signature whose R.x is r + n needs
    # recovery id 2 or 3, which no Ethereum signature can express; honest signers hit it with probability ~2^-128.
    unrepresentable = {350, 471}
    assert {m[0] for m in mismatches} == unrepresentable, mismatches[:10]
    for group in doc["testGroups"]:
        for t in group["tests"]:
            if t["tcId"] in unrepresentable:
                r, _ = decode_dss_signature(bytes.fromhex(t["sig"]))
                assert r + n < 2**256 - 2**32 - 977, "R.x = r + n is a field element only for small r"
