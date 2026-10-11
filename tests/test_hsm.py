# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Signing with keys that never leave a PKCS#11 token, against a real SoftHSM2 token in a temporary directory."""
import os
import shutil
import subprocess
import time

import pytest

pkcs11 = pytest.importorskip("pkcs11")
pytest.importorskip("cryptography")

from plug import Attestation, Plug, suites
from plug.adapters.oracle import OracleAdapter
from plug.core import sha256_hex, statement_hash

CANDIDATES = [os.environ.get("PLUG_PKCS11_LIB", ""), "/opt/homebrew/lib/softhsm/libsofthsm2.so",
              "/usr/local/lib/softhsm/libsofthsm2.so", "/usr/lib/softhsm/libsofthsm2.so",
              "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so"]
LIB = next((p for p in CANDIDATES if p and os.path.exists(p)), None)
TOKEN, PIN = "plug-test", "1234"
pytestmark = pytest.mark.skipif(LIB is None or shutil.which("softhsm2-util") is None, reason="SoftHSM2 not installed")


@pytest.fixture(scope="module")
def token(tmp_path_factory):
    home = tmp_path_factory.mktemp("softhsm")
    (home / "tokens").mkdir()
    conf = home / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {home / 'tokens'}\nobjectstore.backend = file\n")
    os.environ["SOFTHSM2_CONF"] = str(conf)  # read when the library initializes, below
    subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", TOKEN, "--pin", PIN, "--so-pin", "5678"],
                   check=True, capture_output=True)
    from pkcs11 import Attribute, KeyType, Mechanism
    from pkcs11.util.ec import encode_named_curve_parameters
    tok = pkcs11.lib(LIB).get_token(token_label=TOKEN)
    made = set()
    with tok.open(user_pin=PIN, rw=True) as session:
        params = session.create_domain_parameters(
            KeyType.EC, {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")}, local=True)
        params.generate_keypair(store=True, label="p256", private_template={Attribute.EXTRACTABLE: False})
        made.add("ecdsa-p256")
        if Mechanism.EDDSA in set(tok.slot.get_mechanisms()):
            from asn1crypto.keys import PrivateKeyAlgorithmId
            ed = session.create_domain_parameters(KeyType.EC_EDWARDS, {
                Attribute.EC_PARAMS: encode_named_curve_parameters(PrivateKeyAlgorithmId.unmap("ed25519"))},
                local=True)
            ed.generate_keypair(store=True, label="ed25519", private_template={Attribute.EXTRACTABLE: False})
            made.add("ed25519")
    yield made
    os.environ.pop("SOFTHSM2_CONF", None)


@pytest.mark.parametrize("alg,label", [("ecdsa-p256", "p256"), ("ed25519", "ed25519")])
def test_attestations_signed_inside_the_token_verify(token, alg, label):
    if alg not in token:
        pytest.skip(f"this SoftHSM build has no {alg}")
    signer = suites.Pkcs11Signer(LIB, TOKEN, PIN, label, alg)
    try:
        assert suites.parse_did_key(signer.verification_method)[0] == alg
        p = Plug(trust={"evidence": {"issuers": [signer.verification_method]}})
        p.register_adapter("evidence", OracleAdapter())
        att = Attestation(sha256_hex(f"hsm {alg}"), "agent.action", signer.verification_method,
                          time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), meta={"model_family": "family-a"})
        suites.sign_attestation(signer, att)
        p.attest("evidence", att)
        assert p.check(att, network="evidence")["valid"] is True
        att.fact_type = "control.resume"
        assert p.check(att, network="evidence")["valid"] is False
    finally:
        signer.close()


def test_token_keys_cannot_be_extracted(token):
    from pkcs11 import Attribute, ObjectClass
    with pkcs11.lib(LIB).get_token(token_label=TOKEN).open(user_pin=PIN) as session:
        key = session.get_key(object_class=ObjectClass.PRIVATE_KEY, label="p256")
        assert key[Attribute.EXTRACTABLE] is False and key[Attribute.SENSITIVE] is True


def test_key_signer_has_the_same_interface():
    key = suites.generate_key("ed25519")
    signer = suites.KeySigner("ed25519", key)
    att = Attestation(sha256_hex("local"), "doc.sha256", signer.verification_method, "2026-10-11T00:00:00Z")
    proof = suites.sign_attestation(signer, att)
    assert proof == suites.sign("ed25519", key, statement_hash(att))
