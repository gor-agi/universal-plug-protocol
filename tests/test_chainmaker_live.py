# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""ChainMakerLedger: the issuer is the did:key of the member's P-256 certificate key.

Offline tests run against an in-memory client with member keys and self-signed certificates generated per run. The live tests
run against a real node only when UPP_CHAINMAKER_CERTS names a crypto-config directory and UPP_CHAINMAKER_NODE
(default 127.0.0.1:12301) is reachable."""
import os
import socket
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

import pytest

pytest.importorskip("chainmaker")
pytest.importorskip("sha3")
pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from upp import ANY, Attestation, Plug, PlugError, StateRef, Status, sha256_hex, statement_hash, suites
from upp.ext.chainmaker import (ANCHOR_CREATION_CODE, ChainMakerLedger, account_from_public_key, anchor_calldata,
                                anchor_selector)



def _make_members() -> str:
    """Two P-256 member keys with self-signed certificates, written to a fresh directory (no keys in the repo)."""
    import tempfile
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import atexit
    import shutil
    out = tempfile.mkdtemp(prefix="upp-cm-")
    atexit.register(shutil.rmtree, out, True)
    for name in ("member1", "member2"):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name}.test-org.upp.example")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
        with open(os.path.join(out, f"{name}.sign.key"), "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        with open(os.path.join(out, f"{name}.sign.crt"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    return out


DATA = _make_members()
NET = "chainmaker"
TEST_ORG = "test-org.upp.example"


def _keccak(data: bytes) -> bytes:
    from eth_utils import keccak
    return keccak(data)


# ---- offline: calldata, selector, account ----

def test_anchor_selector_and_calldata():
    pytest.importorskip("eth_utils")
    assert anchor_selector() == _keccak(b"anchor(bytes32)")[:4].hex()
    subject = sha256_hex(b"bill of lading")
    assert anchor_calldata(subject) == anchor_selector() + subject
    assert len(bytes.fromhex(anchor_calldata(subject))) == 4 + 32


def test_anchor_contract_runtime_is_a_single_stop():
    code = bytes.fromhex(ANCHOR_CREATION_CODE)
    # PUSH1 01 DUP1 PUSH1 0b PUSH1 00 CODECOPY PUSH1 00 RETURN | STOP
    assert code[:11] == bytes.fromhex("600180600b6000396000f3") and code[11:] == b"\x00"


def test_account_from_public_key_is_keccak_of_the_uncompressed_point():
    pytest.importorskip("eth_utils")
    cert = x509.load_pem_x509_certificate(open(f"{DATA}/member1.sign.crt", "rb").read())
    numbers = cert.public_key().public_numbers()
    compressed = cert.public_key().public_bytes(serialization.Encoding.X962,
                                                serialization.PublicFormat.CompressedPoint)
    expected = "0x" + _keccak(numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big"))[-20:].hex()
    assert account_from_public_key(compressed) == expected


# ---- offline: an in-memory ChainMaker client ----

def member_files(name, org=TEST_ORG):
    return {"org_id": org, "sign_key": f"{DATA}/{name}.sign.key", "sign_crt": f"{DATA}/{name}.sign.crt"}


def member_did(name):
    key = x509.load_pem_x509_certificate(open(f"{DATA}/{name}.sign.crt", "rb").read()).public_key()
    return suites.did_key("ecdsa-p256", key.public_bytes(serialization.Encoding.X962,
                                                         serialization.PublicFormat.CompressedPoint))


def block_time(height):
    return 1_791_000_000 + height


class FakeClient:
    """Includes every request in its own block. The sender is the signer's certificate, as the chain records it."""

    def __init__(self):
        self.txs, self.height, self.fail = {}, 10, False

    def send_request_with_sync_result(self, payload, with_sync_result=True, signer=None):
        self.height += 1
        code = 1 if self.fail else 0
        self.txs[payload.tx_id] = {"payload": payload, "cert": bytes(signer.member_info), "org": signer.org_id,
                                   "height": self.height, "code": code}
        return NS(tx_id=payload.tx_id, code=0, contract_result=NS(code=code, message="reverted" if code else ""))

    def get_tx_by_tx_id(self, tx_id):
        t = self.txs[tx_id]
        signer = NS(member_type=0, member_info=t["cert"], org_id=t["org"])
        return NS(transaction=NS(sender=NS(signer=signer), payload=t["payload"], result=NS(code=t["code"])),
                  block_height=t["height"], block_timestamp=block_time(t["height"]))

    def get_current_block_height(self):
        return self.height


def offline(*names):
    client = FakeClient()
    ledger = ChainMakerLedger({"chain_client": {"chain_id": "chain1"}}, client=client)
    p = Plug(trust={NET: ANY})
    p.register(NET, ledger)
    sessions = [p.open(NET, {"member": member_files(n)}) for n in names]
    return p, ledger, client, sessions


def attestation(r, signer=None, **overrides):
    """The receipt's attestation with overrides; signer re-signs the changed statement with that key."""
    att = replace(Attestation.from_receipt(r), **overrides)
    if signer:
        att.proof = suites.sign("ecdsa-p256", signer, statement_hash(att))
    return att


def test_offline_prove_and_check_with_a_member_did_key():
    p, ledger, client, _ = offline("member1")
    r = p.prove({"bill_of_lading": "BL-2026-0042", "port": "Shanghai"}, "doc.sha256")
    assert r.status == Status.OK, r.error
    assert r.data["issuer"] == member_did("member1") and r.data["issuer"].startswith("did:key:zDn")
    assert r.data["org_id"] == TEST_ORG and r.state_ref.address.startswith("cm:")
    params = {kv.key: bytes(kv.value).decode() for kv in client.txs[r.state_ref.address[3:]]["payload"].parameters}
    assert params == {"data": anchor_calldata(r.data["statement_hash"])}
    v = p.check(attestation(r))
    assert v["valid"] is True, v["receipt"].error
    data = v["receipt"].data
    assert data["verification_method"] == member_did("member1") and data["org_id"] == TEST_ORG
    assert data["finality"]["kind"] == "final" and data["anchored_block"] == r.data["block"]
    assert data["anchored_at"] == datetime.fromtimestamp(block_time(r.data["block"]), timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def test_offline_unanchored_forged_and_impersonated_proofs_fail():
    p, ledger, client, (s1, s2) = offline("member1", "member2")
    p.use(s1)
    r = p.prove(b"real cargo manifest", "doc.sha256")
    key1 = ledger._members[r.data["issuer"]][0]
    v = p.check(attestation(r, signer=key1, subject_hash=sha256_hex(b"never anchored")))
    assert v["receipt"].error == "proof_invalid: anchor does not carry the statement"
    v = p.check(attestation(r, signer=suites.generate_key("ecdsa-p256")))
    assert v["receipt"].error == "proof_invalid: issuer is not bound to the signing key"
    assert p.check(attestation(r, fact_type="contract.signed"))["receipt"].error == "proof_invalid: bad signature"

    p.use(s2)
    other = p.prove(b"member2 claim", "doc.sha256")
    key2 = ledger._members[other.data["issuer"]][0]
    v = p.check(attestation(other, signer=key2, issuer=r.data["issuer"]))
    assert v["receipt"].error == "proof_invalid: issuer is not bound to the signing key"
    v = p.check(attestation(r, anchor=other.state_ref))
    assert v["receipt"].error == "proof_invalid: anchor was sent by another key"
    v = p.check(attestation(other, signer=key1, issuer=r.data["issuer"]))
    assert v["receipt"].error == "proof_invalid: anchor was sent by another key"


def test_offline_anchor_checks():
    p, ledger, client, _ = offline("member1")
    r = p.prove(b"anchored", "doc.sha256")
    assert p.check(attestation(r, anchor=None))["receipt"].error == "proof_invalid: missing anchor"
    assert p.check(attestation(r, anchor=StateRef("elsewhere", r.state_ref.address)))["receipt"].error == \
        "proof_invalid: anchor is on another network"
    assert p.check(attestation(r, anchor=StateRef(NET, "cm:" + "ab" * 32)))["receipt"].error == \
        "not_found: anchor cm:" + "ab" * 32
    att = attestation(r)
    att.proof = suites.sign("ed25519", suites.generate_key("ed25519"), statement_hash(att))
    assert p.check(att)["receipt"].error == "proof_invalid: unsupported alg"
    tx = client.txs[r.state_ref.address[3:]]
    tx["code"] = 1
    assert p.check(attestation(r))["receipt"].error == "proof_invalid: anchor transaction failed"
    tx["code"] = 0
    ledger.contract = "some_other_contract"
    assert p.check(attestation(r))["receipt"].error == "proof_invalid: anchor did not call the anchor contract"


def test_offline_failed_invocation_carries_no_proof():
    p, _, client, _ = offline("member1")
    client.fail = True
    r = p.prove(b"doomed", "doc.sha256")
    assert r.status == Status.REJECTED and r.error == "proof_invalid: reverted"
    assert "proof" not in r.data


def test_offline_only_the_open_session_signs():
    p, _, _, (s1, s2) = offline("member1", "member2")
    as_member1 = Attestation(sha256_hex(b"x"), "doc.sha256", member_did("member1"), "2026-10-10T00:00:00Z")
    with pytest.raises(PlugError) as e:
        p.attest(as_member1, NET)  # member2 is the open session
    assert e.value.code == "auth_failed"
    p.use(s1)
    assert p.attest(as_member1, NET).status == Status.OK
    p.close(s1)
    p.close(s2)
    with pytest.raises(PlugError) as e:
        p.attest(as_member1, NET)
    assert e.value.code == "auth_failed"
    with pytest.raises(PlugError) as e:
        p.prove(b"anonymous", "doc.sha256", network=NET)
    assert e.value.code == "auth_failed"


def test_offline_member_material_must_match():
    _, ledger, _, _ = offline()
    with pytest.raises(PlugError) as e:
        ledger.connect(NET, {"member": dict(member_files("member1"), sign_crt=f"{DATA}/member2.sign.crt")})
    assert e.value.code == "auth_failed" and "does not match" in e.value.message
    for material in ({}, {"org_id": TEST_ORG, "sign_key": f"{DATA}/missing.key", "sign_crt": f"{DATA}/x.crt"}):
        with pytest.raises(PlugError) as e:
            ledger.connect(NET, {"member": material})
        assert e.value.code == "auth_failed"


def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_offline_registry_key_windows_are_judged_at_block_time():
    p, _, _, _ = offline("member1")
    r = p.prove(b"windowed", "doc.sha256")
    att = Attestation.from_receipt(r)
    issuer = member_did("member1")
    anchored = datetime.fromtimestamp(block_time(r.data["block"]), timezone.utc)
    second = timedelta(seconds=1)

    def registry(*entries):
        return {"issuers": [issuer], "keys": {issuer: list(entries)}}

    window = registry({"verification_method": issuer, "valid_from": _iso(anchored - second),
                       "valid_until": _iso(anchored + second)})
    v = p.check(att, trust_registry=window)
    assert v["valid"] is True, v["receipt"].error
    late = registry({"verification_method": issuer, "valid_from": _iso(anchored + second)})
    assert p.check(att, trust_registry=late)["receipt"].error == f"proof_invalid: key not valid at {_iso(anchored)}"
    assert p.check(att, trust_registry={"issuers": [member_did("member2")]})["receipt"].error == \
        "not_authorized: issuer not in trust registry"


# ---- live: a real ChainMaker node, only when configured ----

CERTS = os.environ.get("UPP_CHAINMAKER_CERTS", "")
NODE = os.environ.get("UPP_CHAINMAKER_NODE", "127.0.0.1:12301")
ORG = os.environ.get("UPP_CHAINMAKER_ORG", "wx-org.chainmaker.org")


def _reachable():
    if not (CERTS and os.path.isdir(CERTS)):
        return False
    host, port = NODE.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=2).close()
        return True
    except OSError:
        return False


live = pytest.mark.skipif(not _reachable(), reason="no ChainMaker node configured (UPP_CHAINMAKER_CERTS)")


def member(name):
    base = f"{CERTS}/{ORG}/user/{name}/{name}"
    return {"org_id": ORG, "sign_key": f"{base}.sign.key", "sign_crt": f"{base}.sign.crt"}


def sdk_config():
    u = f"{CERTS}/{ORG}/user/client1/client1"
    return {"chain_client": {
        "chain_id": "chain1", "org_id": ORG,
        "user_key_file_path": f"{u}.tls.key", "user_crt_file_path": f"{u}.tls.crt",
        "user_sign_key_file_path": f"{u}.sign.key", "user_sign_crt_file_path": f"{u}.sign.crt",
        "crypto": {"hash": "SHA256"}, "auth_type": "permissionedWithCert",
        "nodes": [{"node_addr": NODE, "conn_cnt": 1, "enable_tls": True,
                   "trust_root_paths": [f"{CERTS}/{ORG}/ca"], "tls_host_name": "chainmaker.org"}]}}


@pytest.fixture(scope="module")
def chain():
    contract = f"upp_anchor_{int(time.time())}"
    ledger = ChainMakerLedger(sdk_config(), contract=contract)
    deployed = ChainMakerLedger.deploy_anchor(ledger.client, contract, member("admin1"))
    assert deployed.startswith("cm:")
    p = Plug(trust={NET: ANY})
    p.register(NET, ledger)
    return p, ledger


@live
def test_prove_and_check_on_a_permissioned_ledger(chain):
    p, ledger = chain
    p.open(NET, {"member": member("client1")})
    r = p.prove({"bill_of_lading": "BL-2026-0042", "port": "Shanghai"}, "doc.sha256")
    assert r.status == Status.OK, r.error
    assert r.data["issuer"].startswith("did:key:zDn") and r.data["org_id"] == ORG
    v = p.check(attestation(r))
    assert v["valid"] is True, v["receipt"].error
    data = v["receipt"].data
    assert data["finality"]["kind"] == "final" and data["anchored_at"].endswith("Z")
    assert data["verification_method"] == r.data["issuer"]


@live
def test_unanchored_forged_and_impersonated_proofs_fail(chain):
    p, ledger = chain
    p.open(NET, {"member": member("client1")})
    r = p.prove(b"real cargo manifest", "doc.sha256")
    client1_key = ledger._members[r.data["issuer"]][0]
    v = p.check(attestation(r, signer=client1_key, subject_hash=sha256_hex(b"never anchored")))
    assert v["receipt"].error == "proof_invalid: anchor does not carry the statement"

    v = p.check(attestation(r, signer=suites.generate_key("ecdsa-p256")))
    assert v["receipt"].error == "proof_invalid: issuer is not bound to the signing key"
    assert p.check(attestation(r, fact_type="contract.signed"))["receipt"].error == "proof_invalid: bad signature"

    p.open(NET, {"member": member("light1")})
    other = p.prove(b"light1 claim", "doc.sha256")
    light1_key = ledger._members[other.data["issuer"]][0]
    v = p.check(attestation(other, signer=light1_key, issuer=r.data["issuer"]))
    assert v["receipt"].error == "proof_invalid: issuer is not bound to the signing key"
    v = p.check(attestation(r, anchor=other.state_ref))
    assert v["receipt"].error in ("proof_invalid: anchor was sent by another key",
                                  "proof_invalid: anchor does not carry the statement")


@live
def test_the_ledger_record_carries_the_statement(chain):
    p, ledger = chain
    p.open(NET, {"member": member("client1")})
    r = p.prove(b"query me", "doc.sha256")
    found = ledger._transaction(r.state_ref.address)
    assert found["calldata"] == anchor_calldata(statement_hash(Attestation.from_receipt(r)))
    assert found["contract"] == ledger.contract and found["sender"] == r.data["issuer"]
