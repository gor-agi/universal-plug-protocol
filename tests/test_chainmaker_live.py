# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""ChainMaker adapter against a real node. Skipped unless PLUG_CHAINMAKER_CERTS names a
crypto-config directory and PLUG_CHAINMAKER_NODE (default 127.0.0.1:12301) is reachable."""
import os
import socket
import time

import pytest

pytest.importorskip("chainmaker")
pytest.importorskip("Crypto")

from plug import suites
from plug.adapters.chainmaker import ChainMakerAdapter, anchor_calldata
from plug.core import Attestation, Plug, Status, sha256_hex

CERTS = os.environ.get("PLUG_CHAINMAKER_CERTS", "")
NODE = os.environ.get("PLUG_CHAINMAKER_NODE", "127.0.0.1:12301")
ORG = os.environ.get("PLUG_CHAINMAKER_ORG", "wx-org.chainmaker.org")
NET = "chainmaker"


def _reachable():
    host, port = NODE.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=2).close()
        return bool(CERTS) and os.path.isdir(CERTS)
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _reachable(), reason="no ChainMaker node configured")


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
    adapter = ChainMakerAdapter(sdk_config(), contract=contract)
    deployed = ChainMakerAdapter.deploy_anchor(adapter.client, contract, member("admin1"))
    assert deployed.status == Status.OK, deployed.error
    p = Plug()
    p.register_adapter(NET, adapter)
    return p, adapter


def attestation(r, **overrides):
    fields = dict(subject_hash=r.data["subject_hash"], fact_type=r.data["fact_type"], issuer=r.data["issuer"],
                  issued_at="2026-10-11T00:00:00Z", proof=dict(r.data["proof"]), anchor=r.state_ref)
    fields.update(overrides)
    return Attestation(**fields)


def test_prove_and_check_on_a_permissioned_ledger(chain):
    p, adapter = chain
    p.open(NET, {"scheme": "x509", "material": member("client1")})
    r = p.prove({"bill_of_lading": "BL-2026-0042", "port": "Shanghai"}, "doc.sha256")
    assert r.status == Status.OK, r.error
    assert r.data["issuer"].startswith(f"did:plug:{NET}:0x") and r.data["org_id"] == ORG
    v = p.check(attestation(r))
    assert v["valid"] is True, v["receipt"].error
    data = v["receipt"].data
    assert data["finality"]["kind"] == "final" and data["anchored_at"].endswith("Z")
    assert data["verification_method"].startswith("did:key:zDn")


def test_unanchored_forged_and_impersonated_proofs_fail(chain):
    p, adapter = chain
    p.open(NET, {"scheme": "x509", "material": member("client1")})
    r = p.prove(b"real cargo manifest", "doc.sha256")
    client1_key = adapter._members[r.data["issuer"]][0]
    loose = sha256_hex(b"never anchored")
    v = p.check(attestation(r, subject_hash=loose, proof=suites.sign("ecdsa-p256", client1_key, loose)))
    assert v["receipt"].error == "proof_invalid: anchor does not carry the subject hash"

    outsider = suites.generate_key("ecdsa-p256")
    forged = suites.sign("ecdsa-p256", outsider, r.data["subject_hash"])
    v = p.check(attestation(r, proof=forged))
    assert v["receipt"].error == "proof_invalid: issuer is not bound to the signing key"

    p.open(NET, {"scheme": "x509", "material": member("light1")})
    other = p.prove(b"light1 claim", "doc.sha256")
    v = p.check(attestation(other, issuer=r.data["issuer"]))
    assert v["receipt"].error == "proof_invalid: issuer is not bound to the signing key"
    v = p.check(attestation(r, anchor=other.state_ref))
    assert v["receipt"].error in ("proof_invalid: anchor was sent by another key",
                                  "proof_invalid: anchor does not carry the subject hash")


def test_query_reads_the_ledger_record(chain):
    p, adapter = chain
    p.open(NET, {"scheme": "x509", "material": member("client1")})
    r = p.prove(b"query me", "doc.sha256")
    q = p.check(r.state_ref)
    assert q["valid"] is True
    assert q["receipt"].data["calldata"] == anchor_calldata(r.data["subject_hash"])
    assert q["receipt"].data["contract"] == adapter.contract
