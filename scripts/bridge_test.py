#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Cross-network check: prove on a permissioned ChainMaker ledger, reference it on an
Ethereum-family network through the relayer-free bridge, and verify both sides.

Env: PLUG_CHAINMAKER_CERTS, PLUG_CHAINMAKER_NODE (default 127.0.0.1:12301),
     SEPOLIA_RPC_URL, SEPOLIA_PRIVATE_KEY. Sends one transaction to each network.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plug.adapters.chainmaker import ChainMakerAdapter
from plug.adapters.live import LiveAdapter
from plug.core import Attestation, Plug

CERTS = os.environ["PLUG_CHAINMAKER_CERTS"]
NODE = os.environ.get("PLUG_CHAINMAKER_NODE", "127.0.0.1:12301")
ORG = "wx-org.chainmaker.org"


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


def main():
    contract = f"upp_anchor_{int(time.time())}"
    cm = ChainMakerAdapter(sdk_config(), contract=contract)
    deployed = ChainMakerAdapter.deploy_anchor(cm.client, contract, member("admin1"))
    print(f"anchor contract:    {contract} {deployed.status.value}")
    p = Plug()
    p.register_adapter("chainmaker", cm)
    p.register_adapter("sepolia", LiveAdapter())

    p.open("chainmaker", {"scheme": "x509", "material": member("client1")})
    src = p.prove({"certificate_of_origin": "CO-2026-0042", "hs_code": "7403.11"}, "doc.sha256")
    print(f"source attest:      {src.status.value} {src.state_ref.address} block {src.data['block']}")
    att = Attestation(src.data["subject_hash"], src.data["fact_type"], src.data["issuer"],
                      "2026-10-11T00:00:00Z", proof=src.data["proof"], anchor=src.state_ref)
    v = p.check(att)
    print(f"source check:       {v['valid']} org {v['receipt'].data.get('org_id')} finality {v['receipt'].data.get('finality')}")

    p.open("sepolia", {"scheme": "raw", "material": os.environ["SEPOLIA_PRIVATE_KEY"]})
    br = p.bridge(src.state_ref, "sepolia")
    print(f"bridge:             {br.status.value} {br.state_ref.address if br.state_ref else None}")
    both = p.check(br)
    print(f"bridge check:       {both['valid']} {both['receipt'].error or ''}")
    print(f"  target anchored:  block {both['receipt'].data.get('target', {}).get('anchored_block')} "
          f"at {both['receipt'].data.get('target', {}).get('anchored_at')}")
    sys.exit(0 if v["valid"] and both["valid"] else 1)


if __name__ == "__main__":
    main()
