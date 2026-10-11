#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""One-command live Sepolia test for Universal Plug Protocol.

Usage:
    SEPOLIA_RPC_URL=https://... SEPOLIA_PRIVATE_KEY=0x... python scripts/live_test.py

Prints the real tx hash from the attest call. Delete the faucet key after.
"""
import os
import sys

# Ensure the repo root is on the path when run from any directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plug.core import Plug, FactType, StateRef
from plug.adapters.live import LiveAdapter


def main():
    if not os.environ.get("SEPOLIA_RPC_URL") or not os.environ.get("SEPOLIA_PRIVATE_KEY"):
        print("ERROR: set SEPOLIA_RPC_URL and SEPOLIA_PRIVATE_KEY env vars")
        sys.exit(1)

    plug = Plug()
    adapter = LiveAdapter()
    plug.register_adapter("sepolia", adapter)

    # 1. Connect / open session
    sess = plug.open("sepolia", {"scheme": "raw", "material": os.environ["SEPOLIA_PRIVATE_KEY"],
                                 "subject": adapter.address})
    plug.trust("sepolia", {"issuers": [plug.active().credential_subject]})  # closed by default: trust our own key only
    print(f"session: {sess}")
    print(f"wallet:  {adapter.address}")
    print(f"balance: {adapter.w3.eth.get_balance(adapter.address)} wei")

    # 2. Prove (attest) — real on-chain transaction
    r = plug.prove({"temp": 21.5, "unit": "C", "sensor": "alpha"}, FactType.SENSOR_READING)
    print(f"attest status: {r.status.value}")
    print(f"tx hash:      {r.state_ref.address}")
    print(f"block:        {r.data.get('block')}")
    print(f"seq:          {r.seq}")
    print(f"receipt hash: {r.receipt_hash()}")

    # 3. Check (query) the same state ref
    ref = StateRef(r.network, r.state_ref.address, r.state_ref.kind)
    chk = plug.check(ref)
    print(f"query valid:  {chk['valid']}")
    print(f"query status: {chk['receipt'].status.value}")
    print(f"query data:   {chk['receipt'].data}")
    if not chk["valid"]:
        sys.exit(1)

    # 4. Verify the proof the adapter attached to the receipt.
    from plug.core import Attestation
    import time
    proof = r.data.get("proof")
    if not proof:
        print("verify failed: attest receipt has no proof")
        sys.exit(1)
    att = Attestation.from_receipt(r)
    v = plug.check(att)
    print(f"verify valid: {v['valid']}")
    print(f"verify data:  {v['receipt'].data}")
    if not v["valid"]:
        print(f"verify error: {v['receipt'].error}")
        sys.exit(1)

    # 4b. A signature over a hash that was never anchored must not verify.
    from plug.adapters.live import sign_subject
    from dataclasses import replace
    from plug.core import sha256_hex, statement_hash
    loose = sha256_hex(f"never anchored {time.time()}")
    unanchored = replace(att, subject_hash=loose)
    unanchored.proof = sign_subject(statement_hash(unanchored), os.environ["SEPOLIA_PRIVATE_KEY"])
    u = plug.check(unanchored)
    print(f"unanchored rejected: {not u['valid']} ({u['receipt'].error})")
    if u["valid"]:
        sys.exit(1)

    # 5. Watch (subscribe) the same ref. One receipt poll, no socket.
    handle = plug.watch(ref, ["tx"])
    print(f"watch handle: {handle}")
    watched = [e for e in adapter.log if e.get("op") == "subscribe"]
    print(f"watch events: {watched[-1].get('events') if watched else None}")

    print("\nALL LIVE CHECKS DONE")
    print("Rotate/delete the faucet key now.")


if __name__ == "__main__":
    main()
