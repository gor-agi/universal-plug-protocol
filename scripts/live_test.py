#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Prove and check one fact on a live EVM chain (Sepolia by default).

Usage:  ETH_RPC_URL=https://... ETH_PRIVATE_KEY=0x... python scripts/live_test.py
Use a throwaway testnet key funded from a faucet.
"""
import os
import sys

from upp import Attestation, Plug
from upp.ledgers import EthereumLedger


def main():
    if not os.environ.get("ETH_RPC_URL") or not os.environ.get("ETH_PRIVATE_KEY"):
        sys.exit("set ETH_RPC_URL and ETH_PRIVATE_KEY")
    plug = Plug()
    plug.register("sepolia", EthereumLedger())
    plug.open("sepolia")
    me = plug.active().subject
    plug.trust("sepolia", {"issuers": [me]})  # closed by default: trust our own key only
    print("issuer:", me)

    r = plug.prove({"temp": 21.5, "unit": "C", "sensor": "alpha"}, "sensor.reading")
    print("attest:", r.status.value, r.state_ref.address if r.state_ref else r.error)
    v = plug.check(Attestation.from_receipt(r))
    print("check: ", "valid" if v["valid"] else v["receipt"].error, v["receipt"].data.get("anchored_at", ""))
    sys.exit(0 if v["valid"] else 1)


if __name__ == "__main__":
    main()
