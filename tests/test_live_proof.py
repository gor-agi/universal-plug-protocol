# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Live-adapter proof and chain-status checks. No network."""
import pytest

pytest.importorskip("eth_account")
pytest.importorskip("eth_keys")

from eth_account import Account

from plug.adapters.live import chain_status, check_proof, select_stream_events, sign_subject
from plug.core import Status


def test_chain_status_maps_mined_receipts():
    assert chain_status(1) == (Status.OK, None)
    assert chain_status(0)[0] == Status.REJECTED
    assert chain_status("nope")[1] == "finality_unknown"


def test_proof_matches_named_verification_method_only():
    acct = Account.create()
    other = Account.create()
    subject = "11" * 32
    proof = sign_subject(subject, acct.key.hex())
    ok, recovered = check_proof(subject, proof)
    assert ok and recovered == acct.address
    forged = dict(proof, verification_method=other.address)
    ok2, detail = check_proof(subject, forged)
    assert ok2 is False and detail == acct.address


def test_stream_filter_selects_tx_and_logs():
    tx = {"type": "tx", "status": "ok"}
    log = {"type": "log", "address": "0xabc", "topic0": "0x01"}
    assert select_stream_events(None, tx, [log]) == [tx, log]
    assert select_stream_events(["tx"], tx, [log]) == [tx]
    assert select_stream_events(["0x01"], tx, [log]) == [log]
