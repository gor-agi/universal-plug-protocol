# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Batch anchoring: RFC 9162 tree against independent reference vectors, and end to end."""
import json
import os

import pytest

from plug.adapters.stub import StubAdapter
from plug.core import (Attestation, Plug, Status, merkle_leaf_hash, merkle_path, merkle_root,
                       merkle_verify_inclusion)

VECTORS = json.load(open(os.path.join(os.path.dirname(__file__), "..", "spec", "vectors", "rfc9162.json")))


def test_roots_match_reference_for_every_tree_size():
    leaves = [bytes.fromhex(x) for x in VECTORS["leaf_inputs"]]
    for size, want in enumerate(VECTORS["roots_by_size"]):
        assert merkle_root(leaves[:size]).hex() == want, size


def test_inclusion_probes_accept_valid_and_reject_every_corruption():
    for p in VECTORS["inclusion_probes"]:
        ok = merkle_verify_inclusion(bytes.fromhex(p["leaf_hash"]), p["leaf_index"], p["tree_size"],
                                     [bytes.fromhex(x) for x in p["proof"]], bytes.fromhex(p["root"]))
        assert ok is not p["want_error"], (p["file"], p["desc"])


def test_generated_paths_verify_for_all_positions():
    leaves = [bytes.fromhex(x) for x in VECTORS["leaf_inputs"]]
    for size in range(1, len(leaves) + 1):
        root = merkle_root(leaves[:size])
        for i in range(size):
            path = merkle_path(i, leaves[:size])
            assert merkle_verify_inclusion(merkle_leaf_hash(leaves[i]), i, size, path, root)
            assert not merkle_verify_inclusion(merkle_leaf_hash(leaves[i] + b"x"), i, size, path, root)


def batch_plug(**kw):
    p = Plug(**kw)
    p.register_adapter("testnet", StubAdapter())
    p.open("testnet", {"scheme": "raw", "material": "k", "subject": "alice"})
    return p


def test_prove_batch_anchors_once_and_each_fact_proves_membership():
    p = batch_plug()
    facts = [{"parcel": i, "plot": f"geo-{i}"} for i in range(5)]
    receipts = p.prove_batch(facts, "gps.fix")
    log = p.adapter_log("testnet")
    assert len(log.filter(op="attest")) == 1, "one anchor for the whole batch"
    assert len({r.state_ref.address for r in receipts}) == 1
    root = receipts[0].data["batch_root"]
    for i, r in enumerate(receipts):
        att = Attestation(r.data["subject_hash"], r.data["fact_type"], r.data["issuer"], "2026-10-11T00:00:00Z",
                          inclusion=r.data["inclusion"], anchor=r.state_ref)
        v = p.verify(att, "testnet")
        assert v.data["batch_root"] == root and v.data["leaf_index"] == i
        assert "batch" not in (v.error or "")  # inclusion held; the keyless stub decides on the root
        wrong = Attestation(r.data["subject_hash"], r.data["fact_type"], r.data["issuer"], "2026-10-11T00:00:00Z",
                            inclusion=dict(r.data["inclusion"], index=(i + 1) % 5), anchor=r.state_ref)
        assert p.verify(wrong, "testnet").error == "proof_invalid: subject is not in the batch"


def test_salted_batch_keeps_salts_off_the_adapter():
    p = batch_plug(commitment="salted")
    receipts = p.prove_batch(["anna@example.org", "bob@example.org"], "identity.email")
    salts = [r.data["salt"] for r in receipts]
    assert all(len(bytes.fromhex(s)) == 32 for s in salts) and salts[0] != salts[1]
    assert not any(s in json.dumps(list(p.adapter_log("testnet"))) for s in salts)


def test_malformed_inclusion_is_rejected_not_raised():
    p = batch_plug()
    r = p.prove_batch(["a", "b", "c"], "doc.sha256")[1]
    for bad in ({"tree": "naive"}, {"tree": "rfc9162", "index": "x"}, {"tree": "rfc9162"}, "nonsense"):
        att = Attestation(r.data["subject_hash"], "doc.sha256", r.data["issuer"], "2026-10-11T00:00:00Z",
                          inclusion=bad, anchor=r.state_ref)
        assert p.verify(att, "testnet").status == Status.REJECTED


def test_batch_on_ledger_adapter_verifies_every_member():
    pytest.importorskip("web3")
    from eth_account import Account
    from plug.adapters.live import LiveAdapter
    from test_live_adapter import _FakeW3
    p = Plug()
    p.register_adapter("sepolia", LiveAdapter(w3=_FakeW3()))
    p.open("sepolia", {"scheme": "raw", "material": Account.create().key.hex()})
    receipts = p.prove_batch([f"container-{i}" for i in range(7)], "doc.sha256")
    for r in receipts:
        att = Attestation(r.data["subject_hash"], r.data["fact_type"], r.data["issuer"], "2026-10-11T00:00:00Z",
                          proof=r.data["proof"], inclusion=r.data["inclusion"], anchor=r.state_ref)
        v = p.check(att)
        assert v["valid"] is True, v["receipt"].error
    forged = dict(receipts[2].data["inclusion"], path=list(reversed(receipts[2].data["inclusion"]["path"])))
    att = Attestation(receipts[2].data["subject_hash"], "doc.sha256", receipts[2].data["issuer"],
                      "2026-10-11T00:00:00Z", proof=receipts[2].data["proof"], inclusion=forged,
                      anchor=receipts[2].state_ref)
    assert p.check(att)["valid"] is False
