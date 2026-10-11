# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Batch anchoring: RFC 9162 tree against independent reference vectors, and end to end."""
import json
from dataclasses import replace
import os

import pytest

from plug import ANY
from plug.adapters.stub import StubAdapter
from plug.core import (Attestation, Plug, PlugError, Status, batch_commitment, merkle_leaf_hash, merkle_path,
                       merkle_root, merkle_verify_inclusion, sha256_hex)

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
    p = Plug(trust={"testnet": ANY}, **kw)
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
    p = Plug(trust={"sepolia": ANY})
    p.register_adapter("sepolia", LiveAdapter(w3=_FakeW3()))
    p.open("sepolia", {"scheme": "raw", "material": Account.create().key.hex()})
    receipts = p.prove_batch([f"container-{i}" for i in range(7)], "doc.sha256")
    for r in receipts:
        v = p.check(Attestation.from_receipt(r))
        assert v["valid"] is True, v["receipt"].error
    forged = dict(receipts[2].data["inclusion"], path=list(reversed(receipts[2].data["inclusion"]["path"])))
    assert p.check(_att(receipts[2], inclusion=forged))["valid"] is False
    relabeled = p.check(_att(receipts[2], fact_type="contract.signed"))
    assert relabeled["valid"] is False, "a batch member's type is signed through the batch statement"


def _ledger_plug(**kw):
    pytest.importorskip("web3")
    from eth_account import Account
    from plug.adapters.live import LiveAdapter
    from test_live_adapter import _FakeW3
    p = Plug(trust={"sepolia": ANY}, **kw)
    p.register_adapter("sepolia", LiveAdapter(w3=_FakeW3()))
    p.open("sepolia", {"scheme": "raw", "material": Account.create().key.hex()})
    return p


def _att(r, **over):
    return replace(Attestation.from_receipt(r), **over)


def test_single_fact_anchor_cannot_pose_as_a_batch_root():
    p = _ledger_plug()
    claimed = sha256_hex(b"a statement the issuer never made")
    r = p.prove(b"\x00" + bytes.fromhex(claimed), "doc.sha256")  # its subject is the leaf hash of `claimed`
    forged = _att(r, subject_hash=claimed, fact_type="contract.signed",
                  inclusion={"tree": "rfc9162", "index": 0, "size": 1, "path": [], "root": r.data["subject_hash"]})
    assert p.check(forged)["valid"] is False


def test_batch_commitment_binds_the_tree_size():
    p = _ledger_plug()
    r = p.prove_batch(["a", "b", "c", "d"], "doc.sha256")[3]
    assert r.data["batch_commitment"] == batch_commitment(r.data["batch_root"], 4)
    assert p.check(_att(r))["valid"] is True
    resized = dict(r.data["inclusion"], size=5)
    assert p.check(_att(r, inclusion=resized))["valid"] is False


def test_salted_batch_retry_reuses_salts_and_stays_verifiable():
    p = _ledger_plug(commitment="salted")
    facts = ["anna@example.org", "bob@example.org", "carl@example.org"]
    first = p.prove_batch(facts, "identity.email")
    retry = p.prove_batch(facts, "identity.email")
    assert [r.data["salt"] for r in retry] == [r.data["salt"] for r in first]
    assert retry[0].state_ref == first[0].state_ref
    assert all(p.check(_att(r))["valid"] for r in first + retry)
    other = p.prove_batch(facts, "identity.phone")
    assert other[0].data["salt"] != first[0].data["salt"], "salts are reused only for the same batch"


def test_reserved_plug_domain_cannot_be_proven():
    p = batch_plug()
    for fact in ({"plug.batch": {"root": "00" * 32, "size": 1}}, {"plug.bridge": {"network": "x"}},
                 '{"plug.batch":{}}', b'{"plug.anything"'):
        with pytest.raises(PlugError):
            p.prove(fact, "doc.sha256")
        with pytest.raises(PlugError):
            p.prove_batch(["ok", fact], "doc.sha256")
    assert p.prove({"plugin": "fine"}, "doc.sha256").status == Status.OK


def test_repeated_batch_with_other_type_or_meta_is_its_own_statement():
    p = _ledger_plug()
    calls = [(["x", "y"], "doc.sha256", None), (["x", "y"], "contract.signed", None),
             (["x", "y"], "doc.sha256", {"k": 1}), (["x", "y"], "doc.sha256", {"k": 2}),
             (["x", "y"], "doc.sha256", {"k": 2})]
    anchors = []
    for facts, ft, meta in calls:
        receipts = p.prove_batch(facts, ft, meta=meta)
        anchors.append(receipts[0].state_ref.address)
        for r in receipts:
            v = p.check(Attestation.from_receipt(r))
            assert v["valid"] is True, (ft, meta, v["receipt"].error)
    assert len(set(anchors[:4])) == 4 and anchors[4] == anchors[3], "only an identical retry reuses the anchor"


def test_receipts_do_not_share_signed_meta_with_the_caller_or_the_cache():
    p = _ledger_plug()
    meta = {"tags": ["a"]}
    first = p.prove("doc-1", "doc.sha256", meta=meta)
    meta["tags"].append("b")
    first.data["meta"]["tags"].append("c")
    retry = p.prove("doc-1", "doc.sha256", meta={"tags": ["a"]})
    assert retry.state_ref == first.state_ref
    assert p.check(Attestation.from_receipt(retry))["valid"] is True


def test_batch_member_cannot_add_unsigned_batch_labels():
    p = _ledger_plug()
    r = p.prove_batch(["a", "b", "c"], "doc.sha256", meta={"note": "n"})[1]
    assert p.check(Attestation.from_receipt(r))["valid"] is True
    for extra in ({"batch_fact_type": "agent.action"}, {"batch_size": 999}):
        att = Attestation.from_receipt(r)
        att.meta.update(extra)
        v = p.check(att)
        assert v["valid"] is False and "batch member meta" in v["receipt"].error, extra

