# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Batch anchoring: RFC 9162 tree against independent reference vectors, and end to end on a local ledger."""
import json
import os
import secrets
from dataclasses import replace

import pytest

from upp import ANY, Attestation, LocalLedger, Plug, PlugError, Status, commitment, digest, sha256_hex, statement_hash
from upp.core import (batch_commitment, merkle_leaf_hash, merkle_path, merkle_root, merkle_verify_inclusion)

NET = "testnet"

with open(os.path.join(os.path.dirname(__file__), "..", "spec", "vectors", "rfc9162.json")) as _f:
    VECTORS = json.load(_f)


@pytest.fixture
def ledger_path():
    """A JSONL ledger file inside the repository, removed afterwards."""
    path = os.path.join(os.path.dirname(__file__), f".ledger-{secrets.token_hex(6)}.jsonl")
    yield path
    if os.path.exists(path):
        os.remove(path)


def lines(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ---- the tree ----

def test_roots_match_reference_for_every_tree_size():
    leaves = [bytes.fromhex(x) for x in VECTORS["leaf_inputs"]]
    for size, want in enumerate(VECTORS["roots_by_size"]):
        assert merkle_root(leaves[:size]).hex() == want, size


def test_inclusion_probes_accept_valid_and_reject_every_corruption():
    for p in VECTORS["inclusion_probes"]:
        ok = merkle_verify_inclusion(bytes.fromhex(p["leaf_hash"]), p["leaf_index"], p["tree_size"],
                                     [bytes.fromhex(x) for x in p["proof"]], bytes.fromhex(p["root"]))
        assert ok is not p["want_error"], (p["file"], p["desc"])


@pytest.mark.parametrize("hash_alg", ["sha-256", "sha3-256"])
def test_generated_paths_verify_for_all_positions(hash_alg):
    leaves = [bytes.fromhex(x) for x in VECTORS["leaf_inputs"]]
    for size in range(1, len(leaves) + 1):
        root = merkle_root(leaves[:size], hash_alg)
        for i in range(size):
            path = merkle_path(i, leaves[:size], hash_alg)
            leaf = merkle_leaf_hash(leaves[i], hash_alg)
            assert merkle_verify_inclusion(leaf, i, size, path, root, hash_alg)
            assert not merkle_verify_inclusion(merkle_leaf_hash(leaves[i] + b"x", hash_alg), i, size, path, root,
                                               hash_alg)
            if path:
                assert not merkle_verify_inclusion(leaf, i, size, path[:-1], root, hash_alg)


def test_verify_inclusion_refuses_bad_shapes():
    leaf = merkle_leaf_hash(b"a")
    root = merkle_root([b"a"])
    assert merkle_verify_inclusion(leaf, 0, 1, [], root)
    assert not merkle_verify_inclusion(leaf, -1, 1, [], root)
    assert not merkle_verify_inclusion(leaf, 1, 1, [], root)
    assert not merkle_verify_inclusion(leaf[:16], 0, 1, [], root)
    assert not merkle_verify_inclusion(leaf, 0, 1, [b"\x00" * 32], root)
    assert merkle_root([]) == bytes.fromhex(sha256_hex(b""))


# ---- end to end ----

def batch_plug(path=None, **kw):
    p = Plug(trust={NET: ANY}, **kw)
    p.register(NET, LocalLedger(path))
    p.open(NET, {})
    return p


def test_prove_batch_anchors_once_and_each_fact_proves_membership(ledger_path):
    p = batch_plug(ledger_path)
    facts = [{"parcel": i, "plot": f"geo-{i}"} for i in range(5)]
    receipts = p.prove_batch(facts, "GPS_Fix", meta={"field": "north"})
    assert len(lines(ledger_path)) == 1, "one anchor for the whole batch"
    assert len({r.state_ref.address for r in receipts}) == 1
    assert len({json.dumps(r.data["proof"], sort_keys=True) for r in receipts}) == 1, "the root is signed once"
    root = receipts[0].data["batch_root"]
    leaves = [bytes.fromhex(sha256_hex(json.dumps(f, separators=(",", ":"), sort_keys=True))) for f in facts]
    assert merkle_root(leaves).hex() == root
    for i, r in enumerate(receipts):
        assert r.op == "attest" and r.status == Status.OK
        assert r.data["subject_hash"] == leaves[i].hex() and r.data["fact_type"] == "gps.fix"
        assert r.data["meta"] == {"field": "north"} and r.data["inclusion"]["index"] == i
        v = p.check(Attestation.from_receipt(r))
        assert v["valid"] is True, v["receipt"].error
        assert v["receipt"].data["batch_root"] == root and v["receipt"].data["subject_hash"] == r.data["subject_hash"]
        wrong = replace(Attestation.from_receipt(r), inclusion=dict(r.data["inclusion"], index=(i + 1) % 5))
        assert p.check(wrong)["receipt"].error == "proof_invalid: subject is not in the batch"


def test_batch_statement_is_the_anchored_record():
    p = batch_plug()
    r = p.prove_batch(["a", "b", "c", "d"], "doc.sha256", meta={"k": 1})[3]
    root = r.data["batch_root"]
    batch = Attestation(batch_commitment(root, 4), "upp.batch", r.data["issuer"], r.data["issued_at"],
                        proof=r.data["proof"], meta={"k": 1, "batch_size": 4, "batch_fact_type": "doc.sha256"},
                        anchor=r.state_ref)
    assert r.state_ref.address == "local:" + statement_hash(batch)
    assert p.check(batch)["valid"] is True, "the batch statement itself is an ordinary signed statement"
    assert batch_commitment(root, 4) != batch_commitment(root, 5)
    assert batch_commitment(root, 4, "sha3-256") == digest(json.dumps(
        {"upp.batch": {"root": root, "size": 4}}, separators=(",", ":")), "sha3-256")


def test_batch_commitment_binds_the_tree_size():
    p = batch_plug()
    r = p.prove_batch(["a", "b", "c", "d"], "doc.sha256")[3]
    att = Attestation.from_receipt(r)
    assert p.check(att)["valid"] is True
    resized = dict(r.data["inclusion"], size=5)
    assert p.check(replace(att, inclusion=resized))["valid"] is False


def test_tampered_paths_and_labels_are_rejected():
    p = batch_plug()
    receipts = p.prove_batch([f"container-{i}" for i in range(7)], "doc.sha256")
    r = receipts[2]
    att = Attestation.from_receipt(r)
    inc = r.data["inclusion"]
    for forged in (dict(inc, path=list(reversed(inc["path"]))), dict(inc, path=inc["path"][:-1]),
                   dict(inc, path=inc["path"] + ["00" * 32]), dict(inc, path=["00" * 32] + inc["path"][1:]),
                   dict(inc, root="00" * 32)):
        v = p.check(replace(att, inclusion=forged))
        assert v["valid"] is False and v["receipt"].error == "proof_invalid: subject is not in the batch", forged
    other_subject = replace(att, subject_hash=sha256_hex(b"container-99"))
    assert p.check(other_subject)["receipt"].error == "proof_invalid: subject is not in the batch"
    relabeled = p.check(replace(att, fact_type="contract.signed"))
    assert relabeled["valid"] is False, "a batch member's type is signed through the batch statement"
    for changed in (replace(att, meta={"k": 1}), replace(att, issued_at="2020-01-01T00:00:00Z"),
                    replace(att, hash_alg="sha3-256")):
        assert p.check(changed)["valid"] is False
    forged_sig = replace(att, proof=dict(att.proof, sig="0x" + "00" * 64))
    assert p.check(forged_sig)["receipt"].error == "proof_invalid: bad signature"


def test_malformed_inclusion_is_rejected_not_raised():
    p = batch_plug()
    r = p.prove_batch(["a", "b", "c"], "doc.sha256")[1]
    good = r.data["inclusion"]
    cases = {"proof_invalid: unsupported batch tree": ({"tree": "naive"}, dict(good, tree="sha256-pairs")),
             "proof_invalid: bad inclusion proof": ({"tree": "rfc9162", "index": "x"}, {"tree": "rfc9162"},
                                                    "nonsense", dict(good, root="zz"), dict(good, path="ab"),
                                                    dict(good, path=[7]))}
    for error, bads in cases.items():
        for bad in bads:
            v = p.check(replace(Attestation.from_receipt(r), inclusion=bad))
            assert v["valid"] is False and v["receipt"].error == error, bad
    assert p.check(replace(Attestation.from_receipt(r), inclusion=dict(good, index=-1)))["valid"] is False


def test_batch_of_one_and_empty_batch():
    p = batch_plug()
    (r,) = p.prove_batch(["only"], "doc.sha256")
    assert r.data["inclusion"]["size"] == 1 and r.data["inclusion"]["path"] == []
    assert r.data["batch_root"] == merkle_leaf_hash(bytes.fromhex(sha256_hex(b"only"))).hex()
    assert p.check(Attestation.from_receipt(r))["valid"] is True
    with pytest.raises(ValueError):
        p.prove_batch([], "doc.sha256")


def test_salted_batch_keeps_salts_off_the_ledger(ledger_path):
    p = batch_plug(ledger_path, commitment="salted")
    facts = ["anna@example.org", "bob@example.org"]
    receipts = p.prove_batch(facts, "identity.email")
    salts = [r.data["salt"] for r in receipts]
    assert all(len(bytes.fromhex(s)) == 32 for s in salts) and salts[0] != salts[1]
    for fact, r in zip(facts, receipts):
        assert r.data["subject_hash"] == commitment(fact, r.data["salt"]) != sha256_hex(fact)
        assert p.check(Attestation.from_receipt(r))["valid"] is True
    with open(ledger_path, encoding="utf-8") as f:
        text = f.read()
    assert not any(s in text for s in salts) and "anna" not in text
    retry = p.prove_batch(facts, "identity.email")
    assert [r.data["salt"] for r in retry] != salts, "every batch draws fresh salts"


def test_batch_under_another_hash_alg():
    p = batch_plug(hash_alg="sha3-256")
    receipts = p.prove_batch(["a", "b", "c"], "doc.sha256")
    for fact, r in zip("abc", receipts):
        assert r.data["hash_alg"] == "sha3-256" and r.data["subject_hash"] == digest(fact, "sha3-256")
        assert p.check(Attestation.from_receipt(r))["valid"] is True
    assert p.check(replace(Attestation.from_receipt(receipts[0]), hash_alg="sha-256"))["valid"] is False


def test_batch_persists_and_verifies_after_reload(ledger_path):
    p = batch_plug(ledger_path)
    receipts = p.prove_batch(["a", "b", "c"], "doc.sha256")
    reader = Plug(trust={NET: ANY})
    reader.register(NET, LocalLedger(ledger_path))
    assert all(reader.check(Attestation.from_receipt(r), NET)["valid"] for r in receipts)


def test_single_fact_anchor_cannot_pose_as_a_batch_root():
    p = batch_plug()
    claimed = sha256_hex(b"a statement the issuer never made")
    r = p.prove(b"\x00" + bytes.fromhex(claimed), "doc.sha256")  # its subject is the leaf hash of `claimed`
    assert r.data["subject_hash"] == merkle_leaf_hash(bytes.fromhex(claimed)).hex()
    forged = replace(Attestation.from_receipt(r), subject_hash=claimed, fact_type="contract.signed",
                     inclusion={"tree": "rfc9162", "index": 0, "size": 1, "path": [], "root": r.data["subject_hash"]})
    assert p.check(forged)["valid"] is False


def test_reserved_upp_domain_cannot_be_proven():
    p = batch_plug()
    for fact in ({"upp.batch": {"root": "00" * 32, "size": 1}}, {"upp.statement": {"x": 1}},
                 '{"upp.batch":{}}', b'{"upp.anything"'):
        with pytest.raises(PlugError) as e:
            p.prove(fact, "doc.sha256")
        assert e.value.code == "unsupported_op"
        with pytest.raises(PlugError):
            p.prove_batch(["ok", fact], "doc.sha256")
    assert p.prove({"upplication": "fine"}, "doc.sha256").status == Status.OK
    assert p.prove_batch([{"plug.batch": "no longer reserved"}], "doc.sha256")[0].status == Status.OK


def test_repeated_batch_with_other_type_or_meta_is_its_own_statement():
    p = batch_plug()
    calls = [("doc.sha256", None), ("contract.signed", None), ("doc.sha256", {"k": 1}), ("doc.sha256", {"k": 2})]
    anchors = []
    for ft, meta in calls:
        receipts = p.prove_batch(["x", "y"], ft, meta=meta)
        anchors.append(receipts[0].state_ref.address)
        for r in receipts:
            v = p.check(Attestation.from_receipt(r))
            assert v["valid"] is True, (ft, meta, v["receipt"].error)
    assert len(set(anchors)) == 4


def test_receipts_do_not_share_signed_meta_with_the_caller():
    p = batch_plug()
    meta = {"tags": ["a"]}
    receipts = p.prove_batch(["doc-1", "doc-2"], "doc.sha256", meta=meta)
    meta["tags"].append("b")
    receipts[0].data["meta"]["tags"].append("c")
    assert receipts[1].data["meta"] == {"tags": ["a"]}
    assert p.check(Attestation.from_receipt(receipts[1]))["valid"] is True


def test_batch_member_cannot_add_unsigned_batch_labels():
    p = batch_plug()
    r = p.prove_batch(["a", "b", "c"], "doc.sha256", meta={"note": "n"})[1]
    assert p.check(Attestation.from_receipt(r))["valid"] is True
    for extra in ({"batch_fact_type": "agent.action"}, {"batch_size": 999}, {"batch_size": 3}):
        att = Attestation.from_receipt(r)
        att.meta.update(extra)
        v = p.check(att)
        assert v["valid"] is False and "batch member meta" in v["receipt"].error, extra


def test_batch_members_follow_the_trust_policy():
    p = batch_plug()
    r = p.prove_batch(["a", "b"], "doc.sha256")[0]
    att = Attestation.from_receipt(r)
    assert p.check(att, trust_registry={"issuers": [r.data["issuer"]]})["valid"] is True
    v = p.check(att, trust_registry={"issuers": ["did:key:zSomeoneElse"]})
    assert v["receipt"].error == "not_authorized: issuer not in trust registry"


def test_only_the_open_session_signs_a_batch():
    p = Plug(trust={NET: ANY})
    p.register(NET, LocalLedger())
    with pytest.raises(PlugError) as e:
        p.prove_batch(["a"], "doc.sha256")
    assert e.value.code == "auth_failed"


def test_batch_receipts_keep_internal_meta_out():
    p = batch_plug()
    r = p.prove_batch(["a", "b"], "doc.sha256", meta={"note": "n", "_trace": "t-1"})[0]
    assert p.check(Attestation.from_receipt(r))["valid"] is True
    assert r.data["meta"] == {"note": "n"}


@pytest.mark.parametrize("meta", [{"batch_size": 1}, {"batch_fact_type": "agent.action"}])
def test_batch_meta_with_reserved_labels_is_refused_or_verifiable(meta):
    p = batch_plug()
    try:
        receipts = p.prove_batch(["a", "b"], "doc.sha256", meta=meta)
    except (ValueError, PlugError):
        return
    assert all(p.check(Attestation.from_receipt(r))["valid"] for r in receipts)
