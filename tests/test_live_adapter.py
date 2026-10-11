# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""LiveAdapter against an in-memory chain: anchoring, issuer binding, per-session keys, finality. No network."""
import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_account")

from eth_account import Account
from hexbytes import HexBytes
from web3.datastructures import AttributeDict

from plug.adapters.live import LiveAdapter, sign_subject
from dataclasses import replace

from plug.core import Attestation, Plug, PlugError, StateRef, Status, sha256_hex, statement_hash


def _norm(h) -> str:
    text = h.hex() if isinstance(h, (bytes, bytearray)) else str(h)
    return "0x" + text.lower().removeprefix("0x")


class _FakeAccount:
    def __init__(self, eth):
        self._eth = eth

    def sign_transaction(self, tx, key):
        signed = Account.sign_transaction(tx, key)
        self._eth.pending[bytes(signed.raw_transaction)] = (tx, signed.hash)
        return signed


class _FakeEth:
    """Mines every transaction into its own block. status=0 for data the test marks as reverting."""

    def __init__(self):
        self.account = _FakeAccount(self)
        self.pending = {}
        self.txs = {}
        self.receipts = {}
        self.nonces = {}
        self.block_number = 100
        self.finalized = 90
        self.revert_data = set()
        self.revert_all = False
        self.chain_id = 11155111
        self.gas_price = 1

    def get_transaction_count(self, address):
        return self.nonces.get(address, 0)

    def get_balance(self, address):
        return 10**18

    def estimate_gas(self, tx):
        return 22000

    def send_raw_transaction(self, raw):
        tx, tx_hash = self.pending.pop(bytes(raw))
        self.block_number += 1
        self.nonces[tx["from"]] = self.nonces.get(tx["from"], 0) + 1
        key = _norm(tx_hash)
        self.txs[key] = AttributeDict({"from": tx["from"], "to": tx["to"], "input": HexBytes(tx["data"])})
        self.receipts[key] = AttributeDict({"status": 0 if self.revert_all or tx["data"] in self.revert_data else 1,
                                           "blockNumber": self.block_number, "gasUsed": 21512, "logs": []})
        return HexBytes(tx_hash)

    def wait_for_transaction_receipt(self, tx_hash, timeout=120):
        return self.receipts[_norm(tx_hash)]

    def get_transaction_receipt(self, tx_hash):
        if _norm(tx_hash) not in self.receipts:
            raise ValueError("transaction not found")
        return self.receipts[_norm(tx_hash)]

    def get_transaction(self, tx_hash):
        return self.txs[_norm(tx_hash)]

    def get_block(self, ident):
        if ident == "finalized":
            return {"number": self.finalized}
        return {"number": ident, "timestamp": 1_791_000_000 + ident}


class _FakeW3:
    def __init__(self):
        self.eth = _FakeEth()


ALICE = Account.create().key.hex()
BOB = Account.create().key.hex()


def setup(*keys):
    w3 = _FakeW3()
    p = Plug()
    adapter = LiveAdapter(w3=w3)
    p.register_adapter("sepolia", adapter)
    sessions = [p.open("sepolia", {"scheme": "raw", "material": k}) for k in keys]
    return p, adapter, w3, sessions


def attestation_from(p, r, signer=None, **overrides):
    """The receipt's attestation with overrides; signer re-signs the changed statement with that key."""
    att = replace(Attestation.from_receipt(r), **overrides)
    if signer:
        att.proof = sign_subject(statement_hash(att), signer)
    return att


def test_anchored_attestation_verifies_with_time_and_finality():
    p, _, _, _ = setup(ALICE)
    r = p.prove(b"bill of lading 42", "doc.sha256")
    assert r.status == Status.OK and r.data["issuer"].startswith("did:plug:eip155:11155111:0x")
    v = p.check(attestation_from(p, r))
    assert v["valid"] is True, v["receipt"].error
    data = v["receipt"].data
    assert data["anchored_block"] == r.data["block"]
    assert data["anchored_at"].endswith("Z")
    assert data["finality"]["kind"] == "probabilistic"


def test_signed_but_never_anchored_is_rejected():
    p, _, _, _ = setup(ALICE)
    r = p.prove(b"real", "doc.sha256")
    loose = sha256_hex(b"never anchored")
    att = attestation_from(p, r, signer=ALICE, subject_hash=loose)
    v = p.check(att)
    assert v["valid"] is False
    assert v["receipt"].error == "proof_invalid: anchor does not carry the statement"
    missing = p.check(attestation_from(p, r, anchor=None))
    assert missing["receipt"].error == "proof_invalid: missing anchor"


def test_issuer_impersonation_is_rejected_even_when_registry_lists_victim():
    p, _, _, (alice_sid, bob_sid) = setup(ALICE, BOB)
    alice_did = f"did:plug:eip155:11155111:{Account.from_key(ALICE).address}"
    r = p.prove(b"bob's claim", "doc.sha256")  # active session is bob
    relabeled = p.check(attestation_from(p, r, issuer=alice_did), trust_registry={"issuers": [alice_did]})
    assert relabeled["receipt"].error == "proof_invalid: signer mismatch"
    att = attestation_from(p, r, signer=BOB, issuer=alice_did)
    v = p.check(att, trust_registry={"issuers": [alice_did]})
    assert v["valid"] is False
    assert v["receipt"].error == "proof_invalid: issuer is not bound to the signing key"


def test_anchor_from_another_key_is_rejected():
    p, _, _, (alice_sid, bob_sid) = setup(ALICE, BOB)
    bob_r = p.prove(b"shared fact", "doc.sha256")
    p.use(alice_sid)
    alice_did = p.active().credential_subject
    att = attestation_from(p, bob_r, signer=ALICE, issuer=alice_did)
    v = p.check(att)
    assert v["valid"] is False
    assert v["receipt"].error == "proof_invalid: anchor was sent by another key"


def test_each_session_signs_with_its_own_key():
    p, _, w3, (alice_sid, bob_sid) = setup(ALICE, BOB)
    bob_r = p.prove(b"same fact", "doc.sha256")
    p.use(alice_sid)
    alice_r = p.prove(b"same fact", "doc.sha256")
    assert alice_r.state_ref.address != bob_r.state_ref.address
    senders = {w3.eth.get_transaction(r.state_ref.address[5:])["from"] for r in (alice_r, bob_r)}
    assert senders == {Account.from_key(ALICE).address, Account.from_key(BOB).address}
    assert p.check(attestation_from(p, alice_r))["valid"] is True
    assert p.check(attestation_from(p, bob_r))["valid"] is True


def test_settle_signs_with_active_session_key():
    p, _, w3, (alice_sid, bob_sid) = setup(ALICE, BOB)
    p.use(alice_sid)
    s = p.settle(None, "register", {"lot": 7})
    assert w3.eth.get_transaction(s.state_ref.address[5:])["from"] == Account.from_key(ALICE).address


def test_unknown_issuer_cannot_attest():
    p, _, _, _ = setup(ALICE)
    stranger = f"did:plug:eip155:11155111:{Account.create().address}"
    att = Attestation(subject_hash=sha256_hex(b"x"), fact_type="doc.sha256", issuer=stranger,
                      issued_at="2026-10-10T00:00:00Z")
    with pytest.raises(PlugError) as e:
        p.attest("sepolia", att)
    assert e.value.code == "auth_failed"


def test_issuer_on_another_network_is_rejected():
    p, _, _, _ = setup(ALICE)
    r = p.prove(b"x", "doc.sha256")
    address = Account.from_key(ALICE).address
    for other in (f"did:pkh:eip155:1:{address}", f"did:plug:mainnet:{address}"):
        v = p.check(attestation_from(p, r, signer=ALICE, issuer=other))
        assert v["receipt"].error == "proof_invalid: issuer DID names another network", other
    for same in (f"did:pkh:eip155:11155111:{address}", f"did:plug:sepolia:{address}"):
        att = Attestation(subject_hash=sha256_hex(same), fact_type="doc.sha256", issuer=same,
                          issued_at="2026-10-10T00:00:00Z")
        anchored = p.attest("sepolia", att)
        assert p.check(Attestation.from_receipt(anchored))["valid"] is True, same


def test_finality_turns_final_once_block_is_finalized():
    p, _, w3, _ = setup(ALICE)
    r = p.prove(b"x", "doc.sha256")
    w3.eth.finalized = w3.eth.block_number
    v = p.check(attestation_from(p, r))
    assert v["receipt"].data["finality"]["kind"] == "final"


def test_reverted_anchor_carries_no_proof():
    p, _, w3, _ = setup(ALICE)
    w3.eth.revert_all = True
    r = p.prove(b"doomed", "doc.sha256")
    assert r.status == Status.REJECTED
    assert "proof" not in r.data


def two_chains():
    p = Plug()
    a, b = LiveAdapter(w3=_FakeW3()), LiveAdapter(w3=_FakeW3())
    p.register_adapter("chain-a", a)
    p.register_adapter("chain-b", b)
    p.open("chain-a", {"scheme": "raw", "material": ALICE})
    src = p.prove(b"certificate of origin 77", "doc.sha256")
    p.open("chain-b", {"scheme": "raw", "material": BOB})
    return p, a, b, src


def test_bridge_anchors_commitment_on_target_and_checks_both_sides():
    from plug.core import bridge_commitment
    p, a, b, src = two_chains()
    br = p.bridge(src.state_ref, "chain-b")
    assert br.status == Status.OK and br.network == "chain-b" and br.state_ref.network == "chain-b"
    on_b = b.w3.eth.get_transaction(br.state_ref.address[5:])
    a = br.data["attestation"]
    assert a["subject_hash"] == bridge_commitment(src.state_ref)
    target_att = Attestation(subject_hash=a["subject_hash"], fact_type=a["fact_type"], issuer=a["issuer"],
                             issued_at=a["issued_at"], meta=a["meta"], hash_alg=a["hash_alg"])
    assert on_b["input"].hex().removeprefix("0x") == statement_hash(target_att)
    v = p.check(br)
    assert v["valid"] is True, v["receipt"].error
    target = v["receipt"].data["target"]
    assert target["anchor"] == br.state_ref.address and target["anchored_at"].endswith("Z")
    assert target["recovered"] == Account.from_key(BOB).address


def test_bridge_tampering_and_bad_source_are_rejected():
    import copy
    p, a, b, src = two_chains()
    br = p.bridge(src.state_ref, "chain-b")
    moved = copy.deepcopy(br)
    moved.data["source"]["address"] = "live:0x" + "ab" * 32
    assert p.check(moved)["receipt"].error == "proof_invalid: target commitment does not match the source"
    key = src.state_ref.address[5:]
    a.w3.eth.receipts[key] = AttributeDict(dict(a.w3.eth.receipts[key], status=0))
    assert p.check(br)["receipt"].error == "proof_invalid: source proof is not ok"
    refused = p.bridge(src.state_ref, "chain-b")
    assert refused.status == Status.REJECTED and refused.state_ref is None


def test_bridge_without_target_adapter_stays_pending_on_source():
    p, a, _, src = two_chains()
    p.use(p.list_sessions()[0].session_id)
    r = p.bridge(src.state_ref, "chain-z")
    assert r.status == Status.PENDING and r.network == "chain-a" and r.state_ref.network == "chain-a"


def test_repeated_bridge_receipt_still_verifies():
    from unittest import mock
    p, a, b, src = two_chains()
    first = p.bridge(src.state_ref, "chain-b")
    with mock.patch("plug.core.time.strftime", return_value="2030-01-01T00:00:00Z"):
        again = p.bridge(src.state_ref, "chain-b")
    for br in (first, again):
        v = p.check(br)
        assert v["valid"] is True, v["receipt"].error
